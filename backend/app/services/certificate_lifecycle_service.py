"""
Certificate lifecycle service.

This keeps the demo CA bootstrap separate from certificate enrollment and
issuance. Storage is JSON-based for Phase 2; Phase 6 should move this to DB.
"""

import base64
import json
import re
import secrets
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.exceptions import InvalidSignature

from app.core.config import settings
from app.services.crypto_utils import sha256_bytes
from app.services import revocation_service
from app.services.pki_service import (
    ROOT_CERT,
    INT_CERT,
    USER_CERT,
    certificate_view_dict,
    get_demo_backend_user_private_key,
    get_demo_user_public_key_pem,
    get_intermediate_certificate,
    get_root_certificate,
    init_demo_pki,
    issue_user_certificate_from_public_key,
    load_certificate_from_path,
    load_public_key_pem,
    validate_document_signing_certificate_profile,
    write_certificate_pem,
)
from app.services.key_custody import (
    KEY_SOURCE_CLIENT_SIDE,
    KEY_SOURCE_DEMO_BACKEND,
    key_custody_metadata,
    record_key_custody_metadata,
    with_key_custody_metadata,
)

ENROLLMENTS_FILE = settings.certificates_dir / "enrollments.json"
CERTIFICATES_FILE = settings.certificates_dir / "certificates.json"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _read_json(path: Path, default):
    if not path.exists():
        return default
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        # Demo JSON stores are runtime artifacts. If a prior run or merge left
        # them corrupt, rebuild from the current demo PKI instead of crashing.
        return default


def _write_json(path: Path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")


def _normalize_enrollment_record(enrollment: Dict) -> Dict:
    key_source = enrollment.get("key_source")
    if not key_source:
        key_source = (
            KEY_SOURCE_DEMO_BACKEND
            if enrollment.get("enrollment_id") == "demo_alice_bootstrap"
            else KEY_SOURCE_CLIENT_SIDE
        )
    return {**enrollment, **key_custody_metadata(key_source)}


def _normalize_certificate_record(record: Dict) -> Dict:
    return with_key_custody_metadata(record)


def _read_enrollments() -> List[Dict]:
    return [_normalize_enrollment_record(item) for item in _read_json(ENROLLMENTS_FILE, [])]


def _write_enrollments(enrollments: List[Dict]):
    _write_json(ENROLLMENTS_FILE, enrollments)


def _read_certificates() -> List[Dict]:
    return [_normalize_certificate_record(item) for item in _read_json(CERTIFICATES_FILE, [])]


def _write_certificates(certificates: List[Dict]):
    _write_json(CERTIFICATES_FILE, certificates)


def _public_key_fingerprint(public_key) -> str:
    der = public_key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return sha256_bytes(der)


def default_pop_challenge(email: str, public_key_fingerprint_sha256: str) -> str:
    return f"securedoc-pop-v1:{email}:{public_key_fingerprint_sha256}"


def _validate_identity(display_name: str, email: str):
    if not display_name or len(display_name.strip()) < 2:
        raise ValueError("display_name is required")
    if not email or not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email):
        raise ValueError("valid email is required")


def _validate_public_key(public_key):
    if not isinstance(public_key, rsa.RSAPublicKey):
        raise ValueError("Only RSA public keys are supported in this demo")
    if public_key.key_size < 2048:
        raise ValueError("RSA key must be at least 2048 bits")


def verify_proof_of_possession(public_key, challenge: str, proof_signature_base64: str) -> bool:
    try:
        signature = base64.b64decode(proof_signature_base64, validate=True)
    except Exception as exc:
        raise ValueError("proof_signature_base64 is not valid base64") from exc

    try:
        public_key.verify(
            signature,
            challenge.encode("utf-8"),
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256(),
        )
        return True
    except InvalidSignature:
        return False


def create_enrollment(
    display_name: str,
    email: str,
    public_key_pem: str,
    proof_signature_base64: str,
    proof_challenge: str | None = None,
    key_source: str = KEY_SOURCE_CLIENT_SIDE,
) -> Dict:
    _validate_identity(display_name, email)
    public_key = load_public_key_pem(public_key_pem)
    _validate_public_key(public_key)

    fingerprint = _public_key_fingerprint(public_key)
    challenge = proof_challenge or default_pop_challenge(email, fingerprint)
    proof_ok = verify_proof_of_possession(public_key, challenge, proof_signature_base64)
    if not proof_ok:
        raise ValueError("Invalid proof-of-possession")

    enrollment_id = "enr_" + secrets.token_hex(12)
    public_key_path = settings.certificates_dir / f"public_key_{enrollment_id}.pem"
    public_key_path.write_text(public_key_pem, encoding="utf-8")

    custody = key_custody_metadata(key_source)
    enrollment = {
        "enrollment_id": enrollment_id,
        "display_name": display_name,
        "email": email,
        "public_key_path": str(public_key_path),
        "public_key_fingerprint_sha256": fingerprint,
        "proof_challenge": challenge,
        "proof_verified": True,
        "status": "pending",
        "created_at": _now(),
        "decided_at": None,
        "certificate_serial": None,
        **custody,
    }

    enrollments = _read_enrollments()
    enrollments.append(enrollment)
    _write_enrollments(enrollments)
    return enrollment


def create_demo_backend_enrollment(activate: bool = True) -> Dict:
    public_key_pem = get_demo_user_public_key_pem()
    public_key = load_public_key_pem(public_key_pem)
    fingerprint = _public_key_fingerprint(public_key)
    challenge = default_pop_challenge("alice@example.com", fingerprint)
    signature = get_demo_backend_user_private_key().sign(
        challenge.encode("utf-8"),
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256(),
    )
    enrollment = create_enrollment(
        display_name="Alice Demo Signer",
        email="alice@example.com",
        public_key_pem=public_key_pem,
        proof_signature_base64=base64.b64encode(signature).decode("ascii"),
        proof_challenge=challenge,
        key_source=KEY_SOURCE_DEMO_BACKEND,
    )
    cert_record = issue_enrollment(enrollment["enrollment_id"], activate=activate)
    cert_record["enrollment"] = enrollment
    return cert_record


def get_enrollment(enrollment_id: str) -> Dict:
    enrollment = next((e for e in _read_enrollments() if e["enrollment_id"] == enrollment_id), None)
    if not enrollment:
        raise ValueError("Unknown enrollment")
    return enrollment


def issue_enrollment(enrollment_id: str, activate: bool = False) -> Dict:
    enrollments = _read_enrollments()
    enrollment = next((e for e in enrollments if e["enrollment_id"] == enrollment_id), None)
    if not enrollment:
        raise ValueError("Unknown enrollment")

    if enrollment["status"] == "issued":
        existing_serial = enrollment.get("certificate_serial")
        if not existing_serial:
            raise ValueError("Issued enrollment is missing certificate_serial")
        existing_record = next((c for c in _read_certificates() if c["serial"] == existing_serial), None)
        if not existing_record:
            raise ValueError("Issued enrollment certificate record is missing")
        return activate_certificate(existing_serial) if activate else existing_record

    if enrollment["status"] != "pending":
        raise ValueError(f"Enrollment cannot be issued from status {enrollment['status']}")
    if not enrollment.get("proof_verified"):
        raise ValueError("Enrollment proof-of-possession was not verified")

    public_key_pem = Path(enrollment["public_key_path"]).read_text(encoding="utf-8")
    public_key = load_public_key_pem(public_key_pem)
    cert = issue_user_certificate_from_public_key(
        public_key=public_key,
        common_name=enrollment["display_name"],
        email=enrollment["email"],
    )

    serial = str(cert.serial_number)
    pem_path = settings.certificates_dir / f"cert_{serial}.pem"
    write_certificate_pem(pem_path, cert)

    custody = record_key_custody_metadata(enrollment)
    cert_record = {
        "serial": serial,
        "enrollment_id": enrollment_id,
        "subject": cert.subject.rfc4514_string(),
        "issuer": cert.issuer.rfc4514_string(),
        "profile_id": "demo-document-signing-v1",
        "pem_path": str(pem_path),
        "status": "issued",
        "valid_from": cert.not_valid_before_utc.isoformat(),
        "valid_to": cert.not_valid_after_utc.isoformat(),
        "revoked_at": None,
        "superseded_by": None,
        **custody,
        "origin": "lifecycle_issued",
        "created_at": _now(),
    }

    certificates = [c for c in _read_certificates() if c["serial"] != serial]
    certificates.append(cert_record)

    enrollment["status"] = "issued"
    enrollment["decided_at"] = _now()
    enrollment["certificate_serial"] = serial

    _write_enrollments(enrollments)
    _write_certificates(certificates)

    if activate:
        cert_record = activate_certificate(serial)
    return cert_record


def activate_certificate(serial: str) -> Dict:
    certificates = _read_certificates()
    record = next((c for c in certificates if c["serial"] == serial), None)
    if not record:
        raise ValueError("Unknown certificate")

    status = get_certificate_status(serial)
    if status["effective_status"] in {"revoked", "expired"}:
        raise ValueError(f"Cannot activate certificate with status {status['effective_status']}")

    email = _email_from_record(record)
    for cert in certificates:
        if cert["serial"] == serial:
            cert["status"] = "active"
        elif cert["status"] == "active" and _email_from_record(cert) == email:
            cert["status"] = "superseded"
            cert["superseded_by"] = serial

    _write_certificates(certificates)
    return next(c for c in certificates if c["serial"] == serial)


def revoke_certificate(serial: str) -> Dict:
    certificates = _read_certificates()
    record = next((c for c in certificates if c["serial"] == serial), None)
    if not record:
        raise ValueError("Unknown certificate")
    record["status"] = "revoked"
    record["revoked_at"] = _now()
    revocation_service.revoke(serial)
    _write_certificates(certificates)
    return get_certificate_status(serial)


def get_certificate_record(serial: str) -> Dict:
    sync_demo_certificate_record()
    record = next((c for c in _read_certificates() if c["serial"] == serial), None)
    if not record:
        raise ValueError("Unknown certificate")
    return _normalize_certificate_record(record)


def get_certificate_for_serial(serial: str):
    record = get_certificate_record(serial)
    return load_certificate_from_path(record["pem_path"])


def _email_from_record(record: Dict) -> str:
    enrollment_id = record.get("enrollment_id")
    enrollment = next((e for e in _read_enrollments() if e["enrollment_id"] == enrollment_id), None)
    return enrollment.get("email", "alice@example.com") if enrollment else "alice@example.com"


def _derive_status(record: Dict) -> str:
    cert = load_certificate_from_path(record["pem_path"])
    now = datetime.now(timezone.utc)
    if record["status"] == "revoked" or revocation_service.is_revoked(record["serial"]):
        return "revoked"
    if now > cert.not_valid_after_utc:
        return "expired"
    if record["status"] == "superseded":
        return "superseded"
    return record["status"]


def _effective_status(lifecycle_status: str, revocation_status: str) -> str:
    if revocation_status == "revoked":
        return "revoked"
    if lifecycle_status in {"revoked", "expired", "superseded", "rejected"}:
        return lifecycle_status
    return lifecycle_status


def get_certificate_status(serial: str) -> Dict:
    sync_demo_certificate_record()
    record = next((c for c in _read_certificates() if c["serial"] == serial), None)
    if not record:
        raise ValueError("Unknown certificate")
    record = _normalize_certificate_record(record)

    cert = load_certificate_from_path(record["pem_path"])
    lifecycle_status = _derive_status(record)
    rev = revocation_service.status(serial)
    effective_status = _effective_status(lifecycle_status, rev["status"])
    profile_validation = validate_document_signing_certificate_profile(cert)
    return {
        "serial": serial,
        "lifecycle_status": lifecycle_status,
        "revocation_status": rev["status"],
        "effective_status": effective_status,
        "revoked": effective_status == "revoked",
        "profile_id": record["profile_id"],
        "profile_validation": profile_validation,
        "subject": cert.subject.rfc4514_string(),
        "issuer": cert.issuer.rfc4514_string(),
        "valid_from": cert.not_valid_before_utc.isoformat(),
        "valid_to": cert.not_valid_after_utc.isoformat(),
        "key_source": record["key_source"],
        "private_key_custody": record["private_key_custody"],
        "backend_has_private_key": record["backend_has_private_key"],
        "certificate_origin": record.get("origin", "unknown"),
        "is_bootstrap_demo_certificate": record.get("origin") == "bootstrap_demo",
        "source": "DEMO_JSON_CERTIFICATE_LIFECYCLE",
        "warning": "Production requires database persistence, RBAC and real CRL/OCSP.",
    }


def get_active_certificate_record(email: str = "alice@example.com") -> Dict | None:
    sync_demo_certificate_record()
    active_records = [
        c for c in _read_certificates()
        if c["status"] == "active" and _email_from_record(c) == email
    ]
    for record in active_records:
        if _derive_status(record) == "active":
            return record
    return None


def get_my_active_certificate(email: str = "alice@example.com") -> Dict:
    active = get_active_certificate_record(email)
    if not active:
        raise ValueError("No active certificate")
    cert = load_certificate_from_path(active["pem_path"])
    return {
        **certificate_view_dict(cert, status_override=_derive_status(active)),
        **record_key_custody_metadata(active),
        "certificate_origin": active.get("origin", "unknown"),
        "is_bootstrap_demo_certificate": active.get("origin") == "bootstrap_demo",
    }


def get_certificate_chain(serial: str) -> Dict:
    record = next((c for c in _read_certificates() if c["serial"] == serial), None)
    if not record:
        raise ValueError("Unknown certificate")
    record = _normalize_certificate_record(record)
    user_cert = load_certificate_from_path(record["pem_path"])
    inter = get_intermediate_certificate()
    root = get_root_certificate()
    user_view = {
        **certificate_view_dict(user_cert, status_override=_derive_status(record)),
        **record_key_custody_metadata(record),
        "certificate_origin": record.get("origin", "unknown"),
    }
    return {
        "serial": serial,
        "chain": [
            user_view,
            certificate_view_dict(inter, status_override="active"),
            certificate_view_dict(root, status_override="active"),
        ],
    }


def list_certificates() -> List[Dict]:
    sync_demo_certificate_record()
    return [_normalize_certificate_record(record) for record in _read_certificates()]


def sync_demo_certificate_record(force_active: bool = False):
    if not USER_CERT.exists():
        init_demo_pki()
    cert = load_certificate_from_path(USER_CERT)
    serial = str(cert.serial_number)
    existing_certificates = _read_certificates()
    existing_demo = next((c for c in existing_certificates if c["serial"] == serial), None)
    certificates = [c for c in existing_certificates if c["serial"] != serial]
    if force_active:
        for record in certificates:
            if record.get("status") == "active" and _email_from_record(record) == "alice@example.com":
                record["status"] = "superseded"
                record["superseded_by"] = serial
    has_other_active_for_alice = any(
        c.get("status") == "active" and _email_from_record(c) == "alice@example.com"
        for c in certificates
    )
    has_lifecycle_for_alice = any(
        c.get("origin") == "lifecycle_issued" and _email_from_record(c) == "alice@example.com"
        for c in certificates
    )
    if force_active:
        demo_status = "active"
    elif existing_demo and existing_demo.get("status") in {"active", "revoked"}:
        demo_status = existing_demo["status"]
    elif has_other_active_for_alice or (has_lifecycle_for_alice and existing_demo and existing_demo.get("status") == "superseded"):
        demo_status = "superseded"
    else:
        demo_status = "active"
    if revocation_service.is_revoked(serial):
        demo_status = "revoked"

    demo_record = {
        "serial": serial,
        "enrollment_id": "demo_alice_bootstrap",
        "subject": cert.subject.rfc4514_string(),
        "issuer": cert.issuer.rfc4514_string(),
        "profile_id": "demo-document-signing-v1",
        "pem_path": str(USER_CERT),
        "status": demo_status,
        "valid_from": cert.not_valid_before_utc.isoformat(),
        "valid_to": cert.not_valid_after_utc.isoformat(),
        "revoked_at": None,
        "superseded_by": None,
        **key_custody_metadata(KEY_SOURCE_DEMO_BACKEND),
        "origin": "bootstrap_demo",
        "created_at": _now(),
    }
    certificates.append(demo_record)
    _write_certificates(certificates)

    enrollments = [e for e in _read_enrollments() if e["enrollment_id"] != "demo_alice_bootstrap"]
    demo_public_key_pem = get_demo_user_public_key_pem()
    demo_public_key = load_public_key_pem(demo_public_key_pem)
    enrollments.append({
        "enrollment_id": "demo_alice_bootstrap",
        "display_name": "Alice Demo Signer",
        "email": "alice@example.com",
        "public_key_path": str(settings.certificates_dir / "public_key_demo_alice_bootstrap.pem"),
        "public_key_fingerprint_sha256": _public_key_fingerprint(demo_public_key),
        "proof_challenge": "DEMO_BOOTSTRAP",
        "proof_verified": True,
        "status": "issued",
        "created_at": _now(),
        "decided_at": _now(),
        "certificate_serial": serial,
        **key_custody_metadata(KEY_SOURCE_DEMO_BACKEND),
    })
    Path(enrollments[-1]["public_key_path"]).write_text(demo_public_key_pem, encoding="utf-8")
    _write_enrollments(enrollments)
