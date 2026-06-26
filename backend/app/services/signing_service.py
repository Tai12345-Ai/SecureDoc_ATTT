"""
Signing Service.

Baseline:
- DSS: signing protocol and validation report separation.
- SignServer: signing operation is policy-controlled and auditable.
- pyca/cryptography: RSA-PSS signing and verification.

This demo signs a canonical payload that binds:
- requestId
- documentHash
- certificateSerial
- signingPurpose
- nonce
- timestamp
"""

import json
import re
import secrets
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature

from app.core.config import settings
from app.services.crypto_utils import sha256_bytes, digest_hex, canonical_json_bytes, b64e, b64d
from app.services.pki_service import get_demo_backend_user_private_key, load_certificate_from_path, verify_chain
from app.services.revocation_service import status as revocation_status, status_at as revocation_status_at
from app.services.timestamp_service import issue_demo_timestamp, verify_demo_timestamp
from app.services.audit_service import append_event
from app.services.certificate_lifecycle_service import get_certificate_record, get_certificate_status
from app.services.algorithm_policy import ALGORITHM_POLICY
from app.services.pades_service import (
    finalize_external_pades_signature,
    prepare_external_pades_signature,
    sign_pdf_pades_blt,
)
from app.services.key_custody import (
    KEY_SOURCE_CLIENT_SIDE,
    KEY_SOURCE_DEMO_BACKEND,
    KEY_SOURCE_REMOTE_HSM,
    key_custody_metadata,
)

_REQUESTS: Dict[str, Dict] = {}
_SIGNED_PACKAGES: Dict[str, Dict] = {}
_SIGNED_PDF_FILES: Dict[str, Dict] = {}
_CLIENT_PDF_PRESIGNS: Dict[str, Dict] = {}
CLIENT_PDF_PRESIGN_TTL_SECONDS = 300

def _safe_filename(filename: str | None) -> str:
    name = Path(filename or "document.bin").name
    name = re.sub(r"[^A-Za-z0-9._-]+", "_", name).strip("._")
    return name or "document.bin"

def _assert_certificate_usable(certificate_serial: str):
    cert_status = get_certificate_status(certificate_serial)
    if cert_status["effective_status"] != "active":
        raise ValueError(f"Certificate is not active/good: {cert_status['effective_status']}")
    if not cert_status["profile_validation"]["valid"]:
        raise ValueError("Certificate profile is not valid for document signing")
    return cert_status

def _certificate_for_record(record: Dict):
    return load_certificate_from_path(record["pem_path"])


def _request_certificate(certificate_serial: str):
    cert_record = get_certificate_record(certificate_serial)
    return _certificate_for_record(cert_record), cert_record


def _parse_utc_datetime(value: str) -> datetime:
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _assert_demo_signing_key_matches_certificate(cert: x509.Certificate):
    private_key = get_demo_backend_user_private_key()
    private_pub = private_key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    cert_pub = cert.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    if private_pub != cert_pub:
        raise ValueError("Active certificate does not match the demo backend signing key")


def _assert_backend_signing_allowed(cert_status: Dict, operation: str):
    key_source = cert_status.get("key_source")
    if key_source == KEY_SOURCE_DEMO_BACKEND:
        return
    if key_source == KEY_SOURCE_CLIENT_SIDE:
        if operation == "pdf":
            raise ValueError(
                "This certificate uses client-side private key custody. Backend cannot sign PDF "
                "with this certificate. Use client-side PAdES pre-sign/finalize or remote signing flow."
            )
        raise ValueError(
            "This certificate uses client-side private key custody. Backend cannot sign canonical "
            "payload with this certificate. Use submit_client_signature."
        )
    if key_source == KEY_SOURCE_REMOTE_HSM:
        if operation == "pdf":
            raise ValueError(
                "This certificate requires remote signing service/HSM. Remote PDF signing is not "
                "implemented yet."
            )
        raise ValueError(
            "This certificate requires remote signing service/HSM. Remote canonical payload signing "
            "is not implemented yet."
        )
    raise ValueError(f"Unsupported key custody mode for backend signing: {key_source}")

def prepare_request(
    document_name: str,
    document_bytes: bytes,
    signing_purpose: str,
    certificate_serial: str,
    digest_algorithm: str | None = None,
) -> Dict:
    cert_status = _assert_certificate_usable(certificate_serial)

    # Normalize and validate digest algorithm
    normalized_digest = ALGORITHM_POLICY.normalize_digest(digest_algorithm)
    display_digest = ALGORITHM_POLICY.display_digest(normalized_digest)

    request_id = "req_" + secrets.token_hex(12)
    safe_document_name = _safe_filename(document_name)
    document_hash = digest_hex(document_bytes, normalized_digest)
    nonce = secrets.token_hex(16)
    now = datetime.now(timezone.utc).isoformat()

    payload = {
        "schemaVersion": "securedoc-signing-payload-v1",
        "requestId": request_id,
        "documentName": safe_document_name,
        "documentHash": document_hash,
        "hashAlgorithm": display_digest,
        "hashAlgorithmNormalized": normalized_digest,
        "certificateSerial": certificate_serial,
        "signingPurpose": signing_purpose,
        "nonce": nonce,
        "createdAt": now,
    }

    doc_path = settings.documents_dir / f"{request_id}_{safe_document_name}"
    doc_path.write_bytes(document_bytes)

    record = {
        "request_id": request_id,
        "document_name": safe_document_name,
        "document_hash": document_hash,
        "document_path": str(doc_path),
        "certificate_serial": certificate_serial,
        "signing_purpose": signing_purpose,
        "nonce": nonce,
        "digest_algorithm": normalized_digest,
        "digest_algorithm_display": display_digest,
        "payload": payload,
        "confirmed": False,
        "signed": False,
    }
    _REQUESTS[request_id] = record

    append_event(
        actor="alice@example.com",
        action="prepare_signing_request",
        target=request_id,
        status="ok",
        metadata={
            "documentHash": document_hash,
            "certificateSerial": certificate_serial,
            "digestAlgorithm": display_digest,
        },
    )

    digest_info = {
        "selected_digest": display_digest,
        "selected_digest_normalized": normalized_digest,
        "is_pades_compatible": ALGORITHM_POLICY.is_pades_compatible(normalized_digest),
        "is_experimental": ALGORITHM_POLICY.is_experimental(normalized_digest),
    }
    if ALGORITHM_POLICY.is_experimental(normalized_digest):
        digest_info["experimental_warning"] = (
            f"{display_digest} is experimental. It is available for canonical payload demo "
            f"but is NOT enabled for PAdES/PDF signing."
        )

    return {
        "request_id": request_id,
        "document_name": document_name,
        "document_hash": document_hash,
        "hash_algorithm": display_digest,
        "certificate_serial": certificate_serial,
        "signing_purpose": signing_purpose,
        "nonce": nonce,
        "next_action": "confirm_signing_intent",
        "advanced": {
            "canonical_payload": payload,
            "canonical_payload_preview": canonical_json_bytes(payload).decode("utf-8"),
            "certificate_status": cert_status,
            "key_custody": {
                "key_source": cert_status["key_source"],
                "private_key_custody": cert_status["private_key_custody"],
                "backend_has_private_key": cert_status["backend_has_private_key"],
            },
            "digest_policy": digest_info,
        },
    }

def confirm_intent(request_id: str) -> Dict:
    record = _REQUESTS.get(request_id)
    if not record:
        raise ValueError("Unknown signing request")

    record["confirmed"] = True
    append_event(
        actor="alice@example.com",
        action="confirm_signing_intent",
        target=request_id,
        status="ok",
        metadata={
            "binds": ["requestId", "documentHash", "certificateSerial", "signingPurpose", "nonce"],
            "method": "DEMO_OTP",
        },
    )

    return {
        "request_id": request_id,
        "confirmed": True,
        "method": "DEMO_OTP",
        "message": "Ý chí ký đã được xác nhận và gắn với requestId/documentHash/certificateSerial/nonce.",
    }

def sign_and_verify(request_id: str) -> Dict:
    record = _REQUESTS.get(request_id)
    if not record:
        raise ValueError("Unknown signing request")
    if not record["confirmed"]:
        raise ValueError("Signing intent has not been confirmed")
    if record.get("signed"):
        raise ValueError("Signing request has already been signed")
    cert_status = _assert_certificate_usable(record["certificate_serial"])
    _assert_backend_signing_allowed(cert_status, operation="canonical")

    cert, _cert_record = _request_certificate(record["certificate_serial"])
    _assert_demo_signing_key_matches_certificate(cert)
    private_key = get_demo_backend_user_private_key()
    payload_bytes = canonical_json_bytes(record["payload"])

    # Use digest from the request record, not global default
    selected_digest = record.get("digest_algorithm", ALGORITHM_POLICY.default_digest)
    hash_algorithm = ALGORITHM_POLICY.cryptography_hash(selected_digest)
    digest_algorithm = ALGORITHM_POLICY.display_digest(selected_digest)

    signature = private_key.sign(
        payload_bytes,
        padding.PSS(mgf=padding.MGF1(hash_algorithm), salt_length=padding.PSS.MAX_LENGTH),
        hash_algorithm,
    )

    timestamp = issue_demo_timestamp(record["document_hash"])
    signed_package = {
        "packageType": "SECUREDOC_SIGNED_PACKAGE_V1",
        "payload": record["payload"],
        "signatureAlgorithm": "RSA-PSS",
        "digestAlgorithm": digest_algorithm,
        "digestAlgorithmNormalized": selected_digest,
        "signatureBase64": b64e(signature),
        "signerCertificatePem": cert.public_bytes(serialization.Encoding.PEM).decode("utf-8"),
        "timestamp": timestamp,
        "keyCustody": cert_status["key_source"],
        "privateKeyCustody": cert_status["private_key_custody"],
        "backendHasPrivateKey": cert_status["backend_has_private_key"],
        "signatureOrigin": "demo_backend_service",
    }

    _SIGNED_PACKAGES[request_id] = signed_package
    record["signed"] = True

    report = verify_signed_package(request_id, signed_package)
    append_event(
        actor="alice@example.com",
        action="sign_and_verify",
        target=request_id,
        status="ok" if report["accepted"] else "rejected",
        metadata={"signatureAlgorithm": "RSA-PSS", "digestAlgorithm": digest_algorithm},
    )
    return report

def submit_client_signature(request_id: str, signature_base64: str) -> Dict:
    record = _REQUESTS.get(request_id)
    if not record:
        raise ValueError("Unknown signing request")
    if not record["confirmed"]:
        raise ValueError("Signing intent has not been confirmed")
    if record.get("signed"):
        raise ValueError("Signing request has already been signed")
    cert_status = _assert_certificate_usable(record["certificate_serial"])

    cert, _cert_record = _request_certificate(record["certificate_serial"])
    payload_bytes = canonical_json_bytes(record["payload"])

    # Use digest from the request record
    selected_digest = record.get("digest_algorithm", ALGORITHM_POLICY.default_digest)
    hash_algorithm = ALGORITHM_POLICY.cryptography_hash(selected_digest)
    digest_algorithm = ALGORITHM_POLICY.display_digest(selected_digest)

    try:
        cert.public_key().verify(
            b64d(signature_base64),
            payload_bytes,
            padding.PSS(mgf=padding.MGF1(hash_algorithm), salt_length=padding.PSS.MAX_LENGTH),
            hash_algorithm,
        )
    except InvalidSignature as exc:
        raise ValueError("Client signature does not verify against active certificate") from exc

    timestamp = issue_demo_timestamp(record["document_hash"])
    custody = key_custody_metadata(cert_status["key_source"])
    signed_package = {
        "packageType": "SECUREDOC_CLIENT_SIGNED_PACKAGE_V1",
        "payload": record["payload"],
        "signatureAlgorithm": "RSA-PSS",
        "digestAlgorithm": digest_algorithm,
        "digestAlgorithmNormalized": selected_digest,
        "signatureBase64": signature_base64,
        "signerCertificatePem": cert.public_bytes(serialization.Encoding.PEM).decode("utf-8"),
        "timestamp": timestamp,
        "keyCustody": custody["key_source"],
        "privateKeyCustody": custody["private_key_custody"],
        "backendHasPrivateKey": custody["backend_has_private_key"],
        "signatureOrigin": "browser_or_external_client",
    }
    _SIGNED_PACKAGES[request_id] = signed_package
    record["signed"] = True
    report = verify_signed_package(request_id, signed_package)
    report["keyCustody"] = custody["key_source"]
    report["privateKeyCustody"] = custody["private_key_custody"]
    report["backendHasPrivateKey"] = custody["backend_has_private_key"]
    report["signatureOrigin"] = "browser_or_external_client"
    report.setdefault("advanced", {})["key_custody"] = {
        "key_source": custody["key_source"],
        "private_key_custody": custody["private_key_custody"],
        "backend_has_private_key": custody["backend_has_private_key"],
        "signature_origin": "browser_or_external_client",
    }
    append_event(
        actor="alice@example.com",
        action="submit_client_signature",
        target=request_id,
        status="ok" if report["accepted"] else "rejected",
        metadata={
            "keyCustody": custody["key_source"],
            "privateKeyCustody": custody["private_key_custody"],
            "backendHasPrivateKey": custody["backend_has_private_key"],
            "signatureOrigin": "browser_or_external_client",
        },
    )
    return report

def sign_pdf_request(request_id: str) -> Dict:
    record = _REQUESTS.get(request_id)
    if not record:
        raise ValueError("Unknown signing request")
    if not record["confirmed"]:
        raise ValueError("Signing intent has not been confirmed")
    if record.get("signed"):
        raise ValueError("Signing request has already been signed")
    cert_status = _assert_certificate_usable(record["certificate_serial"])
    _assert_backend_signing_allowed(cert_status, operation="pdf")
    signer_cert, _cert_record = _request_certificate(record["certificate_serial"])
    _assert_demo_signing_key_matches_certificate(signer_cert)

    # Reject SHA-3 for PAdES
    selected_digest = record.get("digest_algorithm", ALGORITHM_POLICY.default_digest)
    if not ALGORITHM_POLICY.is_pades_compatible(selected_digest):
        raise ValueError(
            f"Selected digest {ALGORITHM_POLICY.display_digest(selected_digest)} is experimental "
            f"and not enabled for PAdES signing. Use SHA-256/SHA-384/SHA-512 for PAdES."
        )

    document_path = Path(record["document_path"])
    file_id = "pdf_" + secrets.token_hex(12)
    signed_path = settings.signed_documents_dir / f"signed_{file_id}.pdf"
    signer_cert_path = settings.certificates_dir / f"active_signer_{record['certificate_serial']}.pem"
    signer_cert_path.parent.mkdir(parents=True, exist_ok=True)
    signer_cert_path.write_bytes(signer_cert.public_bytes(serialization.Encoding.PEM))

    sign_result = sign_pdf_pades_blt(
        input_pdf_path=document_path,
        output_pdf_path=signed_path,
        signer_cert_path=signer_cert_path,
        reason=record["signing_purpose"],
        field_name=f"SecureDocSignature_{request_id}",
        digest_algorithm=selected_digest,
    )
    verify_report = sign_result["verification_report"]
    signed_hash = sha256_bytes(signed_path.read_bytes())

    metadata = {
        "file_id": file_id,
        "request_id": request_id,
        "original_document_hash": record["document_hash"],
        "signed_document_hash": signed_hash,
        "original_filename": record["document_name"],
        "signed_path": str(signed_path),
        "signed_pdf_path": str(signed_path),
        "signer_certificate_serial": record["certificate_serial"],
        "target_profile": sign_result["target_profile"],
        "achieved_profile": sign_result["achieved_profile"],
        "pades_profile": sign_result["achieved_profile"],
        "digest_algorithm": sign_result["digest_algorithm"],
        "signature_algorithm": sign_result["signature_algorithm"],
        "timestamp_status": sign_result["timestamp_status"],
        "revocation_evidence_status": sign_result["revocation_evidence_status"],
        "certificate_chain_status": sign_result["certificate_chain_status"],
        "key_source": cert_status["key_source"],
        "private_key_custody": cert_status["private_key_custody"],
        "backend_has_private_key": cert_status["backend_has_private_key"],
        "missing_requirements": sign_result["missing_requirements"],
        "verification_report": verify_report,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    _SIGNED_PDF_FILES[file_id] = metadata
    record["signed"] = True

    append_event(
        actor="alice@example.com",
        action="sign_pdf_pades_blt",
        target=request_id,
        status="ok" if verify_report["accepted"] else "rejected",
        metadata={
            "fileId": file_id,
            "targetProfile": sign_result["target_profile"],
            "achievedProfile": sign_result["achieved_profile"],
            "digestAlgorithm": sign_result["digest_algorithm"],
            "keySource": cert_status["key_source"],
        },
    )

    return {
        "request_id": request_id,
        "file_id": file_id,
        "download_url": f"/api/user-signing/signed-files/{file_id}",
        "metadata": metadata,
        "verification": verify_report,
        "advanced": {
            "pades_signing": sign_result,
            "key_custody": {
                "key_source": cert_status["key_source"],
                "private_key_custody": cert_status["private_key_custody"],
                "backend_has_private_key": cert_status["backend_has_private_key"],
            },
            "storage": {
                "signed_file_id": file_id,
                "signed_document_hash": signed_hash,
            },
        },
    }


def prepare_client_pdf_signature(request_id: str) -> Dict:
    record = _REQUESTS.get(request_id)
    if not record:
        raise ValueError("Unknown signing request")
    if not record["confirmed"]:
        raise ValueError("Signing intent has not been confirmed")
    if record.get("signed"):
        raise ValueError("Signing request has already been signed")

    cert_status = _assert_certificate_usable(record["certificate_serial"])
    if cert_status.get("key_source") != KEY_SOURCE_CLIENT_SIDE:
        raise ValueError("Client-side PAdES signing requires a CLIENT_SIDE_KEY certificate")

    selected_digest = record.get("digest_algorithm", ALGORITHM_POLICY.default_digest)
    if not ALGORITHM_POLICY.is_pades_compatible(selected_digest):
        raise ValueError(
            f"Selected digest {ALGORITHM_POLICY.display_digest(selected_digest)} is experimental "
            f"and not enabled for PAdES signing. Use SHA-256/SHA-384/SHA-512 for PAdES."
        )

    cert, _cert_record = _request_certificate(record["certificate_serial"])
    public_key_size = getattr(cert.public_key(), "key_size", None)
    if not public_key_size:
        raise ValueError("Client-side PAdES signing currently requires an RSA certificate")

    document_path = Path(record["document_path"])
    file_id = "pdf_" + secrets.token_hex(12)
    presigned_path = settings.signed_documents_dir / f"client_presign_{file_id}.pdf"
    signer_cert_path = settings.certificates_dir / f"client_side_signer_{record['certificate_serial']}.pem"
    signer_cert_path.parent.mkdir(parents=True, exist_ok=True)
    signer_cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(seconds=CLIENT_PDF_PRESIGN_TTL_SECONDS)

    presign_state = prepare_external_pades_signature(
        input_pdf_path=document_path,
        presigned_pdf_path=presigned_path,
        signer_cert_path=signer_cert_path,
        reason=record["signing_purpose"],
        field_name=f"SecureDocClientSignature_{request_id}",
        public_key_size_bits=public_key_size,
        digest_algorithm=selected_digest,
    )
    presign_state.update(
        {
            "request_id": request_id,
            "file_id": file_id,
            "certificate_serial": record["certificate_serial"],
            "signer_cert_path": str(signer_cert_path),
            "created_at": now.isoformat(),
            "expires_at": expires_at.isoformat(),
            "key_custody": {
                "key_source": cert_status["key_source"],
                "private_key_custody": cert_status["private_key_custody"],
                "backend_has_private_key": cert_status["backend_has_private_key"],
            },
        }
    )
    _CLIENT_PDF_PRESIGNS[request_id] = presign_state

    append_event(
        actor="alice@example.com",
        action="prepare_client_side_pades",
        target=request_id,
        status="ok",
        metadata={
            "fileId": file_id,
            "keySource": cert_status["key_source"],
            "digestAlgorithm": presign_state["digest_algorithm"],
        },
    )

    return {
        "request_id": request_id,
        "file_id": file_id,
        "certificate_serial": record["certificate_serial"],
        "signed_attributes_base64": b64e(presign_state["signed_attrs_der"]),
        "signed_attributes_sha256": sha256_bytes(presign_state["signed_attrs_der"]),
        "document_digest_base64": b64e(presign_state["document_digest"]),
        "digest_algorithm": presign_state["digest_algorithm"],
        "digest_algorithm_normalized": presign_state["digest_algorithm_normalized"],
        "signature_algorithm": "RSA-PSS",
        "rsa_pss_salt_length": presign_state["rsa_pss_salt_length"],
        "key_custody": presign_state["key_custody"],
        "expires_at": presign_state["expires_at"],
        "next_action": "sign_signed_attributes_with_client_private_key",
        "warning": (
            "Client must sign signed_attributes_base64 bytes exactly. "
            "The backend verifies the raw signature with the certificate public key and finalizes CMS/PDF."
        ),
    }


def finalize_client_pdf_signature(request_id: str, signature_base64: str) -> Dict:
    record = _REQUESTS.get(request_id)
    if not record:
        raise ValueError("Unknown signing request")
    if not record["confirmed"]:
        raise ValueError("Signing intent has not been confirmed")
    if record.get("signed"):
        raise ValueError("Signing request has already been signed")
    presign_state = _CLIENT_PDF_PRESIGNS.get(request_id)
    if not presign_state:
        raise ValueError("No pending client-side PAdES pre-sign state for request")
    expires_at = _parse_utc_datetime(presign_state["expires_at"])
    if datetime.now(timezone.utc) > expires_at:
        _CLIENT_PDF_PRESIGNS.pop(request_id, None)
        raise ValueError("Client-side PAdES pre-sign state has expired; prepare again")
    if presign_state.get("certificate_serial") != record["certificate_serial"]:
        _CLIENT_PDF_PRESIGNS.pop(request_id, None)
        raise ValueError("Client-side PAdES pre-sign state is not bound to this certificate")

    cert_status = _assert_certificate_usable(record["certificate_serial"])
    if cert_status.get("key_source") != KEY_SOURCE_CLIENT_SIDE:
        raise ValueError("Client-side PAdES finalization requires a CLIENT_SIDE_KEY certificate")
    cert, _cert_record = _request_certificate(record["certificate_serial"])
    selected_digest = presign_state["digest_algorithm_normalized"]
    hash_algorithm = ALGORITHM_POLICY.cryptography_hash(selected_digest)
    signature = b64d(signature_base64)

    try:
        cert.public_key().verify(
            signature,
            presign_state["signed_attrs_der"],
            padding.PSS(
                mgf=padding.MGF1(hash_algorithm),
                salt_length=presign_state["rsa_pss_salt_length"],
            ),
            hash_algorithm,
        )
    except InvalidSignature as exc:
        _CLIENT_PDF_PRESIGNS.pop(request_id, None)
        raise ValueError("Client PDF signature does not verify against certificate public key") from exc

    try:
        sign_result = finalize_external_pades_signature(presign_state, signature)
    except Exception:
        _CLIENT_PDF_PRESIGNS.pop(request_id, None)
        raise
    signed_path = Path(sign_result["signed_pdf_path"])
    signed_hash = sha256_bytes(signed_path.read_bytes())
    verify_report = sign_result["verification_report"]
    file_id = presign_state["file_id"]

    metadata = {
        "file_id": file_id,
        "request_id": request_id,
        "original_document_hash": record["document_hash"],
        "signed_document_hash": signed_hash,
        "original_filename": record["document_name"],
        "signed_path": str(signed_path),
        "signed_pdf_path": str(signed_path),
        "signer_certificate_serial": record["certificate_serial"],
        "target_profile": sign_result["target_profile"],
        "achieved_profile": sign_result["achieved_profile"],
        "pades_profile": sign_result["achieved_profile"],
        "digest_algorithm": sign_result["digest_algorithm"],
        "signature_algorithm": sign_result["signature_algorithm"],
        "timestamp_status": sign_result["timestamp_status"],
        "revocation_evidence_status": sign_result["revocation_evidence_status"],
        "certificate_chain_status": sign_result["certificate_chain_status"],
        "key_source": cert_status["key_source"],
        "private_key_custody": cert_status["private_key_custody"],
        "backend_has_private_key": cert_status["backend_has_private_key"],
        "signature_origin": "browser_or_external_client",
        "missing_requirements": sign_result["missing_requirements"],
        "verification_report": verify_report,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    _SIGNED_PDF_FILES[file_id] = metadata
    record["signed"] = True
    _CLIENT_PDF_PRESIGNS.pop(request_id, None)

    append_event(
        actor="alice@example.com",
        action="finalize_client_side_pades",
        target=request_id,
        status="ok" if verify_report["accepted"] else "rejected",
        metadata={
            "fileId": file_id,
            "keySource": cert_status["key_source"],
            "digestAlgorithm": sign_result["digest_algorithm"],
            "signatureOrigin": "browser_or_external_client",
        },
    )

    return {
        "request_id": request_id,
        "file_id": file_id,
        "download_url": f"/api/user-signing/signed-files/{file_id}",
        "metadata": metadata,
        "verification": verify_report,
        "client_side_pades": {
            "keyCustody": cert_status["key_source"],
            "privateKeyCustody": cert_status["private_key_custody"],
            "backendHasPrivateKey": cert_status["backend_has_private_key"],
            "signatureOrigin": "browser_or_external_client",
            "signedAttributeSource": "CMS signedAttrs DER",
        },
        "advanced": {
            "pades_signing": sign_result,
            "key_custody": {
                "key_source": cert_status["key_source"],
                "private_key_custody": cert_status["private_key_custody"],
                "backend_has_private_key": cert_status["backend_has_private_key"],
            },
            "storage": {
                "signed_file_id": file_id,
                "signed_document_hash": signed_hash,
            },
        },
    }


def get_signed_pdf_record(file_id: str) -> Dict | None:
    return _SIGNED_PDF_FILES.get(file_id)

def get_signing_history() -> list[Dict]:
    records = sorted(
        _SIGNED_PDF_FILES.values(),
        key=lambda item: item.get("created_at", ""),
        reverse=True,
    )
    return [
        {
            "file_id": record["file_id"],
            "request_id": record["request_id"],
            "original_filename": record["original_filename"],
            "signer_certificate_serial": record["signer_certificate_serial"],
            "target_profile": record.get("target_profile", "PAdES-B-LT"),
            "achieved_profile": record.get("achieved_profile", record["pades_profile"]),
            "pades_profile": record["pades_profile"],
            "digest_algorithm": record.get("digest_algorithm"),
            "signature_algorithm": record.get("signature_algorithm"),
            "created_at": record["created_at"],
            "signed_document_hash": record["signed_document_hash"],
            "download_url": f"/api/user-signing/signed-files/{record['file_id']}",
        }
        for record in records
    ]

def verify_signed_package(request_id: str, signed_package: Dict | None = None) -> Dict:
    record = _REQUESTS.get(request_id)
    if not record:
        raise ValueError("Unknown signing request")
    package = signed_package or _SIGNED_PACKAGES.get(request_id)
    if not package:
        raise ValueError("No signed package for request")

    checks = []

    def add(key: str, label: str, ok: bool, message: str):
        checks.append({"key": key, "label": label, "ok": ok, "message": message})

    payload = package["payload"]
    payload_bytes = canonical_json_bytes(payload)
    cert = x509.load_pem_x509_certificate(package["signerCertificatePem"].encode("utf-8"))
    public_key = cert.public_key()
    signer_cert_serial = str(cert.serial_number)

    # Use the digest declared in the signed package for verification
    package_digest = (
        package.get("digestAlgorithmNormalized")
        or package.get("digestAlgorithm")
        or ALGORITHM_POLICY.default_digest
    )
    hash_algorithm = ALGORITHM_POLICY.cryptography_hash(package_digest)

    try:
        public_key.verify(
            b64d(package["signatureBase64"]),
            payload_bytes,
            padding.PSS(mgf=padding.MGF1(hash_algorithm), salt_length=padding.PSS.MAX_LENGTH),
            hash_algorithm,
        )
        add("cryptoValid", "Chữ ký mật mã hợp lệ", True, "Public key trong chứng thư xác minh được chữ ký RSA-PSS.")
    except InvalidSignature:
        add("cryptoValid", "Chữ ký mật mã hợp lệ", False, "Không xác minh được chữ ký.")

    # Recompute document hash using the digest declared in the signed payload
    payload_hash_algorithm = (
        payload.get("hashAlgorithmNormalized")
        or payload.get("hashAlgorithm")
        or ALGORITHM_POLICY.default_digest
    )
    actual_document_hash = digest_hex(Path(record["document_path"]).read_bytes(), payload_hash_algorithm)
    add(
        "documentHashValid",
        "Tài liệu chưa bị sửa",
        actual_document_hash == payload.get("documentHash"),
        "Hash tài liệu hiện tại trùng với hash trong payload đã ký." if actual_document_hash == payload.get("documentHash") else "Hash tài liệu không khớp.",
    )

    add(
        "contextBound",
        "Ngữ cảnh ký được ràng buộc",
        payload.get("requestId") == request_id and payload.get("certificateSerial") == record["certificate_serial"] and payload.get("nonce") == record["nonce"],
        "requestId, certificateSerial và nonce khớp signing request.",
    )

    add(
        "signerCertificateMatchesRequest",
        "Signer certificate matches request",
        signer_cert_serial == record["certificate_serial"] == payload.get("certificateSerial"),
        "Signer certificate serial matches the signed payload and signing request.",
    )

    chain = verify_chain(cert)
    for chain_check in chain["checks"]:
        add(chain_check["key"], chain_check["label"], chain_check["ok"], chain_check["message"])

    ts = verify_demo_timestamp(package["timestamp"], payload.get("documentHash"))
    add("timestampValid", "Timestamp hợp lệ", ts["ok"], ts["message"])

    if ts.get("ok") and ts.get("genTime"):
        rev = revocation_status_at(record["certificate_serial"], ts["genTime"])
        revocation_ok = not rev["revoked_at_time"]
        revocation_message = (
            "Certificate was good at trusted signing time."
            if revocation_ok
            else "Certificate had already been revoked at trusted signing time."
        )
        revocation_checked_at = "signing_time"
    else:
        rev = revocation_status(record["certificate_serial"])
        revocation_ok = not rev["revoked"]
        revocation_message = (
            "Certificate is good at verification time, but signing time is not trusted."
            if revocation_ok
            else "Certificate is revoked at verification time and no trusted timestamp proves earlier signing."
        )
        revocation_checked_at = "verify_time"

    add(
        "revocationValid",
        "Trạng thái thu hồi chứng thư hợp lệ",
        revocation_ok,
        revocation_message,
    )

    accepted = all(c["ok"] for c in checks)

    selected_digest_display = ALGORITHM_POLICY.display_digest(
        record.get("digest_algorithm", ALGORITHM_POLICY.default_digest)
    )
    package_key_source = package.get("keyCustody")
    package_private_key_custody = package.get("privateKeyCustody")
    package_backend_has_private_key = package.get("backendHasPrivateKey")
    package_signature_origin = package.get("signatureOrigin")
    warnings = [
        "Demo mode: chưa dùng public trusted CA.",
        "Demo mode: chưa dùng HSM/KMS.",
        "Demo mode: timestamp là signed demo TSA token, chưa phải RFC3161 TSA.",
        "Demo mode: revocation là local list, chưa phải OCSP/CRL.",
    ]

    return {
        "request_id": request_id,
        "status": "accepted" if accepted else "rejected",
        "title": "Tài liệu đã được ký và xác minh thành công" if accepted else "Tài liệu ký không hợp lệ",
        "message": "Chữ ký, hash tài liệu, chứng thư, chuỗi tin cậy, trạng thái thu hồi và timestamp demo đều hợp lệ." if accepted else "Một hoặc nhiều kiểm tra không hợp lệ.",
        "checks": checks,
        "legal_ready": False,
        "warnings": warnings,
        "accepted": accepted,
        "keyCustody": package_key_source,
        "privateKeyCustody": package_private_key_custody,
        "backendHasPrivateKey": package_backend_has_private_key,
        "signatureOrigin": package_signature_origin,
        "advanced": {
            "signed_package": package,
            "key_custody": {
                "key_source": package_key_source,
                "private_key_custody": package_private_key_custody,
                "backend_has_private_key": package_backend_has_private_key,
                "signature_origin": package_signature_origin,
            },
            "timestamp_validation": ts,
            "revocation_validation": {
                **rev,
                "checked_at_policy": revocation_checked_at,
            },
            "digest_algorithm": selected_digest_display,
            "signature_algorithm": "RSA-PSS",
            "timestamp_source": "demo_signed_tsa_token",
            "production_tsa": False,
            "ocsp_mode": "demo_local_registry",
            "legal_ready": False,
            "verification_model": "DSS-style validation report simplified for educational demo.",
        },
    }

def get_request(request_id: str) -> Dict | None:
    return _REQUESTS.get(request_id)
