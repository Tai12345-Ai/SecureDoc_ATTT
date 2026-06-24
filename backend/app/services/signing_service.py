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
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature

from app.core.config import settings
from app.services.crypto_utils import sha256_bytes, canonical_json_bytes, b64e, b64d
from app.services.pki_service import get_user_certificate, get_user_private_key, verify_chain
from app.services.revocation_service import status as revocation_status, status_at as revocation_status_at
from app.services.timestamp_service import issue_demo_timestamp, verify_demo_timestamp
from app.services.audit_service import append_event
from app.services.certificate_lifecycle_service import get_certificate_status
from app.services.pades_service import sign_pdf_pades_bb, verify_pdf_signature

_REQUESTS: Dict[str, Dict] = {}
_SIGNED_PACKAGES: Dict[str, Dict] = {}
_SIGNED_PDF_FILES: Dict[str, Dict] = {}

def _safe_filename(filename: str | None) -> str:
    name = Path(filename or "document.bin").name
    name = re.sub(r"[^A-Za-z0-9._-]+", "_", name).strip("._")
    return name or "document.bin"

def _assert_certificate_usable(certificate_serial: str):
    cert_status = get_certificate_status(certificate_serial)
    if cert_status["lifecycle_status"] != "active" or cert_status["revoked"]:
        raise ValueError(f"Certificate is not active/good: {cert_status['lifecycle_status']}")
    return cert_status

def _assert_demo_signing_key_matches_active_certificate():
    private_key = get_user_private_key()
    cert = get_user_certificate()
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

def prepare_request(document_name: str, document_bytes: bytes, signing_purpose: str, certificate_serial: str) -> Dict:
    cert_status = _assert_certificate_usable(certificate_serial)
    request_id = "req_" + secrets.token_hex(12)
    safe_document_name = _safe_filename(document_name)
    document_hash = sha256_bytes(document_bytes)
    nonce = secrets.token_hex(16)
    now = datetime.now(timezone.utc).isoformat()

    payload = {
        "schemaVersion": "securedoc-signing-payload-v1",
        "requestId": request_id,
        "documentName": safe_document_name,
        "documentHash": document_hash,
        "hashAlgorithm": "SHA-256",
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
        metadata={"documentHash": document_hash, "certificateSerial": certificate_serial},
    )

    return {
        "request_id": request_id,
        "document_name": document_name,
        "document_hash": document_hash,
        "hash_algorithm": "SHA-256",
        "certificate_serial": certificate_serial,
        "signing_purpose": signing_purpose,
        "nonce": nonce,
        "next_action": "confirm_signing_intent",
        "advanced": {
            "canonical_payload": payload,
            "canonical_payload_preview": canonical_json_bytes(payload).decode("utf-8"),
            "certificate_status": cert_status,
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
    _assert_certificate_usable(record["certificate_serial"])
    _assert_demo_signing_key_matches_active_certificate()

    private_key = get_user_private_key()
    cert = get_user_certificate()
    payload_bytes = canonical_json_bytes(record["payload"])

    signature = private_key.sign(
        payload_bytes,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256(),
    )

    timestamp = issue_demo_timestamp(record["document_hash"])
    signed_package = {
        "packageType": "SECUREDOC_SIGNED_PACKAGE_V1",
        "payload": record["payload"],
        "signatureAlgorithm": "RSA-PSS-SHA256",
        "signatureBase64": b64e(signature),
        "signerCertificatePem": cert.public_bytes(serialization.Encoding.PEM).decode("utf-8"),
        "timestamp": timestamp,
    }

    _SIGNED_PACKAGES[request_id] = signed_package
    record["signed"] = True

    report = verify_signed_package(request_id, signed_package)
    append_event(
        actor="alice@example.com",
        action="sign_and_verify",
        target=request_id,
        status="ok" if report["accepted"] else "rejected",
        metadata={"signatureAlgorithm": "RSA-PSS-SHA256"},
    )
    return report

def submit_client_signature(request_id: str, signature_base64: str) -> Dict:
    record = _REQUESTS.get(request_id)
    if not record:
        raise ValueError("Unknown signing request")
    if not record["confirmed"]:
        raise ValueError("Signing intent has not been confirmed")
    _assert_certificate_usable(record["certificate_serial"])

    cert = get_user_certificate()
    payload_bytes = canonical_json_bytes(record["payload"])
    try:
        cert.public_key().verify(
            b64d(signature_base64),
            payload_bytes,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256(),
        )
    except InvalidSignature as exc:
        raise ValueError("Client signature does not verify against active certificate") from exc

    timestamp = issue_demo_timestamp(record["document_hash"])
    signed_package = {
        "packageType": "SECUREDOC_CLIENT_SIGNED_PACKAGE_V1",
        "payload": record["payload"],
        "signatureAlgorithm": "RSA-PSS-SHA256",
        "signatureBase64": signature_base64,
        "signerCertificatePem": cert.public_bytes(serialization.Encoding.PEM).decode("utf-8"),
        "timestamp": timestamp,
        "keyCustody": "BROWSER_LOCAL_SIGNING",
    }
    _SIGNED_PACKAGES[request_id] = signed_package
    record["signed"] = True
    report = verify_signed_package(request_id, signed_package)
    append_event(
        actor="alice@example.com",
        action="submit_client_signature",
        target=request_id,
        status="ok" if report["accepted"] else "rejected",
        metadata={"keyCustody": "BROWSER_LOCAL_SIGNING"},
    )
    return report

def sign_pdf_request(request_id: str) -> Dict:
    record = _REQUESTS.get(request_id)
    if not record:
        raise ValueError("Unknown signing request")
    if not record["confirmed"]:
        raise ValueError("Signing intent has not been confirmed")
    _assert_certificate_usable(record["certificate_serial"])
    _assert_demo_signing_key_matches_active_certificate()

    document_path = Path(record["document_path"])
    file_id = "pdf_" + secrets.token_hex(12)
    signed_path = settings.signed_documents_dir / f"signed_{file_id}.pdf"
    signer_cert = get_user_certificate()
    signer_cert_path = settings.certificates_dir / f"active_signer_{record['certificate_serial']}.pem"
    signer_cert_path.parent.mkdir(parents=True, exist_ok=True)
    signer_cert_path.write_bytes(signer_cert.public_bytes(serialization.Encoding.PEM))

    sign_result = sign_pdf_pades_bb(
        input_pdf_path=document_path,
        output_pdf_path=signed_path,
        signer_cert_path=signer_cert_path,
        reason=record["signing_purpose"],
        field_name=f"SecureDocSignature_{request_id}",
    )
    verify_report = verify_pdf_signature(signed_path)
    signed_hash = sha256_bytes(signed_path.read_bytes())

    metadata = {
        "file_id": file_id,
        "request_id": request_id,
        "original_document_hash": record["document_hash"],
        "signed_document_hash": signed_hash,
        "original_filename": record["document_name"],
        "signed_path": str(signed_path),
        "signer_certificate_serial": record["certificate_serial"],
        "pades_profile": sign_result["pades_profile"],
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    _SIGNED_PDF_FILES[file_id] = metadata

    append_event(
        actor="alice@example.com",
        action="sign_pdf_pades_bb",
        target=request_id,
        status="ok" if verify_report["accepted"] else "rejected",
        metadata={"fileId": file_id, "padesProfile": sign_result["pades_profile"]},
    )

    return {
        "request_id": request_id,
        "file_id": file_id,
        "download_url": f"/api/user-signing/signed-files/{file_id}",
        "metadata": metadata,
        "verification": verify_report,
        "advanced": {
            "pades_signing": sign_result,
            "storage": {
                "signed_file_id": file_id,
                "signed_document_hash": signed_hash,
            },
        },
    }

def get_signed_pdf_record(file_id: str) -> Dict | None:
    return _SIGNED_PDF_FILES.get(file_id)

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
    cert = get_user_certificate()
    public_key = cert.public_key()

    try:
        public_key.verify(
            b64d(package["signatureBase64"]),
            payload_bytes,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256(),
        )
        add("cryptoValid", "Chữ ký mật mã hợp lệ", True, "Public key trong chứng thư xác minh được chữ ký RSA-PSS.")
    except InvalidSignature:
        add("cryptoValid", "Chữ ký mật mã hợp lệ", False, "Không xác minh được chữ ký.")

    actual_document_hash = sha256_bytes(Path(record["document_path"]).read_bytes())
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

    chain = verify_chain()
    for chain_check in chain["checks"]:
        add(chain_check["key"], chain_check["label"], chain_check["ok"], chain_check["message"])

    ts = verify_demo_timestamp(package["timestamp"], payload.get("documentHash"))
    add("timestampValid", "Timestamp hợp lệ", ts["ok"], ts["message"])

    if ts.get("trusted") and ts.get("genTime"):
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
        "advanced": {
            "signed_package": package,
            "timestamp_validation": ts,
            "revocation_validation": {
                **rev,
                "checked_at_policy": revocation_checked_at,
            },
            "verification_model": "DSS-style validation report simplified for educational demo.",
        },
    }

def get_request(request_id: str) -> Dict | None:
    return _REQUESTS.get(request_id)
