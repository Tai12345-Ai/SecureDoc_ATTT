"""
SignServer-like remote signing boundary.

This demo keeps the private key server-side and enforces a minimal policy:
confirmed request + demo MFA + active certificate. Production should replace
the key backend with HSM/KMS/qualified remote signing service.
"""

from app.services.audit_service import append_event
from app.services.signing_service import get_request, sign_and_verify, sign_pdf_request
from app.services.pades_service import is_pdf_bytes
from pathlib import Path
from app.services.key_custody import KEY_SOURCE_DEMO_BACKEND, key_custody_metadata

DEMO_MFA_CODE = "000000"


def _demo_remote_key_custody() -> dict:
    custody = key_custody_metadata(KEY_SOURCE_DEMO_BACKEND)
    return {
        "keyCustody": custody["key_source"],
        "privateKeyCustody": custody["private_key_custody"],
        "backendHasPrivateKey": custody["backend_has_private_key"],
        "privateKeyExposed": False,
    }


def remote_sign_request(request_id: str, mfa_code: str, actor: str = "alice@example.com") -> dict:
    record = get_request(request_id)
    if not record:
        raise ValueError("Unknown signing request")
    if not record.get("confirmed"):
        raise ValueError("Signing intent has not been confirmed")
    if mfa_code != DEMO_MFA_CODE:
        append_event(actor, "remote_signing_denied", request_id, "rejected", {"reason": "invalid_mfa"})
        raise ValueError("Invalid demo MFA code")

    append_event(
        actor,
        "remote_signing_policy_check",
        request_id,
        "ok",
        {
            "policy": "confirmed_intent + demo_mfa + active_certificate",
            "keyCustody": KEY_SOURCE_DEMO_BACKEND,
        },
    )
    report = sign_and_verify(request_id)
    append_event(actor, "remote_signing_completed", request_id, report["status"])
    return {
        "request_id": request_id,
        "remote_signing": {
            "service": "SecureDoc Demo Remote Signing Service",
            "policy": "confirmed_intent + demo_mfa + active_certificate",
            **_demo_remote_key_custody(),
            "productionRequires": "HSM/KMS/qualified remote signing service",
        },
        "report": report,
    }


def remote_sign_pdf_request(request_id: str, mfa_code: str, actor: str = "alice@example.com") -> dict:
    """Remote sign a PDF/PAdES document.

    Flow:
    1. Validate request exists and is confirmed.
    2. Validate demo MFA code.
    3. Validate that the uploaded document is a PDF.
    4. Call sign_pdf_request() to produce PAdES-B-LT signed PDF.
    5. Return signed file metadata and verification report.
    """
    record = get_request(request_id)
    if not record:
        raise ValueError("Unknown signing request")
    if not record.get("confirmed"):
        raise ValueError("Signing intent has not been confirmed")
    if mfa_code != DEMO_MFA_CODE:
        append_event(actor, "remote_signing_pdf_denied", request_id, "rejected", {"reason": "invalid_mfa"})
        raise ValueError("Invalid demo MFA code")

    # Verify document is PDF
    doc_path = Path(record.get("document_path", ""))
    if not doc_path.exists():
        raise ValueError("Document file not found for request")
    if not is_pdf_bytes(doc_path.read_bytes()):
        raise ValueError("Document is not a PDF. Remote PDF signing requires a PDF file.")

    append_event(
        actor,
        "remote_signing_pdf_policy_check",
        request_id,
        "ok",
        {
            "policy": "confirmed_intent + demo_mfa + active_certificate + pdf_document",
            "keyCustody": KEY_SOURCE_DEMO_BACKEND,
        },
    )

    result = sign_pdf_request(request_id)
    append_event(actor, "remote_signing_pdf_completed", request_id, result["verification"]["status"])

    return {
        "request_id": request_id,
        "file_id": result["file_id"],
        "download_url": result["download_url"],
        "metadata": result["metadata"],
        "verification": result["verification"],
        "remote_signing": {
            "service": "SecureDoc Demo Remote Signing Service",
            "policy": "confirmed_intent + demo_mfa + active_certificate + pdf_document",
            **_demo_remote_key_custody(),
            "productionRequires": "HSM/KMS/qualified remote signing service",
        },
    }
