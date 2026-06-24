"""
SignServer-like remote signing boundary.

This demo keeps the private key server-side and enforces a minimal policy:
confirmed request + demo MFA + active certificate. Production should replace
the key backend with HSM/KMS/qualified remote signing service.
"""

from app.services.audit_service import append_event
from app.services.signing_service import get_request, sign_and_verify

DEMO_MFA_CODE = "000000"


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
            "keyCustody": "DEMO_BACKEND_SIGNING_KEY",
        },
    )
    report = sign_and_verify(request_id)
    append_event(actor, "remote_signing_completed", request_id, report["status"])
    return {
        "request_id": request_id,
        "remote_signing": {
            "service": "SecureDoc Demo Remote Signing Service",
            "policy": "confirmed_intent + demo_mfa + active_certificate",
            "keyCustody": "DEMO_BACKEND_SIGNING_KEY",
            "privateKeyExposed": False,
        },
        "report": report,
    }
