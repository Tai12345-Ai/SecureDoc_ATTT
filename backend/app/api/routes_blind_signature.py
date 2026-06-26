from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Optional
from app.services.blind_signature_service import (
    blind_signer_info,
    blind_sign_message,
    redeem_with_verification,
    run_blind_signature_flow,
)
from app.services.audit_service import append_event

router = APIRouter()


class BlindRequest(BaseModel):
    message: str


class BlindSignRequest(BaseModel):
    blinded_msg: str
    key_id: str
    # Explicitly reject these fields if sent
    token: Optional[str] = None
    message: Optional[str] = None
    original_message: Optional[str] = None
    signature: Optional[str] = None


class RedeemRequest(BaseModel):
    token_hash: str
    signature: str
    msg_prefix_hex: str
    token: str


@router.get("/signer-info")
def get_signer_info():
    """Returns the blind signer public key information needed by clients."""
    return blind_signer_info()


@router.post("/blind-sign")
def blind_sign_endpoint(req: BlindSignRequest):
    """
    Server-only blind-sign: accepts only blinded_msg + key_id.

    The server MUST NOT receive the original token, message, or unblinded
    signature. If any of these fields are provided, the request is rejected.
    """
    # Reject if caller accidentally sends original token data
    for field_name, field_val in [
        ("token", req.token),
        ("message", req.message),
        ("original_message", req.original_message),
        ("signature", req.signature),
    ]:
        if field_val is not None:
            raise HTTPException(
                status_code=400,
                detail=f"Field '{field_name}' must not be sent to the blind-sign endpoint. "
                       f"The server must only receive the blinded message.",
            )

    try:
        result = blind_sign_message(req.blinded_msg, req.key_id)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    append_event(
        "blind-signer",
        "blind_sign_protocol",
        req.key_id,
        "ok",
        {"key_id": req.key_id, "achieved_scheme": result["achieved_scheme"]},
    )
    return result


@router.post("/redeem")
def redeem_endpoint(req: RedeemRequest):
    """
    Verify signature and redeem token. Rejects duplicate redemption as already_spent.
    """
    try:
        result = redeem_with_verification(
            token_hash=req.token_hash,
            signature_hex=req.signature,
            msg_prefix_hex=req.msg_prefix_hex,
            token=req.token,
        )
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    append_event(
        "verifier",
        "blind_token_redeem",
        req.token_hash,
        "ok" if result["accepted"] else "rejected",
        {"reason": result["reason"]},
    )
    return result


@router.post("/run")
def run(req: BlindRequest):
    """Educational all-in-one demo: the server sees the original token."""
    try:
        result = run_blind_signature_flow(req.message)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    append_event(
        "alice@example.com",
        "blind_signature_demo",
        result["token_hash"],
        "ok" if result["blind_signature_valid"] else "rejected",
        {
            "targetScheme": result["target_scheme"],
            "achievedScheme": result["achieved_scheme"],
            "schemeComplete": result["scheme_complete"],
            "spentStatus": result["spent_status"],
            "keyId": result["key_id"],
        },
    )
    return result
