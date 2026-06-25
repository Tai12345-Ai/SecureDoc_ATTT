from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from app.services.blind_signature_service import run_blind_signature_flow
from app.services.audit_service import append_event

router = APIRouter()

class BlindRequest(BaseModel):
    message: str

@router.post("/run")
def run(req: BlindRequest):
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
