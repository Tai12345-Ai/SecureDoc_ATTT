from fastapi import APIRouter
from pydantic import BaseModel
from app.services.blind_signature_service import run_blind_signature_flow
from app.services.audit_service import append_event

router = APIRouter()

class BlindRequest(BaseModel):
    message: str

@router.post("/run")
def run(req: BlindRequest):
    result = run_blind_signature_flow(req.message)
    append_event("alice@example.com", "blind_signature_demo", "blind-token", "ok", {"verified": result["verified"]})
    return result
