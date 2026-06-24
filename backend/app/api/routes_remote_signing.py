from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from app.services.remote_signing_service import remote_sign_request

router = APIRouter()


class RemoteSigningRequest(BaseModel):
    request_id: str
    mfa_code: str


@router.post("/sign")
def sign(request: RemoteSigningRequest):
    try:
        return remote_sign_request(request.request_id, request.mfa_code)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc))
