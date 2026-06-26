from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from app.services.remote_signing_service import remote_sign_request, remote_sign_pdf_request

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


@router.post("/sign-pdf")
def sign_pdf(request: RemoteSigningRequest):
    """Remote sign a PDF document with PAdES-B-LT.

    Requires confirmed signing intent, valid demo MFA code, active certificate,
    and a PDF document in the signing request.
    """
    try:
        return remote_sign_pdf_request(request.request_id, request.mfa_code)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc))
