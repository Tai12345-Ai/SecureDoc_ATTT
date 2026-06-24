from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from app.services.proof_of_possession_service import (
    create_key_enrollment_challenge,
    submit_public_key_proof,
)

router = APIRouter()


class KeyEnrollmentChallengeRequest(BaseModel):
    display_name: str
    email: str
    public_key_pem: str


class KeyEnrollmentSubmitRequest(BaseModel):
    challenge_id: str
    proof_signature_base64: str
    issue_certificate: bool = True
    activate_certificate: bool = False


@router.post("/challenge")
def challenge(request: KeyEnrollmentChallengeRequest):
    try:
        return create_key_enrollment_challenge(
            display_name=request.display_name,
            email=request.email,
            public_key_pem=request.public_key_pem,
        )
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.post("/submit-public-key")
def submit_public_key(request: KeyEnrollmentSubmitRequest):
    try:
        return submit_public_key_proof(
            challenge_id=request.challenge_id,
            proof_signature_base64=request.proof_signature_base64,
            issue_certificate=request.issue_certificate,
            activate_certificate=request.activate_certificate,
        )
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc))
