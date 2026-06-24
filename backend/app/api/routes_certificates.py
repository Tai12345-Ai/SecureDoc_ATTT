from fastapi import APIRouter, HTTPException

from app.domain.schemas import CertificateEnrollmentRequest
from app.services.pki_service import init_demo_pki, describe_demo_pki
from app.services.certificate_lifecycle_service import (
    activate_certificate,
    create_demo_backend_enrollment,
    create_enrollment,
    get_certificate_chain,
    get_certificate_status,
    get_enrollment,
    get_my_active_certificate as lifecycle_get_my_active_certificate,
    issue_enrollment,
    revoke_certificate as lifecycle_revoke_certificate,
    sync_demo_certificate_record,
)

router = APIRouter()

@router.post("/init-demo-pki")
def init_pki(force: bool = False):
    pki = init_demo_pki(force=force)
    sync_demo_certificate_record()
    return pki

@router.get("/demo-pki")
def get_demo_pki():
    sync_demo_certificate_record()
    return describe_demo_pki()

@router.post("/enroll")
def enroll(request: CertificateEnrollmentRequest):
    try:
        return create_enrollment(
            display_name=request.display_name,
            email=request.email,
            public_key_pem=request.public_key_pem,
            proof_signature_base64=request.proof_signature_base64,
            proof_challenge=request.proof_challenge,
        )
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc))

@router.post("/enroll-demo-backend-key")
def enroll_demo_backend_key(activate: bool = True):
    try:
        return create_demo_backend_enrollment(activate=activate)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc))

@router.get("/enrollments/{enrollment_id}")
def enrollment_detail(enrollment_id: str):
    try:
        return get_enrollment(enrollment_id)
    except Exception as exc:
        raise HTTPException(status_code=404, detail=str(exc))

@router.post("/enrollments/{enrollment_id}/issue-demo")
def issue_demo_certificate(enrollment_id: str, activate: bool = False):
    try:
        return issue_enrollment(enrollment_id, activate=activate)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc))

@router.get("/my-active")
def get_my_active_certificate():
    try:
        return lifecycle_get_my_active_certificate()
    except Exception as exc:
        raise HTTPException(status_code=404, detail=str(exc))

@router.post("/{serial}/activate")
def activate(serial: str):
    try:
        return activate_certificate(serial)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc))

@router.post("/{serial}/revoke")
def revoke_certificate(serial: str):
    try:
        return lifecycle_revoke_certificate(serial)
    except Exception as exc:
        raise HTTPException(status_code=404, detail=str(exc))

@router.get("/{serial}/status")
def certificate_status(serial: str):
    try:
        return get_certificate_status(serial)
    except Exception as exc:
        raise HTTPException(status_code=404, detail=str(exc))

@router.get("/chain/{serial}")
def certificate_chain(serial: str):
    try:
        return get_certificate_chain(serial)
    except Exception as exc:
        raise HTTPException(status_code=404, detail=str(exc))
