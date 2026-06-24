from pathlib import Path

from fastapi import APIRouter, UploadFile, File, Form, HTTPException
from fastapi.responses import FileResponse
from app.services.pki_service import get_user_certificate, certificate_view_dict, init_demo_pki
from app.services.signing_service import (
    prepare_request,
    confirm_intent,
    sign_and_verify,
    sign_pdf_request,
    get_signed_pdf_record,
    get_signing_history,
)
from app.services.certificate_lifecycle_service import get_my_active_certificate, sync_demo_certificate_record

router = APIRouter()

@router.get("/workspace")
def get_workspace():
    init_demo_pki()
    sync_demo_certificate_record()
    try:
        active_certificate = get_my_active_certificate()
    except Exception:
        active_certificate = None
    return {
        "user": {
            "name": "Alice Demo Signer",
            "email": "alice@example.com",
        },
        "certificate": active_certificate,
        "availableActions": [
            "upload_document",
            "prepare_signing_request",
            "confirm_signing_intent",
            "sign_and_verify",
            "sign_pdf",
            "download_signed_pdf",
        ],
    }

@router.post("/prepare")
async def prepare(
    file: UploadFile = File(...),
    signing_purpose: str = Form(...),
    certificate_serial: str = Form(...),
):
    data = await file.read()
    if not data:
        raise HTTPException(status_code=400, detail="Empty file")
    try:
        return prepare_request(
            document_name=file.filename or "document.bin",
            document_bytes=data,
            signing_purpose=signing_purpose,
            certificate_serial=certificate_serial,
        )
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc))

@router.post("/confirm")
def confirm(request_id: str):
    try:
        return confirm_intent(request_id)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc))

@router.post("/sign-and-verify")
def sign_verify(request_id: str):
    try:
        return sign_and_verify(request_id)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc))

@router.post("/sign-pdf")
def sign_pdf(request_id: str):
    try:
        return sign_pdf_request(request_id)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc))

@router.get("/signed-files/{file_id}")
def download_signed_pdf(file_id: str):
    record = get_signed_pdf_record(file_id)
    if not record:
        raise HTTPException(status_code=404, detail="Unknown signed file")
    signed_path = Path(record["signed_path"])
    if not signed_path.exists():
        raise HTTPException(status_code=404, detail="Signed file no longer exists")
    return FileResponse(
        path=signed_path,
        media_type="application/pdf",
        filename=f"signed_{record['original_filename'] if record['original_filename'].lower().endswith('.pdf') else record['original_filename'] + '.pdf'}",
    )

@router.get("/history")
def signing_history():
    return {"items": get_signing_history()}
