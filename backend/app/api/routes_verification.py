import secrets

from fastapi import APIRouter, File, HTTPException, UploadFile

from app.core.config import settings
from app.services.pades_service import is_pdf_bytes, verify_pdf_signature
from app.services.signing_service import get_signed_pdf_record

router = APIRouter()


@router.post("/verify-pdf")
async def verify_uploaded_pdf(file: UploadFile = File(...)):
    data = await file.read()
    if not data:
        raise HTTPException(status_code=400, detail="Empty file")
    if not is_pdf_bytes(data):
        raise HTTPException(status_code=400, detail="Input file is not a PDF")

    verify_id = "verify_" + secrets.token_hex(12)
    temp_path = settings.signed_documents_dir / f"{verify_id}.pdf"
    temp_path.write_bytes(data)

    try:
        return verify_pdf_signature(temp_path)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.post("/verify-signed-file/{file_id}")
def verify_signed_file(file_id: str):
    record = get_signed_pdf_record(file_id)
    if not record:
        raise HTTPException(status_code=404, detail="Unknown signed file")

    try:
        return verify_pdf_signature(record["signed_path"])
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc))
