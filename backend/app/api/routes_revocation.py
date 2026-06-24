from fastapi import APIRouter, HTTPException

from app.services.revocation_service import crl, revoke, status

router = APIRouter()


@router.get("/crl")
def get_demo_crl():
    return crl()


@router.get("/status/{serial}")
def revocation_status(serial: str):
    return status(serial)


@router.post("/revoke/{serial}")
def revoke_serial(serial: str, reason: str = "cessationOfOperation"):
    try:
        return revoke(serial, reason=reason)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc))
