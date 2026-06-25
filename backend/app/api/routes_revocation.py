from fastapi import APIRouter, HTTPException, Response

from app.services.pki_service import get_user_certificate
from app.services.revocation_service import crl, generate_signed_crl, get_ocsp_response, revoke, status

router = APIRouter()


@router.get("/crl")
def get_demo_crl():
    return crl()


@router.get("/crl.pem")
def get_signed_crl_pem():
    signed = generate_signed_crl()
    return Response(content=signed["crl_pem"], media_type="application/pkix-crl")


@router.get("/ocsp")
def get_demo_ocsp_response():
    try:
        response = get_ocsp_response(get_user_certificate())
        return {key: value for key, value in response.items() if key != "ocsp_der"}
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.get("/status/{serial}")
def revocation_status(serial: str):
    return status(serial)


@router.post("/revoke/{serial}")
def revoke_serial(serial: str, reason: str = "cessationOfOperation"):
    try:
        return revoke(serial, reason=reason)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc))
