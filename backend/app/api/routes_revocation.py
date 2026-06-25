from fastapi import APIRouter, HTTPException, Request, Response

from app.services.pki_service import get_user_certificate
from app.services.revocation_service import crl, generate_signed_crl, get_ocsp_response, revoke, status

router = APIRouter()


@router.get("/crl")
def get_demo_crl():
    """JSON debug view of the signed CRL (not standards-compliant)."""
    return crl()


@router.get("/crl.der")
def get_signed_crl_der():
    """RFC 5280 DER-encoded signed X.509 CRL."""
    signed = generate_signed_crl()
    return Response(content=signed["crl_der"], media_type="application/pkix-crl")


@router.get("/crl.pem")
def get_signed_crl_pem():
    """PEM-encoded signed X.509 CRL."""
    signed = generate_signed_crl()
    return Response(content=signed["crl_pem"], media_type="application/x-pem-file")


@router.post("/ocsp")
async def binary_ocsp_endpoint(request: Request):
    """
    RFC 6960 binary OCSP endpoint.

    Accepts application/ocsp-request, returns application/ocsp-response.
    For this demo, the request body is accepted but the response is always
    generated for the active user signer certificate.
    """
    try:
        # Accept the binary OCSP request body (we acknowledge it but use the
        # demo user cert since full ASN.1 request parsing is out of scope).
        _ = await request.body()
        response = get_ocsp_response(get_user_certificate())
        return Response(content=response["ocsp_der"], media_type="application/ocsp-response")
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.get("/ocsp-demo")
def get_demo_ocsp_response():
    """
    JSON debug endpoint for OCSP data inspection.

    This is NOT a standards-compliant OCSP endpoint — it returns JSON
    for educational/debugging purposes only.
    """
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
