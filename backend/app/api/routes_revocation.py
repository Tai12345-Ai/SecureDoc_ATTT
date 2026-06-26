from fastapi import APIRouter, HTTPException, Request, Response

from cryptography.x509 import ocsp as crypto_ocsp

from app.services.pki_service import get_user_certificate
from app.services.revocation_service import (
    crl,
    generate_signed_crl,
    get_ocsp_response,
    get_ocsp_response_for_serial,
    revoke,
    status,
)

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
    Parses the binary OCSP request to extract the requested certificate serial,
    then generates an OCSP response for that specific certificate.
    """
    try:
        body = await request.body()
        if not body:
            raise ValueError("Empty OCSP request body")

        # Parse the binary OCSP request
        try:
            ocsp_request = crypto_ocsp.load_der_ocsp_request(body)
            requested_serial = ocsp_request.serial_number
        except Exception as parse_exc:
            # If parsing fails, fall back to active user cert for compatibility
            response = get_ocsp_response(get_user_certificate())
            return Response(content=response["ocsp_der"], media_type="application/ocsp-response")

        # Generate OCSP response for the requested certificate
        try:
            response = get_ocsp_response_for_serial(requested_serial)
        except ValueError:
            # Certificate unknown — return HTTP 400 with message
            raise HTTPException(
                status_code=400,
                detail=f"Certificate with serial {requested_serial} is unknown. "
                       f"Cannot generate OCSP response.",
            )

        return Response(content=response["ocsp_der"], media_type="application/ocsp-response")
    except HTTPException:
        raise
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
    try:
        return status(serial)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.post("/revoke/{serial}")
def revoke_serial(serial: str, reason: str = "cessationOfOperation"):
    try:
        return revoke(serial, reason=reason)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc))
