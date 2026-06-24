def test_demo_pki_and_signing_flow():
    from app.services.pki_service import init_demo_pki
    from app.services.signing_service import prepare_request, confirm_intent, sign_and_verify

    pki = init_demo_pki(force=True)
    cert_serial = pki["user_certificate"]["serial"]
    prepared = prepare_request("test.txt", b"hello", "test signing", cert_serial)
    confirm = confirm_intent(prepared["request_id"])
    assert confirm["confirmed"] is True
    result = sign_and_verify(prepared["request_id"])
    assert result["status"] == "accepted"


def _minimal_pdf_bytes() -> bytes:
    from io import BytesIO
    from pyhanko.pdf_utils import generic
    from pyhanko.pdf_utils.writer import PageObject, PdfFileWriter

    writer = PdfFileWriter()
    contents = writer.add_object(generic.StreamObject(stream_data=b""))
    page = PageObject(
        contents=contents,
        media_box=generic.ArrayObject([
            generic.NumberObject(0),
            generic.NumberObject(0),
            generic.NumberObject(200),
            generic.NumberObject(200),
        ]),
        resources=generic.DictionaryObject(),
    )
    writer.insert_page(page)
    output = BytesIO()
    writer.write(output)
    return output.getvalue()


def test_pades_sign_and_verify_pdf():
    from app.services.pki_service import init_demo_pki
    from app.services.certificate_lifecycle_service import get_my_active_certificate
    from app.services.signing_service import prepare_request, confirm_intent, sign_pdf_request

    init_demo_pki(force=True)
    cert = get_my_active_certificate()
    prepared = prepare_request("test.pdf", _minimal_pdf_bytes(), "test PDF signing", cert["serial"])
    confirm_intent(prepared["request_id"])
    result = sign_pdf_request(prepared["request_id"])
    assert result["verification"]["status"] == "accepted"
    assert result["file_id"]


def test_pades_sign_rejects_non_pdf():
    import pytest
    from app.services.pki_service import init_demo_pki
    from app.services.certificate_lifecycle_service import get_my_active_certificate
    from app.services.signing_service import prepare_request, confirm_intent, sign_pdf_request

    init_demo_pki(force=True)
    cert = get_my_active_certificate()
    prepared = prepare_request("not_pdf.txt", b"hello", "test PDF signing", cert["serial"])
    confirm_intent(prepared["request_id"])
    with pytest.raises(ValueError):
        sign_pdf_request(prepared["request_id"])


def test_pades_sign_requires_confirmed_request():
    import pytest
    from app.services.pki_service import init_demo_pki
    from app.services.certificate_lifecycle_service import get_my_active_certificate
    from app.services.signing_service import prepare_request, sign_pdf_request

    init_demo_pki(force=True)
    cert = get_my_active_certificate()
    prepared = prepare_request("test.pdf", _minimal_pdf_bytes(), "test PDF signing", cert["serial"])
    with pytest.raises(ValueError):
        sign_pdf_request(prepared["request_id"])


def test_certificate_lifecycle_demo_enrollment_and_revocation():
    import pytest
    from app.services.pki_service import init_demo_pki
    from app.services.certificate_lifecycle_service import (
        create_demo_backend_enrollment,
        get_certificate_chain,
        get_certificate_status,
        revoke_certificate,
    )
    from app.services.signing_service import prepare_request

    init_demo_pki(force=True)
    cert_record = create_demo_backend_enrollment(activate=True)
    status = get_certificate_status(cert_record["serial"])
    assert status["lifecycle_status"] == "active"

    chain = get_certificate_chain(cert_record["serial"])
    assert len(chain["chain"]) == 3

    revoke_certificate(cert_record["serial"])
    revoked = get_certificate_status(cert_record["serial"])
    assert revoked["lifecycle_status"] == "revoked"

    with pytest.raises(ValueError):
        prepare_request("test.txt", b"hello", "test signing", cert_record["serial"])
