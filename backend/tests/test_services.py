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


def test_pades_verify_rejects_tampered_pdf():
    from pathlib import Path
    from app.services.pki_service import init_demo_pki
    from app.services.certificate_lifecycle_service import get_my_active_certificate
    from app.services.signing_service import prepare_request, confirm_intent, sign_pdf_request
    from app.services.pades_service import verify_pdf_signature

    init_demo_pki(force=True)
    cert = get_my_active_certificate()
    prepared = prepare_request("test.pdf", _minimal_pdf_bytes(), "test PDF signing", cert["serial"])
    confirm_intent(prepared["request_id"])
    result = sign_pdf_request(prepared["request_id"])

    signed_path = Path(result["metadata"]["signed_path"])
    tampered_path = signed_path.with_name(f"{signed_path.stem}_tampered.pdf")
    data = bytearray(signed_path.read_bytes())
    index = max(0, len(data) - 200)
    data[index] = (data[index] + 1) % 255
    tampered_path.write_bytes(data)

    report = verify_pdf_signature(tampered_path)
    assert report["status"] != "accepted"
    assert report["accepted"] is False


def test_pades_verify_rejects_unsigned_pdf():
    from pathlib import Path
    from app.services.pades_service import verify_pdf_signature

    unsigned_path = Path("data/documents/unsigned_test.pdf")
    unsigned_path.parent.mkdir(parents=True, exist_ok=True)
    unsigned_path.write_bytes(_minimal_pdf_bytes())
    report = verify_pdf_signature(unsigned_path)
    assert report["status"] != "accepted"
    assert report["accepted"] is False


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


def test_certificate_lifecycle_demo_enrollment_profile_and_revocation():
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
    assert status["effective_status"] == "active"
    assert status["certificate_origin"] == "lifecycle_issued"
    assert status["profile_validation"]["valid"] is True
    profile_keys = {check["key"] for check in status["profile_validation"]["checks"]}
    assert "basic_constraints_end_entity" in profile_keys
    assert "key_usage_document_signing" in profile_keys
    assert "subject_key_identifier_present" in profile_keys
    assert "authority_key_identifier_present" in profile_keys

    chain = get_certificate_chain(cert_record["serial"])
    assert len(chain["chain"]) == 3

    revoke_certificate(cert_record["serial"])
    revoked = get_certificate_status(cert_record["serial"])
    assert revoked["lifecycle_status"] == "revoked"
    assert revoked["revocation_status"] == "revoked"
    assert revoked["effective_status"] == "revoked"

    with pytest.raises(ValueError):
        prepare_request("test.pdf", _minimal_pdf_bytes(), "test signing", cert_record["serial"])


def test_certificate_lifecycle_rejects_invalid_proof_of_possession():
    import base64
    import pytest
    from app.services.pki_service import init_demo_pki, get_demo_user_public_key_pem
    from app.services.certificate_lifecycle_service import create_enrollment

    init_demo_pki(force=True)
    with pytest.raises(ValueError):
        create_enrollment(
            display_name="Alice Demo Signer",
            email="alice@example.com",
            public_key_pem=get_demo_user_public_key_pem(),
            proof_signature_base64=base64.b64encode(b"not a valid signature").decode("ascii"),
        )


def test_ca_certificate_profiles_have_required_extensions():
    from app.services.pki_service import (
        get_intermediate_certificate,
        get_root_certificate,
        init_demo_pki,
        validate_ca_certificate_profile,
    )

    init_demo_pki(force=True)
    root_profile = validate_ca_certificate_profile(get_root_certificate(), expected_root=True)
    intermediate_profile = validate_ca_certificate_profile(get_intermediate_certificate())
    assert root_profile["valid"] is True
    assert intermediate_profile["valid"] is True
