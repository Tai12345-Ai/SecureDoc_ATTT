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
    assert result["metadata"]["target_profile"] == "PAdES-B-LT"
    assert result["metadata"]["achieved_profile"] == "PAdES-B-LT"
    assert result["metadata"]["timestamp_status"]["state"] == "valid"
    assert result["metadata"]["revocation_evidence_status"]["state"] == "embedded"
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
    page_marker = data.find(b"/MediaBox")
    index = data.find(b"200", page_marker)
    assert index != -1
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


def test_signed_timestamp_token_verifies_and_tamper_fails():
    from app.services.timestamp_service import issue_demo_timestamp, verify_demo_timestamp

    imprint = "a" * 64
    token = issue_demo_timestamp(imprint)
    assert token["tokenType"] == "SECUREDOC_DEMO_TSA_TOKEN_V1"
    verified = verify_demo_timestamp(token, imprint)
    assert verified["ok"] is True
    assert verified["trusted"] is True

    token["messageImprintSha256"] = "b" * 64
    tampered = verify_demo_timestamp(token, imprint)
    assert tampered["ok"] is False


def test_revocation_after_signing_is_accepted_with_trusted_timestamp():
    from app.services.pki_service import init_demo_pki
    from app.services.signing_service import prepare_request, confirm_intent, sign_and_verify, verify_signed_package
    from app.services.revocation_service import revoke

    pki = init_demo_pki(force=True)
    cert_serial = pki["user_certificate"]["serial"]
    prepared = prepare_request("test.txt", b"hello", "test signing", cert_serial)
    confirm_intent(prepared["request_id"])
    initial = sign_and_verify(prepared["request_id"])
    assert initial["status"] == "accepted"

    revoke(cert_serial)
    verified_again = verify_signed_package(prepared["request_id"])
    assert verified_again["status"] == "accepted"
    assert verified_again["advanced"]["revocation_validation"]["checked_at_policy"] == "signing_time"


def test_revocation_before_signing_rejects_new_request():
    import pytest
    from app.services.pki_service import init_demo_pki
    from app.services.revocation_service import revoke
    from app.services.signing_service import prepare_request

    pki = init_demo_pki(force=True)
    cert_serial = pki["user_certificate"]["serial"]
    revoke(cert_serial)
    with pytest.raises(ValueError):
        prepare_request("test.txt", b"hello", "test signing", cert_serial)


def test_key_enrollment_challenge_and_submit_public_key():
    import base64
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding
    from app.services.pki_service import init_demo_pki, get_demo_user_public_key_pem, get_user_private_key
    from app.services.proof_of_possession_service import create_key_enrollment_challenge, submit_public_key_proof

    init_demo_pki(force=True)
    challenge = create_key_enrollment_challenge(
        display_name="Alice Demo Signer",
        email="alice@example.com",
        public_key_pem=get_demo_user_public_key_pem(),
    )
    signature = get_user_private_key().sign(
        challenge["challenge"].encode("utf-8"),
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256(),
    )
    result = submit_public_key_proof(
        challenge_id=challenge["challenge_id"],
        proof_signature_base64=base64.b64encode(signature).decode("ascii"),
        issue_certificate=False,
    )
    assert result["enrollment"]["proof_verified"] is True


def test_key_enrollment_rejects_wrong_proof():
    import base64
    import pytest
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding
    from app.services.pki_service import init_demo_pki, get_demo_user_public_key_pem, get_user_private_key
    from app.services.proof_of_possession_service import create_key_enrollment_challenge, submit_public_key_proof

    init_demo_pki(force=True)
    challenge = create_key_enrollment_challenge(
        display_name="Alice Demo Signer",
        email="alice@example.com",
        public_key_pem=get_demo_user_public_key_pem(),
    )
    wrong_signature = get_user_private_key().sign(
        b"wrong challenge",
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256(),
    )

    with pytest.raises(ValueError):
        submit_public_key_proof(
            challenge_id=challenge["challenge_id"],
            proof_signature_base64=base64.b64encode(wrong_signature).decode("ascii"),
            issue_certificate=False,
        )


def test_client_signature_submit_verifies_payload():
    import base64
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding
    from app.services.crypto_utils import canonical_json_bytes
    from app.services.pki_service import init_demo_pki, get_user_private_key
    from app.services.signing_service import prepare_request, confirm_intent, submit_client_signature

    pki = init_demo_pki(force=True)
    prepared = prepare_request("test.txt", b"hello", "browser signing", pki["user_certificate"]["serial"])
    confirm_intent(prepared["request_id"])
    signature = get_user_private_key().sign(
        canonical_json_bytes(prepared["advanced"]["canonical_payload"]),
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256(),
    )

    result = submit_client_signature(prepared["request_id"], base64.b64encode(signature).decode("ascii"))
    assert result["status"] == "accepted"
    assert result["advanced"]["signed_package"]["keyCustody"] == "BROWSER_LOCAL_SIGNING"


def test_external_browser_key_enrollment_can_client_sign_payload():
    import base64
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding, rsa
    from app.services.crypto_utils import canonical_json_bytes
    from app.services.pki_service import init_demo_pki
    from app.services.proof_of_possession_service import create_key_enrollment_challenge, submit_public_key_proof
    from app.services.signing_service import prepare_request, confirm_intent, submit_client_signature

    init_demo_pki(force=True)
    browser_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    public_key_pem = browser_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")
    challenge = create_key_enrollment_challenge(
        display_name="Alice Browser Key",
        email="alice@example.com",
        public_key_pem=public_key_pem,
    )
    proof_signature = browser_key.sign(
        challenge["challenge"].encode("utf-8"),
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256(),
    )
    enrollment = submit_public_key_proof(
        challenge_id=challenge["challenge_id"],
        proof_signature_base64=base64.b64encode(proof_signature).decode("ascii"),
        issue_certificate=True,
        activate_certificate=True,
    )
    serial = enrollment["certificate"]["serial"]
    prepared = prepare_request("test.txt", b"hello browser key", "browser local signing", serial)
    confirm_intent(prepared["request_id"])
    payload_signature = browser_key.sign(
        canonical_json_bytes(prepared["advanced"]["canonical_payload"]),
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256(),
    )

    result = submit_client_signature(prepared["request_id"], base64.b64encode(payload_signature).decode("ascii"))
    assert result["status"] == "accepted"
    assert any(check["key"] == "signerCertificateMatchesRequest" and check["ok"] for check in result["checks"])


def test_remote_signing_requires_confirmed_intent_and_mfa():
    import pytest
    from app.services.pki_service import init_demo_pki
    from app.services.signing_service import prepare_request, confirm_intent
    from app.services.remote_signing_service import remote_sign_request

    pki = init_demo_pki(force=True)
    prepared = prepare_request("test.txt", b"hello", "remote signing", pki["user_certificate"]["serial"])
    with pytest.raises(ValueError):
        remote_sign_request(prepared["request_id"], "000000")

    confirm_intent(prepared["request_id"])
    with pytest.raises(ValueError):
        remote_sign_request(prepared["request_id"], "111111")

    result = remote_sign_request(prepared["request_id"], "000000")
    assert result["report"]["status"] == "accepted"
    assert result["remote_signing"]["privateKeyExposed"] is False


def test_blind_signature_flow_uses_separate_scheme_and_spent_registry():
    import uuid
    from app.services.blind_signature_service import run_blind_signature_flow

    message = f"privacy-token-{uuid.uuid4()}"
    first = run_blind_signature_flow(message)
    assert first["target_scheme"] == "RFC9474-RSABSSA"
    assert first["achieved_scheme"] == "RSABSSA-SHA384-PSS-Randomized"
    assert first["scheme_complete"] is True
    assert first["production_ready"] is False
    assert first["blind_signature_valid"] is True
    assert first["spent_status"] == "spent"
    assert first["redeemed"] is True
    assert first["advanced"]["key"]["purpose"] == "blind-signature-only"
    assert first["advanced"]["variant"] == "RSABSSA-SHA384-PSS-Randomized"
    assert first["advanced"]["hash"] == "SHA-384"

    second = run_blind_signature_flow(message)
    assert second["blind_signature_valid"] is True
    assert second["scheme_complete"] is True
    assert second["spent_status"] == "already_spent"
    assert second["redeemed"] is False
