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
    assert result["metadata"]["achieved_profile"] in ("PAdES-B-LT", "PAdES-B-T", "PAdES-B-B")
    assert result["file_id"]


def test_pades_achieved_profile_is_honest():
    """achieved_profile must be PAdES-B-LT only when full evidence is present."""
    from app.services.pki_service import init_demo_pki
    from app.services.certificate_lifecycle_service import get_my_active_certificate
    from app.services.signing_service import prepare_request, confirm_intent, sign_pdf_request

    init_demo_pki(force=True)
    cert = get_my_active_certificate()
    prepared = prepare_request("test.pdf", _minimal_pdf_bytes(), "test PDF signing", cert["serial"])
    confirm_intent(prepared["request_id"])
    result = sign_pdf_request(prepared["request_id"])
    meta = result["metadata"]
    achieved = meta["achieved_profile"]
    missing = meta.get("missing_requirements", [])
    if achieved == "PAdES-B-LT":
        assert len(missing) == 0, f"B-LT claimed but missing: {missing}"
    else:
        assert len(missing) > 0, f"Not B-LT but missing_requirements is empty"


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


def test_validate_pades_blt_requirements():
    """validate_pades_blt_requirements returns structured report."""
    from pathlib import Path
    from app.services.pki_service import init_demo_pki
    from app.services.certificate_lifecycle_service import get_my_active_certificate
    from app.services.signing_service import prepare_request, confirm_intent, sign_pdf_request
    from app.services.pades_service import validate_pades_blt_requirements

    init_demo_pki(force=True)
    cert = get_my_active_certificate()
    prepared = prepare_request("test.pdf", _minimal_pdf_bytes(), "test PDF signing", cert["serial"])
    confirm_intent(prepared["request_id"])
    result = sign_pdf_request(prepared["request_id"])

    report = validate_pades_blt_requirements(result["metadata"]["signed_path"])
    assert "has_embedded_signature" in report
    assert "has_signature_timestamp" in report
    assert "has_dss" in report
    assert "target_profile" in report
    assert report["target_profile"] == "PAdES-B-LT"
    assert "achieved_profile" in report
    assert "missing_requirements" in report
    assert isinstance(report["missing_requirements"], list)


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


def _issue_client_side_certificate_with_key(activate: bool = True):
    import base64
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding, rsa
    from app.services.pki_service import init_demo_pki
    from app.services.proof_of_possession_service import create_key_enrollment_challenge, submit_public_key_proof

    init_demo_pki(force=True)
    client_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    public_key_pem = client_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")
    challenge = create_key_enrollment_challenge(
        display_name="Alice Browser Key",
        email="alice@example.com",
        public_key_pem=public_key_pem,
    )
    proof_signature = client_key.sign(
        challenge["challenge"].encode("utf-8"),
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256(),
    )
    enrollment = submit_public_key_proof(
        challenge_id=challenge["challenge_id"],
        proof_signature_base64=base64.b64encode(proof_signature).decode("ascii"),
        issue_certificate=True,
        activate_certificate=activate,
    )
    return client_key, enrollment["certificate"], enrollment


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
    assert result["advanced"]["signed_package"]["keyCustody"] == "DEMO_BACKEND_KEY"
    assert result["advanced"]["signed_package"]["signatureOrigin"] == "browser_or_external_client"


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
    assert result["keyCustody"] == "CLIENT_SIDE_KEY"
    assert result["backendHasPrivateKey"] is False
    assert result["signatureOrigin"] == "browser_or_external_client"


def test_demo_backend_certificate_record_has_key_custody_metadata():
    from app.services.pki_service import init_demo_pki
    from app.services.certificate_lifecycle_service import get_certificate_status, get_my_active_certificate

    pki = init_demo_pki(force=True)
    status = get_certificate_status(pki["user_certificate"]["serial"])
    assert status["key_source"] == "DEMO_BACKEND_KEY"
    assert status["private_key_custody"] == "BACKEND_DEMO_STORAGE"
    assert status["backend_has_private_key"] is True

    active = get_my_active_certificate()
    assert active["key_source"] == "DEMO_BACKEND_KEY"
    assert active["backend_has_private_key"] is True


def test_client_side_certificate_record_has_no_backend_private_key():
    from app.services.certificate_lifecycle_service import get_certificate_status

    _client_key, cert_record, enrollment = _issue_client_side_certificate_with_key(activate=True)
    assert enrollment["enrollment"]["key_source"] == "CLIENT_SIDE_KEY"
    assert enrollment["enrollment"]["backend_has_private_key"] is False
    assert cert_record["key_source"] == "CLIENT_SIDE_KEY"
    assert cert_record["private_key_custody"] == "USER_BROWSER_OR_DEVICE"
    assert cert_record["backend_has_private_key"] is False

    status = get_certificate_status(cert_record["serial"])
    assert status["key_source"] == "CLIENT_SIDE_KEY"
    assert status["backend_has_private_key"] is False


def test_sign_pdf_rejects_client_side_key_certificate():
    import pytest
    from app.services.signing_service import prepare_request, confirm_intent, sign_pdf_request

    _client_key, cert_record, _enrollment = _issue_client_side_certificate_with_key(activate=True)
    prepared = prepare_request("client.pdf", _minimal_pdf_bytes(), "client-side PDF signing", cert_record["serial"])
    confirm_intent(prepared["request_id"])

    with pytest.raises(ValueError, match="client-side private key custody"):
        sign_pdf_request(prepared["request_id"])


def test_submit_client_signature_reports_client_side_custody():
    import base64
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding
    from app.services.crypto_utils import canonical_json_bytes
    from app.services.signing_service import prepare_request, confirm_intent, submit_client_signature

    client_key, cert_record, _enrollment = _issue_client_side_certificate_with_key(activate=True)
    prepared = prepare_request("test.txt", b"hello browser key", "browser local signing", cert_record["serial"])
    confirm_intent(prepared["request_id"])
    payload_signature = client_key.sign(
        canonical_json_bytes(prepared["advanced"]["canonical_payload"]),
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256(),
    )

    result = submit_client_signature(prepared["request_id"], base64.b64encode(payload_signature).decode("ascii"))
    assert result["status"] == "accepted"
    assert result["keyCustody"] == "CLIENT_SIDE_KEY"
    assert result["privateKeyCustody"] == "USER_BROWSER_OR_DEVICE"
    assert result["backendHasPrivateKey"] is False
    assert result["signatureOrigin"] == "browser_or_external_client"
    assert result["advanced"]["signed_package"]["keyCustody"] == "CLIENT_SIDE_KEY"


def test_workspace_response_returns_key_custody_metadata():
    from app.api.routes_user_signing import get_workspace

    _client_key, cert_record, _enrollment = _issue_client_side_certificate_with_key(activate=True)
    workspace = get_workspace()
    cert = workspace["certificate"]
    assert cert["serial"] == cert_record["serial"]
    assert cert["key_source"] == "CLIENT_SIDE_KEY"
    assert cert["private_key_custody"] == "USER_BROWSER_OR_DEVICE"
    assert cert["backend_has_private_key"] is False


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
    assert "RSABSSA-SHA384-PSS-Randomized" in first["achieved_scheme"]
    assert first["scheme_complete"] is True
    assert first["production_ready"] is False
    assert first["rfc9474_test_vectors_passed"] is False
    assert first["compliance_status"] == "not_test_vector_verified"
    assert first["blind_signature_valid"] is True
    assert first["spent_status"] == "spent"
    assert first["redeemed"] is True
    assert first["token_hash_algorithm"] == "SHA-256"
    assert first["advanced"]["key"]["purpose"] == "blind-signature-only"
    assert "RSABSSA-SHA384-PSS-Randomized" in first["advanced"]["variant"]
    assert first["advanced"]["hash"] == "SHA-384"

    second = run_blind_signature_flow(message)
    assert second["blind_signature_valid"] is True
    assert second["scheme_complete"] is True
    assert second["spent_status"] == "already_spent"
    assert second["redeemed"] is False


# ── Digest policy tests ──────────────────────────────────────────────────────

def test_digest_hex_uses_selected_algorithm():
    from app.services.crypto_utils import digest_hex

    data = b"test data for hashing"
    sha256 = digest_hex(data, "sha256")
    sha384 = digest_hex(data, "sha384")
    sha512 = digest_hex(data, "sha512")

    assert len(sha256) == 64
    assert len(sha384) == 96
    assert len(sha512) == 128
    assert sha256 != sha384 != sha512


def test_digest_hex_default_matches_policy():
    from app.services.crypto_utils import digest_hex
    from app.services.algorithm_policy import ALGORITHM_POLICY

    data = b"consistency test"
    default = digest_hex(data)
    explicit = digest_hex(data, ALGORITHM_POLICY.default_digest)
    assert default == explicit


def test_digest_policy_rejects_md5_and_sha1():
    import pytest
    from app.services.crypto_utils import digest_hex

    with pytest.raises(ValueError):
        digest_hex(b"test", "md5")
    with pytest.raises(ValueError):
        digest_hex(b"test", "sha1")


def test_prepare_and_verify_hash_consistent():
    """prepare_request and verify_signed_package use the same digest algorithm."""
    from app.services.pki_service import init_demo_pki
    from app.services.signing_service import prepare_request, confirm_intent, sign_and_verify

    pki = init_demo_pki(force=True)
    cert_serial = pki["user_certificate"]["serial"]
    prepared = prepare_request("test.txt", b"consistency check", "test", cert_serial)
    confirm_intent(prepared["request_id"])
    result = sign_and_verify(prepared["request_id"])
    assert result["status"] == "accepted"
    # The documentHashValid check proves prepare and verify use the same hash
    hash_check = next(c for c in result["checks"] if c["key"] == "documentHashValid")
    assert hash_check["ok"] is True


# ── CRL / OCSP endpoint tests ───────────────────────────────────────────────

def test_signed_crl_der_returns_bytes():
    from app.services.pki_service import init_demo_pki
    from app.services.revocation_service import generate_signed_crl

    init_demo_pki(force=True)
    crl_data = generate_signed_crl()
    assert isinstance(crl_data["crl_der"], bytes)
    assert len(crl_data["crl_der"]) > 0
    assert crl_data["crl_type"] == "SIGNED_X509_CRL"
    assert crl_data["standard"] == "RFC5280"


def test_signed_crl_pem_is_pem():
    from app.services.pki_service import init_demo_pki
    from app.services.revocation_service import generate_signed_crl

    init_demo_pki(force=True)
    crl_data = generate_signed_crl()
    assert isinstance(crl_data["crl_pem"], str)
    assert crl_data["crl_pem"].startswith("-----BEGIN X509 CRL-----")


# ── Blind signature protocol tests ──────────────────────────────────────────

def test_blind_signer_info_returns_key_data():
    from app.services.blind_signature_service import blind_signer_info

    info = blind_signer_info()
    assert info["status"] == "active"
    assert info["purpose"] == "blind-signature-only"
    assert "key_id" in info
    assert "public_key_der_hex" in info
    assert "scheme" in info
    assert info["compliance_status"] == "not_test_vector_verified"
    assert info["rfc9474_test_vectors_passed"] is False


def test_blind_sign_message_rejects_wrong_key_id():
    import pytest
    from app.services.blind_signature_service import blind_sign_message

    with pytest.raises(ValueError, match="Unknown key_id"):
        blind_sign_message("aabb", "wrong-key-id")


def test_redeem_duplicate_rejected():
    import uuid
    from app.services.blind_signature_service import (
        prepare_token, blind_token, blind_sign, unblind_signature,
        verify_blind_signature, redeem_with_verification,
    )

    message = f"redeem-test-{uuid.uuid4()}"
    rec = prepare_token(message)
    blind_token(rec)
    blind_sign(rec)
    unblind_signature(rec)
    verify_blind_signature(rec)

    first = redeem_with_verification(
        token_hash=rec["token_hash"],
        signature_hex=rec["signature"].hex(),
        msg_prefix_hex=rec["msg_prefix"].hex(),
        token=rec["token"],
    )
    assert first["accepted"] is True
    assert first["reason"] == "redeemed"
    assert first["token_hash_algorithm"] == "SHA-256"

    second = redeem_with_verification(
        token_hash=rec["token_hash"],
        signature_hex=rec["signature"].hex(),
        msg_prefix_hex=rec["msg_prefix"].hex(),
        token=rec["token"],
    )
    assert second["accepted"] is False
    assert second["reason"] == "already_spent"


def test_redeem_wrong_signature_rejected():
    import uuid
    from app.services.blind_signature_service import (
        prepare_token, blind_token, blind_sign, unblind_signature,
        redeem_with_verification,
    )

    message = f"wrong-sig-{uuid.uuid4()}"
    rec = prepare_token(message)
    blind_token(rec)
    blind_sign(rec)
    unblind_signature(rec)

    result = redeem_with_verification(
        token_hash=rec["token_hash"],
        signature_hex="00" * 384,  # wrong signature
        msg_prefix_hex=rec["msg_prefix"].hex(),
        token=rec["token"],
    )
    assert result["accepted"] is False
    assert result["reason"] == "invalid_signature"


# ── V5 Standardization Tests ────────────────────────────────────────────────

# ── Digest policy: SHA-3 experimental ────────────────────────────────────────

def test_sha3_256_digest_hex():
    from app.services.crypto_utils import digest_hex

    data = b"sha3 test data"
    result = digest_hex(data, "sha3_256")
    assert len(result) == 64  # SHA3-256 produces 32 bytes = 64 hex chars


def test_sha3_384_digest_hex():
    from app.services.crypto_utils import digest_hex

    data = b"sha3 test data"
    result = digest_hex(data, "sha3_384")
    assert len(result) == 96  # SHA3-384 produces 48 bytes = 96 hex chars


def test_sha3_512_digest_hex():
    from app.services.crypto_utils import digest_hex

    data = b"sha3 test data"
    result = digest_hex(data, "sha3_512")
    assert len(result) == 128  # SHA3-512 produces 64 bytes = 128 hex chars


def test_sha3_digests_differ_from_sha2():
    from app.services.crypto_utils import digest_hex

    data = b"comparison data"
    sha256 = digest_hex(data, "sha256")
    sha3_256 = digest_hex(data, "sha3_256")
    assert sha256 != sha3_256


def test_algorithm_policy_is_pades_compatible():
    from app.services.algorithm_policy import ALGORITHM_POLICY

    assert ALGORITHM_POLICY.is_pades_compatible("sha256") is True
    assert ALGORITHM_POLICY.is_pades_compatible("sha384") is True
    assert ALGORITHM_POLICY.is_pades_compatible("sha512") is True
    assert ALGORITHM_POLICY.is_pades_compatible("sha3_256") is False
    assert ALGORITHM_POLICY.is_pades_compatible("sha3_384") is False
    assert ALGORITHM_POLICY.is_pades_compatible("sha3_512") is False


def test_algorithm_policy_is_experimental():
    from app.services.algorithm_policy import ALGORITHM_POLICY

    assert ALGORITHM_POLICY.is_experimental("sha3_256") is True
    assert ALGORITHM_POLICY.is_experimental("sha3_384") is True
    assert ALGORITHM_POLICY.is_experimental("sha3_512") is True
    assert ALGORITHM_POLICY.is_experimental("sha256") is False


def test_algorithm_policy_digest_capabilities():
    from app.services.algorithm_policy import ALGORITHM_POLICY

    caps = ALGORITHM_POLICY.digest_capabilities()
    assert caps["default"] == "sha256"
    assert "sha3_256" in caps["experimental"]
    assert "sha256" in caps["pades_compatible"]
    assert "note" in caps


def test_algorithm_policy_normalize_flexible_input():
    from app.services.algorithm_policy import ALGORITHM_POLICY

    assert ALGORITHM_POLICY.normalize_digest("SHA-256") == "sha256"
    assert ALGORITHM_POLICY.normalize_digest("sha-384") == "sha384"
    assert ALGORITHM_POLICY.normalize_digest("SHA3-256") == "sha3_256"
    assert ALGORITHM_POLICY.normalize_digest("sha-3-256") == "sha3_256"
    assert ALGORITHM_POLICY.normalize_digest("SHA3_512") == "sha3_512"


def test_algorithm_policy_cryptography_hash_sha3():
    from cryptography.hazmat.primitives import hashes
    from app.services.algorithm_policy import ALGORITHM_POLICY

    h = ALGORITHM_POLICY.cryptography_hash("sha3_256")
    assert isinstance(h, hashes.SHA3_256)
    h = ALGORITHM_POLICY.cryptography_hash("sha3_384")
    assert isinstance(h, hashes.SHA3_384)
    h = ALGORITHM_POLICY.cryptography_hash("sha3_512")
    assert isinstance(h, hashes.SHA3_512)


# ── Digest selection per signing request ─────────────────────────────────────

def test_prepare_request_with_sha384():
    from app.services.pki_service import init_demo_pki
    from app.services.signing_service import prepare_request

    pki = init_demo_pki(force=True)
    cert_serial = pki["user_certificate"]["serial"]
    prepared = prepare_request("test.txt", b"hello", "test", cert_serial, digest_algorithm="sha384")
    assert prepared["hash_algorithm"] == "SHA-384"
    assert len(prepared["document_hash"]) == 96  # SHA-384 hex


def test_prepare_request_with_sha512():
    from app.services.pki_service import init_demo_pki
    from app.services.signing_service import prepare_request

    pki = init_demo_pki(force=True)
    cert_serial = pki["user_certificate"]["serial"]
    prepared = prepare_request("test.txt", b"hello", "test", cert_serial, digest_algorithm="sha512")
    assert prepared["hash_algorithm"] == "SHA-512"
    assert len(prepared["document_hash"]) == 128  # SHA-512 hex


def test_prepare_request_with_sha3_256():
    from app.services.pki_service import init_demo_pki
    from app.services.signing_service import prepare_request

    pki = init_demo_pki(force=True)
    cert_serial = pki["user_certificate"]["serial"]
    prepared = prepare_request("test.txt", b"hello", "test", cert_serial, digest_algorithm="sha3_256")
    assert prepared["hash_algorithm"] == "SHA3-256"
    assert prepared["advanced"]["digest_policy"]["is_experimental"] is True
    assert prepared["advanced"]["digest_policy"]["is_pades_compatible"] is False


def test_sign_and_verify_with_sha384():
    from app.services.pki_service import init_demo_pki
    from app.services.signing_service import prepare_request, confirm_intent, sign_and_verify

    pki = init_demo_pki(force=True)
    cert_serial = pki["user_certificate"]["serial"]
    prepared = prepare_request("test.txt", b"hello", "test", cert_serial, digest_algorithm="sha384")
    confirm_intent(prepared["request_id"])
    result = sign_and_verify(prepared["request_id"])
    assert result["status"] == "accepted"


def test_sign_and_verify_with_sha3_256():
    """SHA-3 works for canonical payload signing demo."""
    from app.services.pki_service import init_demo_pki
    from app.services.signing_service import prepare_request, confirm_intent, sign_and_verify

    pki = init_demo_pki(force=True)
    cert_serial = pki["user_certificate"]["serial"]
    prepared = prepare_request("test.txt", b"hello", "test", cert_serial, digest_algorithm="sha3_256")
    confirm_intent(prepared["request_id"])
    result = sign_and_verify(prepared["request_id"])
    assert result["status"] == "accepted"


def test_sign_pdf_rejects_sha3():
    """PAdES signing must reject SHA-3 experimental digests."""
    import pytest
    from app.services.pki_service import init_demo_pki
    from app.services.certificate_lifecycle_service import get_my_active_certificate
    from app.services.signing_service import prepare_request, confirm_intent, sign_pdf_request

    init_demo_pki(force=True)
    cert = get_my_active_certificate()
    prepared = prepare_request("test.pdf", _minimal_pdf_bytes(), "test", cert["serial"], digest_algorithm="sha3_256")
    confirm_intent(prepared["request_id"])
    with pytest.raises(ValueError, match="experimental"):
        sign_pdf_request(prepared["request_id"])


def test_sign_pdf_with_sha384():
    """PAdES signing works with SHA-384."""
    from app.services.pki_service import init_demo_pki
    from app.services.certificate_lifecycle_service import get_my_active_certificate
    from app.services.signing_service import prepare_request, confirm_intent, sign_pdf_request

    init_demo_pki(force=True)
    cert = get_my_active_certificate()
    prepared = prepare_request("test.pdf", _minimal_pdf_bytes(), "test", cert["serial"], digest_algorithm="sha384")
    confirm_intent(prepared["request_id"])
    result = sign_pdf_request(prepared["request_id"])
    assert result["verification"]["status"] == "accepted"
    assert result["metadata"]["digest_algorithm"] == "SHA-384"


def test_sign_pdf_with_sha512():
    """PAdES signing works with SHA-512."""
    from app.services.pki_service import init_demo_pki
    from app.services.certificate_lifecycle_service import get_my_active_certificate
    from app.services.signing_service import prepare_request, confirm_intent, sign_pdf_request

    init_demo_pki(force=True)
    cert = get_my_active_certificate()
    prepared = prepare_request("test.pdf", _minimal_pdf_bytes(), "test", cert["serial"], digest_algorithm="sha512")
    confirm_intent(prepared["request_id"])
    result = sign_pdf_request(prepared["request_id"])
    assert result["verification"]["status"] == "accepted"
    assert result["metadata"]["digest_algorithm"] == "SHA-512"


# ── Revocation serial validation ────────────────────────────────────────────

def test_revoke_invalid_serial_raises():
    import pytest
    from app.services.revocation_service import revoke

    with pytest.raises(ValueError, match="Invalid certificate serial"):
        revoke("hh")


def test_revoke_invalid_serial_hex_raises():
    import pytest
    from app.services.revocation_service import revoke

    with pytest.raises(ValueError, match="Invalid certificate serial"):
        revoke("abc123")


def test_status_invalid_serial_raises():
    import pytest
    from app.services.revocation_service import status

    with pytest.raises(ValueError, match="Invalid certificate serial"):
        status("not_a_number")


def test_crl_generation_with_dirty_records():
    """CRL generation does not crash if revocations.json contains invalid serials."""
    import json
    from app.services.pki_service import init_demo_pki
    from app.services.revocation_service import generate_signed_crl
    from app.core.config import settings

    init_demo_pki(force=True)

    # Write a dirty record directly to the JSON file
    dirty_records = [
        {"serial": "hh", "revoked_at": "2024-01-01T00:00:00+00:00", "reason": "keyCompromise"},
        {"serial": "99999999999999999999", "revoked_at": "2024-01-01T00:00:00+00:00", "reason": "cessationOfOperation"},
    ]
    settings.revocation_file.write_text(json.dumps(dirty_records, indent=2), encoding="utf-8")

    crl = generate_signed_crl()
    assert crl["crl_type"] == "SIGNED_X509_CRL"
    assert crl["skipped_invalid_record_count"] >= 1
    assert "hh" in crl["skipped_invalid_serials"]

    # Clean up
    settings.revocation_file.write_text("[]", encoding="utf-8")


def test_crl_contains_valid_revoked_serial():
    """A valid revoked serial should appear in the CRL."""
    from app.services.pki_service import init_demo_pki
    from app.services.revocation_service import revoke, generate_signed_crl
    from app.core.config import settings

    # Start clean
    settings.revocation_file.write_text("[]", encoding="utf-8")

    pki = init_demo_pki(force=True)
    cert_serial = pki["user_certificate"]["serial"]
    revoke(cert_serial)

    crl = generate_signed_crl()
    assert crl["revoked_certificate_count"] >= 1
    assert crl["skipped_invalid_record_count"] == 0

    # Clean up
    settings.revocation_file.write_text("[]", encoding="utf-8")


# ── Timestamp source fields ─────────────────────────────────────────────────

def test_verification_report_has_timestamp_source():
    from app.services.pki_service import init_demo_pki
    from app.services.certificate_lifecycle_service import get_my_active_certificate
    from app.services.signing_service import prepare_request, confirm_intent, sign_pdf_request

    init_demo_pki(force=True)
    cert = get_my_active_certificate()
    prepared = prepare_request("test.pdf", _minimal_pdf_bytes(), "test", cert["serial"])
    confirm_intent(prepared["request_id"])
    result = sign_pdf_request(prepared["request_id"])

    report = result["verification"]
    assert "timestamp_source" in report
    assert "production_tsa" in report
    assert report["production_tsa"] is False
    assert report["legal_ready"] is False


def test_verification_report_has_standard_fields():
    from app.services.pki_service import init_demo_pki
    from app.services.certificate_lifecycle_service import get_my_active_certificate
    from app.services.signing_service import prepare_request, confirm_intent, sign_pdf_request

    init_demo_pki(force=True)
    cert = get_my_active_certificate()
    prepared = prepare_request("test.pdf", _minimal_pdf_bytes(), "test", cert["serial"])
    confirm_intent(prepared["request_id"])
    result = sign_pdf_request(prepared["request_id"])

    report = result["verification"]
    assert "target_profile" in report
    assert "achieved_profile" in report
    assert "digest_algorithm" in report
    assert "signature_algorithm" in report
    assert "ocsp_mode" in report
    assert "revocation_evidence_status" in report


# ── Remote PDF signing ──────────────────────────────────────────────────────

def test_remote_sign_pdf_success():
    from app.services.pki_service import init_demo_pki
    from app.services.certificate_lifecycle_service import get_my_active_certificate
    from app.services.signing_service import prepare_request, confirm_intent
    from app.services.remote_signing_service import remote_sign_pdf_request

    init_demo_pki(force=True)
    cert = get_my_active_certificate()
    prepared = prepare_request("test.pdf", _minimal_pdf_bytes(), "test", cert["serial"])
    confirm_intent(prepared["request_id"])

    result = remote_sign_pdf_request(prepared["request_id"], "000000")
    assert result["file_id"]
    assert result["remote_signing"]["keyCustody"] == "DEMO_BACKEND_KEY"
    assert result["remote_signing"]["privateKeyExposed"] is False
    assert result["verification"]["status"] == "accepted"


def test_remote_sign_pdf_wrong_mfa():
    import pytest
    from app.services.pki_service import init_demo_pki
    from app.services.certificate_lifecycle_service import get_my_active_certificate
    from app.services.signing_service import prepare_request, confirm_intent
    from app.services.remote_signing_service import remote_sign_pdf_request

    init_demo_pki(force=True)
    cert = get_my_active_certificate()
    prepared = prepare_request("test.pdf", _minimal_pdf_bytes(), "test", cert["serial"])
    confirm_intent(prepared["request_id"])

    with pytest.raises(ValueError, match="Invalid demo MFA code"):
        remote_sign_pdf_request(prepared["request_id"], "111111")


def test_remote_sign_pdf_unconfirmed_fails():
    import pytest
    from app.services.pki_service import init_demo_pki
    from app.services.certificate_lifecycle_service import get_my_active_certificate
    from app.services.signing_service import prepare_request
    from app.services.remote_signing_service import remote_sign_pdf_request

    init_demo_pki(force=True)
    cert = get_my_active_certificate()
    prepared = prepare_request("test.pdf", _minimal_pdf_bytes(), "test", cert["serial"])

    with pytest.raises(ValueError, match="confirmed"):
        remote_sign_pdf_request(prepared["request_id"], "000000")


def test_remote_sign_pdf_non_pdf_fails():
    import pytest
    from app.services.pki_service import init_demo_pki
    from app.services.certificate_lifecycle_service import get_my_active_certificate
    from app.services.signing_service import prepare_request, confirm_intent
    from app.services.remote_signing_service import remote_sign_pdf_request

    init_demo_pki(force=True)
    cert = get_my_active_certificate()
    prepared = prepare_request("test.txt", b"hello not pdf", "test", cert["serial"])
    confirm_intent(prepared["request_id"])

    with pytest.raises(ValueError, match="not a PDF"):
        remote_sign_pdf_request(prepared["request_id"], "000000")


# ── Canonical payload verification uses selected digest ──────────────────────

def test_verification_recomputes_hash_with_selected_digest():
    """Verification must use the declared digest, not global default."""
    from app.services.pki_service import init_demo_pki
    from app.services.signing_service import prepare_request, confirm_intent, sign_and_verify

    pki = init_demo_pki(force=True)
    cert_serial = pki["user_certificate"]["serial"]
    prepared = prepare_request("test.txt", b"verification test", "test", cert_serial, digest_algorithm="sha512")
    confirm_intent(prepared["request_id"])
    result = sign_and_verify(prepared["request_id"])
    assert result["status"] == "accepted"
    hash_check = next(c for c in result["checks"] if c["key"] == "documentHashValid")
    assert hash_check["ok"] is True
