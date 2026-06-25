"""
PKI Service.

Baseline:
- EJBCA: CA/certificate lifecycle.
- DSS: certificate validation boundary.
- pyca/cryptography: key generation and X.509 building.

Demo model:
Root CA -> Intermediate CA -> User Signing Certificate

Production model:
- Root CA offline.
- Intermediate CA online/HSM.
- User private key in device/browser token/HSM/remote signing service.
"""

from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, Tuple

from cryptography import x509
from cryptography.x509.oid import AuthorityInformationAccessOID, ExtendedKeyUsageOID, NameOID
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key
from cryptography.exceptions import InvalidSignature

from app.core.config import settings
from app.services.algorithm_policy import ALGORITHM_POLICY
from app.services.crypto_utils import sha256_bytes
from app.services.revocation_service import status as revocation_status

ROOT_KEY = settings.demo_pki_dir / "root_ca_key.pem"
ROOT_CERT = settings.demo_pki_dir / "root_ca_cert.pem"
INT_KEY = settings.demo_pki_dir / "intermediate_ca_key.pem"
INT_CERT = settings.demo_pki_dir / "intermediate_ca_cert.pem"
USER_KEY = settings.demo_pki_dir / "alice_signing_key.pem"
USER_CERT = settings.demo_pki_dir / "alice_signing_cert.pem"
TSA_KEY = settings.demo_pki_dir / "tsa_key.pem"
TSA_CERT = settings.demo_pki_dir / "tsa_cert.pem"
OCSP_KEY = settings.demo_pki_dir / "ocsp_responder_key.pem"
OCSP_CERT = settings.demo_pki_dir / "ocsp_responder_cert.pem"

DEMO_POLICY_OID = x509.ObjectIdentifier("1.3.6.1.4.1.55555.1.1")
DEMO_DOCUMENT_SIGNING_POLICY_OID = x509.ObjectIdentifier("1.3.6.1.4.1.55555.1.2")
DEMO_TIMESTAMP_POLICY_OID = x509.ObjectIdentifier("1.3.6.1.4.1.55555.1.3")
DEMO_OCSP_POLICY_OID = x509.ObjectIdentifier("1.3.6.1.4.1.55555.1.4")
DEMO_CRL_URL = "http://localhost:8000/api/revocation/crl.der"
DEMO_OCSP_URL = "http://localhost:8000/api/revocation/ocsp"
DEMO_ROOT_CA_URL = "http://localhost:8000/api/certificates/demo-pki/root.der"
DEMO_INTERMEDIATE_CA_URL = "http://localhost:8000/api/certificates/demo-pki/intermediate.der"

def _write(path: Path, data: bytes):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)

def _private_key_pem(key) -> bytes:
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )

def _cert_pem(cert: x509.Certificate) -> bytes:
    return cert.public_bytes(serialization.Encoding.PEM)

def _load_key(path: Path):
    return load_pem_private_key(path.read_bytes(), password=None)

def _load_cert(path: Path) -> x509.Certificate:
    return x509.load_pem_x509_certificate(path.read_bytes())

def load_certificate_from_path(path: str | Path) -> x509.Certificate:
    return _load_cert(Path(path))

def load_public_key_pem(public_key_pem: str):
    return load_pem_public_key(public_key_pem.encode("utf-8"))

def _name(common_name: str, email: str | None = None):
    attrs = [x509.NameAttribute(NameOID.COMMON_NAME, common_name)]
    if email:
        attrs.append(x509.NameAttribute(NameOID.EMAIL_ADDRESS, email))
    return x509.Name(attrs)

def _new_rsa_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=3072)

def _certificate_policies(*oids: x509.ObjectIdentifier) -> x509.CertificatePolicies:
    return x509.CertificatePolicies([x509.PolicyInformation(oid, None) for oid in oids])


def _crl_distribution_points(url: str = DEMO_CRL_URL) -> x509.CRLDistributionPoints:
    return x509.CRLDistributionPoints([
        x509.DistributionPoint(
            full_name=[x509.UniformResourceIdentifier(url)],
            relative_name=None,
            reasons=None,
            crl_issuer=None,
        )
    ])


def _authority_information_access(ca_issuers_url: str) -> x509.AuthorityInformationAccess:
    return x509.AuthorityInformationAccess([
        x509.AccessDescription(
            AuthorityInformationAccessOID.OCSP,
            x509.UniformResourceIdentifier(DEMO_OCSP_URL),
        ),
        x509.AccessDescription(
            AuthorityInformationAccessOID.CA_ISSUERS,
            x509.UniformResourceIdentifier(ca_issuers_url),
        ),
    ])


def _build_ca_cert(subject_name, issuer_name, public_key, issuer_key, is_root: bool):
    now = datetime.now(timezone.utc)
    path_length = None if is_root else 0
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject_name)
        .issuer_name(issuer_name)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=3650 if is_root else 1825))
        .add_extension(x509.BasicConstraints(ca=True, path_length=path_length), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(public_key), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_key.public_key()), critical=False)
    )
    if not is_root:
        builder = (
            builder
            .add_extension(_crl_distribution_points(), critical=False)
            .add_extension(_authority_information_access(DEMO_ROOT_CA_URL), critical=False)
            .add_extension(_certificate_policies(DEMO_POLICY_OID), critical=False)
        )
    return builder.sign(private_key=issuer_key, algorithm=ALGORITHM_POLICY.cryptography_hash())

def _build_user_cert(
    public_key,
    issuer_cert: x509.Certificate,
    issuer_key,
    common_name: str = "Alice Demo Signer",
    email: str = "alice@example.com",
    validity_days: int = 365,
):
    now = datetime.now(timezone.utc)
    subject = _name(common_name, email)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer_cert.subject)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=validity_days))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=True,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(public_key), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_key.public_key()), critical=False)
        .add_extension(x509.SubjectAlternativeName([x509.RFC822Name(email)]), critical=False)
        .add_extension(_crl_distribution_points(), critical=False)
        .add_extension(_authority_information_access(DEMO_INTERMEDIATE_CA_URL), critical=False)
        .add_extension(_certificate_policies(DEMO_DOCUMENT_SIGNING_POLICY_OID), critical=False)
        .sign(private_key=issuer_key, algorithm=ALGORITHM_POLICY.cryptography_hash())
    )
    return cert


def _build_service_cert(
    public_key,
    issuer_cert: x509.Certificate,
    issuer_key,
    common_name: str,
    eku: ExtendedKeyUsageOID,
    policy_oid: x509.ObjectIdentifier,
    validity_days: int = 365,
):
    now = datetime.now(timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(_name(common_name))
        .issuer_name(issuer_cert.subject)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=validity_days))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.ExtendedKeyUsage([eku]), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(public_key), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_key.public_key()), critical=False)
        .add_extension(_crl_distribution_points(), critical=False)
        .add_extension(_authority_information_access(DEMO_INTERMEDIATE_CA_URL), critical=False)
        .add_extension(_certificate_policies(policy_oid), critical=False)
    )
    if eku == ExtendedKeyUsageOID.OCSP_SIGNING:
        builder = builder.add_extension(x509.OCSPNoCheck(), critical=False)
    return builder.sign(private_key=issuer_key, algorithm=ALGORITHM_POLICY.cryptography_hash())

def init_demo_pki(force: bool = False) -> Dict:
    if not force and _demo_pki_is_current():
        return describe_demo_pki()

    root_key = _new_rsa_key()
    root_subject = _name("SecureDoc Demo Root CA")
    root_cert = _build_ca_cert(root_subject, root_subject, root_key.public_key(), root_key, is_root=True)

    intermediate_key = _new_rsa_key()
    intermediate_subject = _name("SecureDoc Demo Intermediate CA")
    intermediate_cert = _build_ca_cert(
        intermediate_subject,
        root_cert.subject,
        intermediate_key.public_key(),
        root_key,
        is_root=False,
    )

    user_key = _new_rsa_key()
    user_cert = _build_user_cert(user_key.public_key(), intermediate_cert, intermediate_key)

    tsa_key = _new_rsa_key()
    tsa_cert = _build_service_cert(
        tsa_key.public_key(),
        intermediate_cert,
        intermediate_key,
        "SecureDoc Demo RFC3161 TSA",
        ExtendedKeyUsageOID.TIME_STAMPING,
        DEMO_TIMESTAMP_POLICY_OID,
    )

    ocsp_key = _new_rsa_key()
    ocsp_cert = _build_service_cert(
        ocsp_key.public_key(),
        intermediate_cert,
        intermediate_key,
        "SecureDoc Demo OCSP Responder",
        ExtendedKeyUsageOID.OCSP_SIGNING,
        DEMO_OCSP_POLICY_OID,
    )

    _write(ROOT_KEY, _private_key_pem(root_key))
    _write(ROOT_CERT, _cert_pem(root_cert))
    _write(INT_KEY, _private_key_pem(intermediate_key))
    _write(INT_CERT, _cert_pem(intermediate_cert))
    _write(USER_KEY, _private_key_pem(user_key))
    _write(USER_CERT, _cert_pem(user_cert))
    _write(TSA_KEY, _private_key_pem(tsa_key))
    _write(TSA_CERT, _cert_pem(tsa_cert))
    _write(OCSP_KEY, _private_key_pem(ocsp_key))
    _write(OCSP_CERT, _cert_pem(ocsp_cert))

    try:
        from app.services.certificate_lifecycle_service import sync_demo_certificate_record

        sync_demo_certificate_record(force_active=force)
    except Exception:
        # PKI bootstrap must still work if lifecycle storage is not ready yet.
        pass

    return describe_demo_pki()

def describe_demo_pki() -> Dict:
    if not _demo_pki_is_current():
        init_demo_pki(force=True)

    root = _load_cert(ROOT_CERT)
    inter = _load_cert(INT_CERT)
    user = _load_cert(USER_CERT)
    tsa = _load_cert(TSA_CERT)
    ocsp = _load_cert(OCSP_CERT)

    return {
        "root": {
            "subject": root.subject.rfc4514_string(),
            "serial": str(root.serial_number),
            "fingerprint_sha256": sha256_bytes(root.public_bytes(serialization.Encoding.DER)),
        },
        "intermediate": {
            "subject": inter.subject.rfc4514_string(),
            "issuer": inter.issuer.rfc4514_string(),
            "serial": str(inter.serial_number),
            "fingerprint_sha256": sha256_bytes(inter.public_bytes(serialization.Encoding.DER)),
        },
        "tsa_certificate": certificate_view_dict(tsa),
        "ocsp_responder_certificate": certificate_view_dict(ocsp),
        "user_certificate": certificate_view_dict(user),
        "chain": [
            "User Signing Certificate",
            "SecureDoc Demo Intermediate CA",
            "SecureDoc Demo Root CA",
        ],
    }

def certificate_view_dict(cert: x509.Certificate, status_override: str | None = None) -> Dict:
    now = datetime.now(timezone.utc)
    revoked = revocation_status(str(cert.serial_number))["revoked"]
    if status_override:
        cert_status = status_override
    elif revoked:
        cert_status = "revoked"
    elif now > cert.not_valid_after_utc:
        cert_status = "expired"
    elif now < cert.not_valid_before_utc:
        cert_status = "not_yet_valid"
    else:
        cert_status = "active"

    public_key = cert.public_key()
    public_key_algorithm = public_key.__class__.__name__.replace("PublicKey", "")
    public_key_size = getattr(public_key, "key_size", None)
    key_usage = _extension_value(cert, x509.KeyUsage)
    key_usage_values = _key_usage_values(key_usage)
    profile = _certificate_profile_name(cert)

    return {
        "serial": str(cert.serial_number),
        "subject": cert.subject.rfc4514_string(),
        "issuer": cert.issuer.rfc4514_string(),
        "status": cert_status,
        "valid_from": cert.not_valid_before_utc.isoformat(),
        "valid_to": cert.not_valid_after_utc.isoformat(),
        "public_key_algorithm": public_key_algorithm,
        "public_key_size": public_key_size,
        "certificate_signature_algorithm": cert.signature_algorithm_oid._name,
        "document_signature_algorithm": "RSA-PSS",
        "digest_algorithm": ALGORITHM_POLICY.display_digest(),
        "key_usage": key_usage_values,
        "certificate_profile": profile,
        "standards": ["RFC5280"],
    }

def get_root_certificate() -> x509.Certificate:
    init_demo_pki()
    return _load_cert(ROOT_CERT)

def get_intermediate_certificate() -> x509.Certificate:
    init_demo_pki()
    return _load_cert(INT_CERT)

def get_intermediate_private_key():
    init_demo_pki()
    return _load_key(INT_KEY)

def issue_user_certificate_from_public_key(
    public_key,
    common_name: str,
    email: str,
    validity_days: int = 365,
) -> x509.Certificate:
    issuer_cert = get_intermediate_certificate()
    issuer_key = get_intermediate_private_key()
    return _build_user_cert(
        public_key=public_key,
        issuer_cert=issuer_cert,
        issuer_key=issuer_key,
        common_name=common_name,
        email=email,
        validity_days=validity_days,
    )

def write_certificate_pem(path: Path, cert: x509.Certificate):
    _write(path, _cert_pem(cert))

def get_demo_user_public_key_pem() -> str:
    key = get_user_private_key()
    return key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")

def get_user_certificate() -> x509.Certificate:
    try:
        from app.services.certificate_lifecycle_service import get_active_certificate_record

        active = get_active_certificate_record()
        if active and active.get("pem_path"):
            return _load_cert(Path(active["pem_path"]))
    except Exception:
        pass

    init_demo_pki()
    return _load_cert(USER_CERT)

def get_user_private_key():
    init_demo_pki()
    return _load_key(USER_KEY)


def get_tsa_certificate() -> x509.Certificate:
    init_demo_pki()
    return _load_cert(TSA_CERT)


def get_tsa_private_key():
    init_demo_pki()
    return _load_key(TSA_KEY)


def get_ocsp_responder_certificate() -> x509.Certificate:
    init_demo_pki()
    return _load_cert(OCSP_CERT)


def get_ocsp_responder_private_key():
    init_demo_pki()
    return _load_key(OCSP_KEY)

def _extension_value(cert: x509.Certificate, extension_type):
    try:
        return cert.extensions.get_extension_for_class(extension_type).value
    except x509.ExtensionNotFound:
        return None


def _key_usage_values(key_usage: x509.KeyUsage | None) -> list[str]:
    if not key_usage:
        return []
    values = []
    if key_usage.digital_signature:
        values.append("digitalSignature")
    if key_usage.content_commitment:
        values.append("contentCommitment/nonRepudiation")
    if key_usage.key_cert_sign:
        values.append("keyCertSign")
    if key_usage.crl_sign:
        values.append("cRLSign")
    if key_usage.key_encipherment:
        values.append("keyEncipherment")
    return values


def _certificate_profile_name(cert: x509.Certificate) -> str:
    basic_constraints = _extension_value(cert, x509.BasicConstraints)
    eku = _extension_value(cert, x509.ExtendedKeyUsage)
    if basic_constraints and basic_constraints.ca:
        return "RFC5280 Root CA" if cert.subject == cert.issuer else "RFC5280 Intermediate CA"
    if eku and ExtendedKeyUsageOID.TIME_STAMPING in eku:
        return "RFC5280 TSA certificate"
    if eku and ExtendedKeyUsageOID.OCSP_SIGNING in eku:
        return "RFC5280 OCSP responder certificate"
    return "RFC5280 document-signing end-entity"


def _has_extension(cert: x509.Certificate, extension_type) -> bool:
    return _extension_value(cert, extension_type) is not None


def _demo_pki_is_current() -> bool:
    required_paths = [ROOT_KEY, ROOT_CERT, INT_KEY, INT_CERT, USER_KEY, USER_CERT, TSA_KEY, TSA_CERT, OCSP_KEY, OCSP_CERT]
    if not all(path.exists() for path in required_paths):
        return False
    try:
        root = _load_cert(ROOT_CERT)
        inter = _load_cert(INT_CERT)
        user = _load_cert(USER_CERT)
        tsa = _load_cert(TSA_CERT)
        ocsp = _load_cert(OCSP_CERT)
        return (
            validate_ca_certificate_profile(root, expected_root=True)["valid"]
            and validate_ca_certificate_profile(inter)["valid"]
            and validate_document_signing_certificate_profile(user)["valid"]
            and validate_tsa_certificate_profile(tsa)["valid"]
            and validate_ocsp_responder_certificate_profile(ocsp)["valid"]
        )
    except Exception:
        return False


def _profile_result(checks: list[Dict]) -> Dict:
    return {
        "valid": all(check["ok"] for check in checks),
        "checks": checks,
    }


def _profile_check(key: str, label: str, ok: bool, message: str) -> Dict:
    return {"key": key, "label": label, "ok": ok, "message": message}


def validate_document_signing_certificate_profile(cert: x509.Certificate) -> Dict:
    basic_constraints = _extension_value(cert, x509.BasicConstraints)
    key_usage = _extension_value(cert, x509.KeyUsage)
    ski = _extension_value(cert, x509.SubjectKeyIdentifier)
    aki = _extension_value(cert, x509.AuthorityKeyIdentifier)
    san = _extension_value(cert, x509.SubjectAlternativeName)

    checks = [
        _profile_check(
            "basic_constraints_end_entity",
            "BasicConstraints CA:FALSE",
            bool(basic_constraints and basic_constraints.ca is False),
            "Document signing certificate must be an end-entity certificate.",
        ),
        _profile_check(
            "key_usage_document_signing",
            "KeyUsage permits document signing",
            bool(
                key_usage
                and key_usage.digital_signature
                and key_usage.content_commitment
                and not key_usage.key_cert_sign
            ),
            "Document signing uses digitalSignature + contentCommitment and must not permit certificate signing.",
        ),
        _profile_check(
            "subject_key_identifier_present",
            "SubjectKeyIdentifier present",
            ski is not None,
            "SKI is required to trace the signer certificate.",
        ),
        _profile_check(
            "authority_key_identifier_present",
            "AuthorityKeyIdentifier present",
            aki is not None,
            "AKI is required to link the signer certificate to the issuing CA.",
        ),
        _profile_check(
            "subject_alt_name_email_present",
            "SubjectAlternativeName email present",
            bool(san and san.get_values_for_type(x509.RFC822Name)),
            "Document signing certificate must bind an email address in SAN.",
        ),
        _profile_check(
            "crl_distribution_points_present",
            "CRLDistributionPoints present",
            _has_extension(cert, x509.CRLDistributionPoints),
            "RFC 5280 profile requires a revocation distribution point.",
        ),
        _profile_check(
            "authority_information_access_present",
            "AuthorityInformationAccess present",
            _has_extension(cert, x509.AuthorityInformationAccess),
            "AIA should advertise OCSP and issuer certificate locations.",
        ),
        _profile_check(
            "certificate_policies_present",
            "CertificatePolicies present",
            _has_extension(cert, x509.CertificatePolicies),
            "Demo document-signing policy OID must be present.",
        ),
    ]
    return _profile_result(checks)


def validate_ca_certificate_profile(cert: x509.Certificate, expected_root: bool = False) -> Dict:
    basic_constraints = _extension_value(cert, x509.BasicConstraints)
    key_usage = _extension_value(cert, x509.KeyUsage)
    ski = _extension_value(cert, x509.SubjectKeyIdentifier)
    aki = _extension_value(cert, x509.AuthorityKeyIdentifier)

    checks = [
        _profile_check(
            "basic_constraints_ca",
            "BasicConstraints CA:TRUE",
            bool(basic_constraints and basic_constraints.ca is True),
            "CA certificate must be marked as CA.",
        ),
        _profile_check(
            "key_usage_ca",
            "KeyUsage permits CA operations",
            bool(key_usage and key_usage.key_cert_sign and key_usage.crl_sign),
            "CA certificate must permit certificate and CRL signing.",
        ),
        _profile_check(
            "subject_key_identifier_present",
            "SubjectKeyIdentifier present",
            ski is not None,
            "SKI is required for CA chain building.",
        ),
        _profile_check(
            "authority_key_identifier_present",
            "AuthorityKeyIdentifier present",
            aki is not None,
            "AKI is required for CA chain building, including demo self-issued root.",
        ),
    ]
    if expected_root:
        checks.append(
            _profile_check(
                "root_self_issued",
                "Root certificate is self-issued",
                cert.subject == cert.issuer,
                "Demo root CA should be self-issued.",
            )
        )
    else:
        checks.extend([
            _profile_check(
                "intermediate_path_len_zero",
                "Intermediate pathLen=0",
                bool(basic_constraints and basic_constraints.path_length == 0),
                "Intermediate CA must not issue subordinate CA certificates in this demo profile.",
            ),
            _profile_check(
                "crl_distribution_points_present",
                "CRLDistributionPoints present",
                _has_extension(cert, x509.CRLDistributionPoints),
                "Intermediate CA certificate should publish a CRL distribution point.",
            ),
            _profile_check(
                "authority_information_access_present",
                "AuthorityInformationAccess present",
                _has_extension(cert, x509.AuthorityInformationAccess),
                "Intermediate CA certificate should publish OCSP and issuer certificate locations.",
            ),
            _profile_check(
                "certificate_policies_present",
                "CertificatePolicies present",
                _has_extension(cert, x509.CertificatePolicies),
                "Intermediate CA demo policy OID must be present.",
            ),
        ])
    return _profile_result(checks)


def _validate_service_certificate_profile(
    cert: x509.Certificate,
    required_eku: x509.ObjectIdentifier,
    profile_name: str,
) -> Dict:
    basic_constraints = _extension_value(cert, x509.BasicConstraints)
    key_usage = _extension_value(cert, x509.KeyUsage)
    eku = _extension_value(cert, x509.ExtendedKeyUsage)
    checks = [
        _profile_check(
            "basic_constraints_end_entity",
            "BasicConstraints CA:FALSE",
            bool(basic_constraints and basic_constraints.ca is False),
            f"{profile_name} must be an end-entity certificate.",
        ),
        _profile_check(
            "key_usage_digital_signature",
            "KeyUsage digitalSignature",
            bool(key_usage and key_usage.digital_signature and not key_usage.key_cert_sign),
            f"{profile_name} must be restricted to digital signature use.",
        ),
        _profile_check(
            "extended_key_usage_present",
            "ExtendedKeyUsage present",
            bool(eku and required_eku in eku),
            f"{profile_name} must carry the required EKU.",
        ),
        _profile_check(
            "subject_key_identifier_present",
            "SubjectKeyIdentifier present",
            _has_extension(cert, x509.SubjectKeyIdentifier),
            "SKI is required for chain building.",
        ),
        _profile_check(
            "authority_key_identifier_present",
            "AuthorityKeyIdentifier present",
            _has_extension(cert, x509.AuthorityKeyIdentifier),
            "AKI is required to link the certificate to the issuing CA.",
        ),
        _profile_check(
            "crl_distribution_points_present",
            "CRLDistributionPoints present",
            _has_extension(cert, x509.CRLDistributionPoints),
            "Service certificates should publish a CRL distribution point.",
        ),
        _profile_check(
            "authority_information_access_present",
            "AuthorityInformationAccess present",
            _has_extension(cert, x509.AuthorityInformationAccess),
            "Service certificates should publish OCSP and issuer certificate locations.",
        ),
        _profile_check(
            "certificate_policies_present",
            "CertificatePolicies present",
            _has_extension(cert, x509.CertificatePolicies),
            "Service certificate demo policy OID must be present.",
        ),
    ]
    return _profile_result(checks)


def validate_tsa_certificate_profile(cert: x509.Certificate) -> Dict:
    return _validate_service_certificate_profile(cert, ExtendedKeyUsageOID.TIME_STAMPING, "TSA certificate")


def validate_ocsp_responder_certificate_profile(cert: x509.Certificate) -> Dict:
    return _validate_service_certificate_profile(cert, ExtendedKeyUsageOID.OCSP_SIGNING, "OCSP responder certificate")


def get_chain(user_cert: x509.Certificate | None = None) -> Tuple[x509.Certificate, x509.Certificate, x509.Certificate]:
    init_demo_pki()
    return user_cert or get_user_certificate(), _load_cert(INT_CERT), _load_cert(ROOT_CERT)

def verify_chain(user_cert: x509.Certificate | None = None) -> Dict:
    user, inter, root = get_chain(user_cert)
    now = datetime.now(timezone.utc)
    checks = []

    def add(key, label, ok, message):
        checks.append({"key": key, "label": label, "ok": ok, "message": message})

    try:
        inter.public_key().verify(
            user.signature,
            user.tbs_certificate_bytes,
            padding.PKCS1v15(),
            user.signature_hash_algorithm,
        )
        add(
            "user_cert_signed_by_intermediate",
            "User certificate signed by Intermediate CA",
            True,
            "User certificate signature is valid.",
        )
    except InvalidSignature:
        add(
            "user_cert_signed_by_intermediate",
            "User certificate signed by Intermediate CA",
            False,
            "Invalid user certificate signature.",
        )

    try:
        root.public_key().verify(
            inter.signature,
            inter.tbs_certificate_bytes,
            padding.PKCS1v15(),
            inter.signature_hash_algorithm,
        )
        add(
            "intermediate_signed_by_root",
            "Intermediate CA signed by Root CA",
            True,
            "Intermediate CA certificate signature is valid.",
        )
    except InvalidSignature:
        add(
            "intermediate_signed_by_root",
            "Intermediate CA signed by Root CA",
            False,
            "Invalid intermediate certificate signature.",
        )

    add(
        "user_cert_time_valid",
        "User certificate validity period",
        user.not_valid_before_utc <= now <= user.not_valid_after_utc,
        "User certificate is within validity period.",
    )
    add(
        "intermediate_time_valid",
        "Intermediate certificate validity period",
        inter.not_valid_before_utc <= now <= inter.not_valid_after_utc,
        "Intermediate CA is within validity period.",
    )
    add(
        "root_time_valid",
        "Root certificate validity period",
        root.not_valid_before_utc <= now <= root.not_valid_after_utc,
        "Root CA is within validity period.",
    )

    user_profile = validate_document_signing_certificate_profile(user)
    intermediate_profile = validate_ca_certificate_profile(inter)
    root_profile = validate_ca_certificate_profile(root, expected_root=True)

    checks.extend(user_profile["checks"])
    checks.extend(intermediate_profile["checks"])
    checks.extend(root_profile["checks"])

    return {
        "trusted_chain_valid": all(c["ok"] for c in checks),
        "checks": checks,
        "profiles": {
            "user": user_profile,
            "intermediate": intermediate_profile,
            "root": root_profile,
        },
    }
