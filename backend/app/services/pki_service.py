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
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key
from cryptography.exceptions import InvalidSignature

from app.core.config import settings
from app.services.crypto_utils import sha256_bytes
from app.services.revocation_service import status as revocation_status

ROOT_KEY = settings.demo_pki_dir / "root_ca_key.pem"
ROOT_CERT = settings.demo_pki_dir / "root_ca_cert.pem"
INT_KEY = settings.demo_pki_dir / "intermediate_ca_key.pem"
INT_CERT = settings.demo_pki_dir / "intermediate_ca_cert.pem"
USER_KEY = settings.demo_pki_dir / "alice_signing_key.pem"
USER_CERT = settings.demo_pki_dir / "alice_signing_cert.pem"

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

def _build_ca_cert(subject_name, issuer_name, public_key, issuer_key, is_root: bool):
    now = datetime.now(timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject_name)
        .issuer_name(issuer_name)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=3650 if is_root else 1825))
        .add_extension(x509.BasicConstraints(ca=True, path_length=1 if is_root else 0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
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
    )
    return builder.sign(private_key=issuer_key, algorithm=hashes.SHA256())

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
        .sign(private_key=issuer_key, algorithm=hashes.SHA256())
    )
    return cert

def init_demo_pki(force: bool = False) -> Dict:
    if not force and ROOT_KEY.exists() and ROOT_CERT.exists() and INT_KEY.exists() and INT_CERT.exists() and USER_KEY.exists() and USER_CERT.exists():
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

    _write(ROOT_KEY, _private_key_pem(root_key))
    _write(ROOT_CERT, _cert_pem(root_cert))
    _write(INT_KEY, _private_key_pem(intermediate_key))
    _write(INT_CERT, _cert_pem(intermediate_cert))
    _write(USER_KEY, _private_key_pem(user_key))
    _write(USER_CERT, _cert_pem(user_cert))

    try:
        from app.services.certificate_lifecycle_service import sync_demo_certificate_record

        sync_demo_certificate_record(force_active=force)
    except Exception:
        # PKI bootstrap must still work if lifecycle storage is not ready yet.
        pass

    return describe_demo_pki()

def describe_demo_pki() -> Dict:
    if not USER_CERT.exists():
        init_demo_pki(force=True)

    root = _load_cert(ROOT_CERT)
    inter = _load_cert(INT_CERT)
    user = _load_cert(USER_CERT)

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

    return {
        "serial": str(cert.serial_number),
        "subject": cert.subject.rfc4514_string(),
        "issuer": cert.issuer.rfc4514_string(),
        "status": cert_status,
        "valid_from": cert.not_valid_before_utc.isoformat(),
        "valid_to": cert.not_valid_after_utc.isoformat(),
        "key_usage": ["digitalSignature", "contentCommitment/nonRepudiation"],
        "algorithm": "RSA-PSS-SHA256",
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

def get_chain() -> Tuple[x509.Certificate, x509.Certificate, x509.Certificate]:
    init_demo_pki()
    return _load_cert(USER_CERT), _load_cert(INT_CERT), _load_cert(ROOT_CERT)

def verify_chain() -> Dict:
    user, inter, root = get_chain()
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
        add("user_cert_signed_by_intermediate", "User certificate signed by Intermediate CA", True, "User certificate signature is valid.")
    except InvalidSignature:
        add("user_cert_signed_by_intermediate", "User certificate signed by Intermediate CA", False, "Invalid user certificate signature.")

    try:
        root.public_key().verify(
            inter.signature,
            inter.tbs_certificate_bytes,
            padding.PKCS1v15(),
            inter.signature_hash_algorithm,
        )
        add("intermediate_signed_by_root", "Intermediate CA signed by Root CA", True, "Intermediate CA certificate signature is valid.")
    except InvalidSignature:
        add("intermediate_signed_by_root", "Intermediate CA signed by Root CA", False, "Invalid intermediate certificate signature.")

    add("user_cert_time_valid", "User certificate validity period", user.not_valid_before_utc <= now <= user.not_valid_after_utc, "User certificate is within validity period.")
    add("intermediate_time_valid", "Intermediate certificate validity period", inter.not_valid_before_utc <= now <= inter.not_valid_after_utc, "Intermediate CA is within validity period.")
    add("root_time_valid", "Root certificate validity period", root.not_valid_before_utc <= now <= root.not_valid_after_utc, "Root CA is within validity period.")

    return {
        "trusted_chain_valid": all(c["ok"] for c in checks),
        "checks": checks,
    }
