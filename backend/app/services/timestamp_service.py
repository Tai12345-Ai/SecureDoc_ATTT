"""
SecureDoc demo timestamp service.

This produces a SIGNED demo timestamp token (SECUREDOC_DEMO_TSA_TOKEN_V1).
It is NOT an RFC3161 TimeStampToken — the token is JSON-based, signed by a
dedicated demo TSA RSA key.

For PAdES/PDF signing, the actual RFC3161 timestamp is produced by pyHanko:
- DummyTimeStamper (demo mode): generates a valid RFC3161-like ASN.1 token
  but from a local demo TSA certificate, not a production TSA.
- HTTPTimeStamper (external mode): connects to a real RFC3161 TSA service
  when configured via SECUREDOC_TSA_MODE=external and SECUREDOC_TSA_URL.
"""

import secrets
import re
from datetime import datetime, timezone
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key

from app.core.config import settings
from app.services.algorithm_policy import ALGORITHM_POLICY
from app.services.crypto_utils import b64d, b64e, canonical_json_bytes, sha256_bytes

TSA_KEY = settings.demo_tsa_dir / "tsa_key.pem"
TSA_PUBLIC_KEY = settings.demo_tsa_dir / "tsa_public_key.pem"


def _write(path: Path, data: bytes):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


def init_demo_tsa(force: bool = False):
    if not force and TSA_KEY.exists() and TSA_PUBLIC_KEY.exists():
        return

    key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    _write(
        TSA_KEY,
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ),
    )
    _write(
        TSA_PUBLIC_KEY,
        key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ),
    )


def _tsa_private_key():
    init_demo_tsa()
    return load_pem_private_key(TSA_KEY.read_bytes(), password=None)


def _tsa_public_key():
    init_demo_tsa()
    return load_pem_public_key(TSA_PUBLIC_KEY.read_bytes())


# Valid hex digest lengths: SHA-256=64, SHA-384=96, SHA-512=128, SHA3-256=64, SHA3-384=96, SHA3-512=128
_VALID_HEX_LENGTHS = {64, 96, 128}


def _token_payload(message_imprint: str, serial: str, gen_time: str) -> dict:
    return {
        "tokenType": "SECUREDOC_DEMO_TSA_TOKEN_V1",
        "hashAlgorithm": ALGORITHM_POLICY.display_digest(),
        "messageImprint": message_imprint,
        # Legacy compatibility alias
        "messageImprintSha256": message_imprint,
        "serial": serial,
        "genTime": gen_time,
        "tsa": "SecureDoc Demo TSA",
        "tsaPublicKeyFingerprintSha256": sha256_bytes(TSA_PUBLIC_KEY.read_bytes()),
    }


def issue_demo_timestamp(message_imprint_sha256: str) -> dict:
    """Issue a demo timestamp token for a document hash digest.

    Despite the legacy parameter name, this now accepts any valid hex digest
    (SHA-256/384/512 or SHA3-256/384/512).
    """
    if not message_imprint_sha256 or not re.fullmatch(r"[0-9a-fA-F]+", message_imprint_sha256):
        raise ValueError("message_imprint must be a valid hex digest")
    if len(message_imprint_sha256) not in _VALID_HEX_LENGTHS:
        raise ValueError(
            f"message_imprint has unexpected length {len(message_imprint_sha256)}. "
            f"Expected one of {sorted(_VALID_HEX_LENGTHS)} hex characters."
        )

    init_demo_tsa()
    serial = secrets.token_hex(12)
    gen_time = datetime.now(timezone.utc).isoformat()
    payload = _token_payload(message_imprint_sha256, serial, gen_time)
    hash_algorithm = ALGORITHM_POLICY.cryptography_hash()
    signature = _tsa_private_key().sign(
        canonical_json_bytes(payload),
        padding.PSS(mgf=padding.MGF1(hash_algorithm), salt_length=padding.PSS.MAX_LENGTH),
        hash_algorithm,
    )
    return {
        **payload,
        "signatureAlgorithm": "RSA-PSS",
        "digestAlgorithm": ALGORITHM_POLICY.display_digest(),
        "signatureBase64": b64e(signature),
        "warning": "Demo TSA token only. Production requires RFC3161 TimeStampToken.",
    }


def verify_demo_timestamp(token: dict, expected_imprint: str) -> dict:
    if not token:
        return {
            "ok": False,
            "trusted": False,
            "source": "missing",
            "message": "Timestamp token is missing.",
        }

    if token.get("tokenType") == "DEMO_TIMESTAMP_JSON":
        imprint_ok = token.get("messageImprintSha256") == expected_imprint
        return {
            "ok": False,
            "trusted": False,
            "source": "DEMO_TIMESTAMP_JSON",
            "genTime": token.get("genTime"),
            "message": (
                "Legacy timestamp imprint matches, but token is unsigned."
                if imprint_ok
                else "Legacy timestamp imprint mismatch and token is unsigned."
            ),
        }

    required = ["messageImprintSha256", "serial", "genTime", "tsa", "tsaPublicKeyFingerprintSha256", "signatureBase64"]
    missing = [key for key in required if not token.get(key)]
    if missing:
        return {
            "ok": False,
            "trusted": False,
            "source": "SECUREDOC_DEMO_TSA_TOKEN_V1",
            "message": f"Timestamp token missing fields: {', '.join(missing)}.",
        }

    imprint_ok = token.get("messageImprintSha256") == expected_imprint
    payload = _token_payload(token["messageImprintSha256"], token["serial"], token["genTime"])
    hash_algorithm = ALGORITHM_POLICY.cryptography_hash(token.get("digestAlgorithm") or token.get("hashAlgorithm"))
    try:
        _tsa_public_key().verify(
            b64d(token["signatureBase64"]),
            canonical_json_bytes(payload),
            padding.PSS(mgf=padding.MGF1(hash_algorithm), salt_length=padding.PSS.MAX_LENGTH),
            hash_algorithm,
        )
        signature_ok = True
    except (InvalidSignature, ValueError):
        signature_ok = False

    ok = imprint_ok and signature_ok
    return {
        "ok": ok,
        "trusted": signature_ok,
        "source": "SECUREDOC_DEMO_TSA_TOKEN_V1",
        "genTime": token.get("genTime"),
        "serial": token.get("serial"),
        "message": (
            "Signed demo TSA token is valid and imprint matches document hash."
            if ok
            else "Timestamp token signature or imprint is invalid."
        ),
        "checks": {
            "imprintMatches": imprint_ok,
            "tsaSignatureValid": signature_ok,
        },
    }
