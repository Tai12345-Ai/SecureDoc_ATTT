"""
Blind Signature Service.

This service implements the RSABSSA-SHA384-PSS-Randomized blind signature
variant for privacy token signing.

Important:
- This is not document signing.
- This is for unlinkability/privacy.
- Do not reuse CA/TSA/document-signing keys for blind signing.
"""

import hashlib
import json
import math
import secrets
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict

from app.core.config import settings
from app.services.crypto_utils import sha256_bytes

_BLIND_SIGNER_KEY = None


def _load_pycryptodome():
    try:
        from Crypto.PublicKey import RSA
        from Crypto.Util.number import bytes_to_long, inverse
        from Crypto.Hash import SHA256
        from Crypto.Random import random
    except ModuleNotFoundError as exc:
        try:
            from cryptography.hazmat.primitives import hashes, serialization
            from cryptography.hazmat.primitives.asymmetric import rsa
            from cryptography.hazmat.primitives.serialization import load_pem_private_key
        except ModuleNotFoundError:
            raise RuntimeError("Blind Signature Mode requires PyCryptodome or cryptography RSA support.") from exc

        class _Hash:
            def __init__(self, data: bytes):
                digest = hashes.Hash(hashes.SHA256())
                digest.update(data)
                self._digest = digest.finalize()

            def digest(self):
                return self._digest

        class _SHA256:
            @staticmethod
            def new(data: bytes):
                return _Hash(data)

        class _StrongRandom:
            @staticmethod
            def randint(start: int, end: int) -> int:
                return start + secrets.randbelow(end - start + 1)

        class _Random:
            StrongRandom = _StrongRandom

        class _RSAKey:
            def __init__(self, key):
                self._key = key
                if hasattr(key, "private_numbers"):
                    numbers = key.private_numbers()
                    self.n = numbers.public_numbers.n
                    self.e = numbers.public_numbers.e
                    self.d = numbers.d
                    self._is_private = True
                else:
                    numbers = key.public_numbers()
                    self.n = numbers.n
                    self.e = numbers.e
                    self._is_private = False

            def publickey(self):
                return _RSAKey(self._key.public_key() if self._is_private else self._key)

            def size_in_bits(self):
                return self.n.bit_length()

            def export_key(self, format="PEM"):
                encoding = serialization.Encoding.PEM if format == "PEM" else serialization.Encoding.DER
                if self._is_private:
                    return self._key.private_bytes(
                        encoding,
                        serialization.PrivateFormat.PKCS8,
                        serialization.NoEncryption(),
                    )
                return self._key.public_bytes(
                    encoding,
                    serialization.PublicFormat.SubjectPublicKeyInfo,
                )

        class _RSA:
            @staticmethod
            def generate(bits: int):
                return _RSAKey(rsa.generate_private_key(public_exponent=65537, key_size=bits))

            @staticmethod
            def import_key(data: bytes):
                return _RSAKey(load_pem_private_key(data, password=None))

        return _RSA, lambda data: int.from_bytes(data, "big"), lambda value, modulus: pow(value, -1, modulus), _SHA256, _Random
    return RSA, bytes_to_long, inverse, SHA256, random


def _legacy_in_memory_blind_signer_key():
    global _BLIND_SIGNER_KEY
    RSA, _, _, _, _ = _load_pycryptodome()
    if _BLIND_SIGNER_KEY is None:
        _BLIND_SIGNER_KEY = RSA.generate(2048)
    return _BLIND_SIGNER_KEY

def _legacy_run_blind_signature_flow(message: str) -> dict:
    raise RuntimeError("Legacy blind RSA flow is disabled. Use run_blind_signature_flow for RSABSSA.")
    _, bytes_to_long, inverse, SHA256, random = _load_pycryptodome()
    blind_signer_key = _blind_signer_key()
    public_key = blind_signer_key.publickey()
    message_bytes = message.encode("utf-8")
    message_hash = SHA256.new(message_bytes).digest()
    m = bytes_to_long(message_hash)
    n = public_key.n
    e = public_key.e

    while True:
        r = random.StrongRandom().randint(2, n - 1)
        try:
            r_inv = inverse(r, n)
            break
        except ValueError:
            continue

    blinded = (m * pow(r, e, n)) % n
    blind_signature = pow(blinded, blind_signer_key.d, blind_signer_key.n)
    unblinded_signature = (blind_signature * r_inv) % n
    recovered = pow(unblinded_signature, e, n)
    verified = recovered == m

    return {
        "title": "Blind signature verified" if verified else "Blind signature failed",
        "message": "Signer ký bản đã làm mù; verifier vẫn xác minh được chữ ký trên token gốc.",
        "steps": [
            {
                "name": "Create token",
                "explanation": "User tạo token/message cần được ký ẩn danh.",
                "value": message,
            },
            {
                "name": "Blind token",
                "explanation": "User nhân hash token với r^e mod n để signer không nhìn thấy token gốc.",
                "value": str(blinded)[:48] + "...",
            },
            {
                "name": "Blind signer signs",
                "explanation": "Blind signer ký blinded token bằng private key riêng của blind service.",
                "value": str(blind_signature)[:48] + "...",
            },
            {
                "name": "Unblind signature",
                "explanation": "User loại bỏ blinding factor để nhận chữ ký hợp lệ trên token gốc.",
                "value": str(unblinded_signature)[:48] + "...",
            },
            {
                "name": "Verify",
                "explanation": "Verifier dùng public key của blind signer để kiểm tra chữ ký trên token gốc.",
                "value": "valid" if verified else "invalid",
            },
        ],
        "verified": verified,
        "unlinkability_note": "Signer chỉ thấy blinded token, nên khó liên kết yêu cầu ký ban đầu với token đã unblind sau này.",
        "advanced": {
            "scheme": "legacy-disabled",
            "messageHashSha256": message_hash.hex(),
            "publicExponent": e,
            "modulusBits": public_key.size_in_bits(),
            "warning": "Demo only. Production privacy token should use a reviewed protocol and double-spend protection.",
        },
    }


TARGET_SCHEME = "RFC9474-RSABSSA"
RSABSSA_VARIANT = "RSABSSA-SHA384-PSS-Randomized"
ACHIEVED_SCHEME = f"{RSABSSA_VARIANT} demo implementation"
HASH_NAME = "SHA-384"
PSS_SALT_LENGTH = 48
PREPARE_RANDOM_PREFIX_LENGTH = 32
MAX_BLINDING_RETRIES = 32
BLIND_KEY_PATH = settings.blind_signature_dir / "blind_signer_key.pem"
SPENT_TOKENS_FILE = settings.blind_signature_dir / "spent_tokens.json"
TOKEN_HASH_ALGORITHM = "SHA-256"
RFC9474_TEST_VECTORS_PASSED = False
COMPLIANCE_STATUS = "not_test_vector_verified"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _read_json(path: Path, default):
    if not path.exists():
        return default
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return default


def _write_json(path: Path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")


def _sha384(data: bytes) -> bytes:
    return hashlib.sha384(data).digest()


def _i2osp(value: int, size: int) -> bytes:
    if value < 0 or value >= 256**size:
        raise ValueError("integer too large")
    return value.to_bytes(size, "big")


def _os2ip(data: bytes) -> int:
    return int.from_bytes(data, "big")


def _mgf1(seed: bytes, mask_len: int) -> bytes:
    if mask_len < 0:
        raise ValueError("mask length must be non-negative")
    chunks = []
    for counter in range(math.ceil(mask_len / PSS_SALT_LENGTH)):
        chunks.append(_sha384(seed + counter.to_bytes(4, "big")))
    return b"".join(chunks)[:mask_len]


def _xor_bytes(left: bytes, right: bytes) -> bytes:
    return bytes(a ^ b for a, b in zip(left, right))


def _clear_leftmost_bits(data: bytes, unused_bits: int) -> bytes:
    if not data or unused_bits == 0:
        return data
    return bytes([data[0] & (0xFF >> unused_bits)]) + data[1:]


def _leftmost_bits_are_zero(data: bytes, unused_bits: int) -> bool:
    if not data or unused_bits == 0:
        return True
    return data[0] & (0xFF << (8 - unused_bits)) == 0


def _rsa_modulus_len(public_key) -> int:
    return math.ceil(public_key.n.bit_length() / 8)


def _rsa_pss_em_bits(public_key) -> int:
    return public_key.n.bit_length() - 1


def _emsa_pss_encode(message: bytes, em_bits: int, salt_len: int = PSS_SALT_LENGTH) -> bytes:
    m_hash = _sha384(message)
    h_len = len(m_hash)
    em_len = math.ceil(em_bits / 8)
    if em_len < h_len + salt_len + 2:
        raise ValueError("encoding error")

    salt = secrets.token_bytes(salt_len)
    m_prime = b"\x00" * 8 + m_hash + salt
    h = _sha384(m_prime)
    ps = b"\x00" * (em_len - salt_len - h_len - 2)
    db = ps + b"\x01" + salt
    db_mask = _mgf1(h, em_len - h_len - 1)
    masked_db = _xor_bytes(db, db_mask)
    masked_db = _clear_leftmost_bits(masked_db, 8 * em_len - em_bits)
    return masked_db + h + b"\xbc"


def _emsa_pss_verify(
    message: bytes,
    encoded_msg: bytes,
    em_bits: int,
    salt_len: int = PSS_SALT_LENGTH,
) -> bool:
    m_hash = _sha384(message)
    h_len = len(m_hash)
    em_len = math.ceil(em_bits / 8)
    if len(encoded_msg) != em_len or em_len < h_len + salt_len + 2:
        return False
    if encoded_msg[-1] != 0xBC:
        return False

    masked_db = encoded_msg[: em_len - h_len - 1]
    h = encoded_msg[em_len - h_len - 1 : -1]
    unused_bits = 8 * em_len - em_bits
    if not _leftmost_bits_are_zero(masked_db, unused_bits):
        return False

    db_mask = _mgf1(h, em_len - h_len - 1)
    db = _xor_bytes(masked_db, db_mask)
    db = _clear_leftmost_bits(db, unused_bits)
    ps_len = em_len - h_len - salt_len - 2
    if any(db[:ps_len]) or db[ps_len] != 0x01:
        return False

    salt = db[-salt_len:] if salt_len else b""
    expected_h = _sha384(b"\x00" * 8 + m_hash + salt)
    return secrets.compare_digest(h, expected_h)


def _rsa_pss_verify(public_key, message: bytes, signature: bytes) -> bool:
    modulus_len = _rsa_modulus_len(public_key)
    if len(signature) != modulus_len:
        return False
    representative = _os2ip(signature)
    if representative >= public_key.n:
        return False
    encoded_int = pow(representative, public_key.e, public_key.n)
    encoded_msg = _i2osp(encoded_int, math.ceil(_rsa_pss_em_bits(public_key) / 8))
    return _emsa_pss_verify(message, encoded_msg, _rsa_pss_em_bits(public_key))


def _blind_signer_key():
    global _BLIND_SIGNER_KEY
    RSA, _, _, _, _ = _load_pycryptodome()
    if _BLIND_SIGNER_KEY is not None:
        return _BLIND_SIGNER_KEY
    if BLIND_KEY_PATH.exists():
        _BLIND_SIGNER_KEY = RSA.import_key(BLIND_KEY_PATH.read_bytes())
    else:
        BLIND_KEY_PATH.parent.mkdir(parents=True, exist_ok=True)
        _BLIND_SIGNER_KEY = RSA.generate(3072)
        BLIND_KEY_PATH.write_bytes(_BLIND_SIGNER_KEY.export_key("PEM"))
    return _BLIND_SIGNER_KEY


def blind_signer_info() -> Dict:
    key = _blind_signer_key()
    public_key = key.publickey()
    public_der = public_key.export_key("DER")
    return {
        "key_id": sha256_bytes(public_der)[:24],
        "key_version": 1,
        "public_key_algorithm": "RSA",
        "public_key_size": public_key.size_in_bits(),
        "public_exponent": public_key.e,
        "public_key_der_hex": public_der.hex(),
        "scheme": RSABSSA_VARIANT,
        "status": "active",
        "purpose": "blind-signature-only",
        "separation": "Not reused for CA, TSA, OCSP, PAdES or document signing.",
        "compliance_status": COMPLIANCE_STATUS,
        "rfc9474_test_vectors_passed": RFC9474_TEST_VECTORS_PASSED,
    }


def _spent_records() -> list[Dict]:
    return _read_json(SPENT_TOKENS_FILE, [])


def _is_spent(token_hash: str) -> bool:
    return any(record["token_hash"] == token_hash for record in _spent_records())


def _mark_spent(token_hash: str, token_id: str) -> Dict:
    records = [record for record in _spent_records() if record["token_hash"] != token_hash]
    record = {
        "token_hash": token_hash,
        "token_id": token_id,
        "spent_at": _now(),
        "source": "DEMO_SPENT_TOKEN_REGISTRY",
    }
    records.append(record)
    _write_json(SPENT_TOKENS_FILE, records)
    return record


def _short(value: int | str, length: int = 48) -> str:
    text = str(value)
    return text if len(text) <= length else f"{text[:length]}..."


def prepare_token(message: str) -> Dict:
    if not message or not message.strip():
        raise ValueError("message is required")
    token = message.strip()
    token_bytes = token.encode("utf-8")
    token_hash = sha256_bytes(token_bytes)
    msg_prefix = secrets.token_bytes(PREPARE_RANDOM_PREFIX_LENGTH)
    input_msg = msg_prefix + token_bytes
    return {
        "token_id": "tok_" + secrets.token_hex(12),
        "token": token,
        "token_hash": token_hash,
        "message_bytes": token_bytes,
        "msg_prefix": msg_prefix,
        "input_msg": input_msg,
        "prepare_mode": "PrepareRandomize",
        "lifecycle": ["created"],
        "state": "created",
        "created_at": _now(),
    }


def blind_token(token_record: Dict) -> Dict:
    public_key = _blind_signer_key().publickey()
    n = public_key.n
    e = public_key.e
    modulus_len = _rsa_modulus_len(public_key)
    em_bits = _rsa_pss_em_bits(public_key)

    last_error = "invalid input"
    for pss_retry in range(1, MAX_BLINDING_RETRIES + 1):
        encoded_msg = _emsa_pss_encode(token_record["input_msg"], em_bits)
        message_representative = _os2ip(encoded_msg)
        if message_representative >= n or math.gcd(message_representative, n) != 1:
            continue

        blinding_factor = 1 + secrets.randbelow(n - 1)
        try:
            blinding_inverse = pow(blinding_factor, -1, n)
        except ValueError:
            last_error = "blinding error"
            continue

        blinded = (message_representative * pow(blinding_factor, e, n)) % n
        break
    else:
        raise ValueError(f"{last_error}: unable to blind token after retries")

    blinded_msg = _i2osp(blinded, modulus_len)
    token_record.update(
        {
            "message_hash": _sha384(token_record["input_msg"]).hex(),
            "message_representative": message_representative,
            "encoded_msg": encoded_msg,
            "blinding_factor": blinding_factor,
            "blinding_factor_inverse": blinding_inverse,
            "blinded_token": blinded,
            "blinded_msg": blinded_msg,
            "pss_retry_count": pss_retry,
            "state": "blinded",
        }
    )
    token_record["lifecycle"].append("blinded")
    return token_record


def blind_sign(token_record: Dict) -> Dict:
    key = _blind_signer_key()
    modulus_len = _rsa_modulus_len(key.publickey())
    blinded_representative = _os2ip(token_record["blinded_msg"])
    if not 0 <= blinded_representative < key.n:
        raise ValueError("message representative out of range")

    signed_representative = pow(blinded_representative, key.d, key.n)
    if pow(signed_representative, key.e, key.n) != blinded_representative:
        raise ValueError("signing failure")

    token_record["blind_signature"] = signed_representative
    token_record["blind_sig"] = _i2osp(signed_representative, modulus_len)
    token_record["state"] = "blind_signed"
    token_record["lifecycle"].append("blind_signed")
    return token_record


def unblind_signature(token_record: Dict) -> Dict:
    key = _blind_signer_key()
    public_key = key.publickey()
    modulus_len = _rsa_modulus_len(public_key)
    if len(token_record["blind_sig"]) != modulus_len:
        raise ValueError("unexpected input size")

    blind_sig_int = _os2ip(token_record["blind_sig"])
    signature_int = (blind_sig_int * token_record["blinding_factor_inverse"]) % key.n
    signature = _i2osp(signature_int, modulus_len)
    if not _rsa_pss_verify(public_key, token_record["input_msg"], signature):
        raise ValueError("invalid signature")

    token_record["unblinded_signature"] = signature_int
    token_record["signature"] = signature
    token_record["blind_signature_valid"] = True
    token_record["state"] = "finalized"
    token_record["lifecycle"].append("finalized")
    return token_record


def verify_blind_signature(token_record: Dict) -> Dict:
    public_key = _blind_signer_key().publickey()
    valid = _rsa_pss_verify(public_key, token_record["input_msg"], token_record["signature"])
    token_record["blind_signature_valid"] = valid
    token_record["state"] = "verified" if valid else "verification_failed"
    token_record["lifecycle"].append(token_record["state"])
    return token_record


def redeem_token(token_record: Dict) -> Dict:
    if not token_record.get("blind_signature_valid"):
        token_record["spent_status"] = "not_redeemable"
        token_record["redeemed"] = False
        return token_record

    token_hash = token_record["token_hash"]
    if _is_spent(token_hash):
        token_record["spent_status"] = "already_spent"
        token_record["redeemed"] = False
        token_record["state"] = "spent"
        token_record["lifecycle"].append("spent")
        return token_record

    spent_record = _mark_spent(token_hash, token_record["token_id"])
    token_record["spent_record"] = spent_record
    token_record["spent_status"] = "spent"
    token_record["redeemed"] = True
    token_record["state"] = "spent"
    token_record["lifecycle"].extend(["redeemed", "spent"])
    return token_record


def blind_sign_message(blinded_msg_hex: str, key_id: str) -> Dict:
    """Server-only blind-sign: receives only the blinded message, never the original token."""
    info = blind_signer_info()
    if key_id != info["key_id"]:
        raise ValueError(f"Unknown key_id: {key_id}")

    key = _blind_signer_key()
    modulus_len = _rsa_modulus_len(key.publickey())
    blinded_msg = bytes.fromhex(blinded_msg_hex)
    blinded_representative = _os2ip(blinded_msg)
    if not 0 <= blinded_representative < key.n:
        raise ValueError("message representative out of range")

    signed_representative = pow(blinded_representative, key.d, key.n)
    if pow(signed_representative, key.e, key.n) != blinded_representative:
        raise ValueError("signing failure")

    blind_sig = _i2osp(signed_representative, modulus_len)
    return {
        "blind_sig": blind_sig.hex(),
        "key_id": info["key_id"],
        "achieved_scheme": ACHIEVED_SCHEME,
    }


def redeem_with_verification(
    token_hash: str,
    signature_hex: str,
    msg_prefix_hex: str,
    token: str,
) -> Dict:
    """Verify signature then redeem: check spent registry, mark spent, reject duplicates."""
    public_key = _blind_signer_key().publickey()
    token_bytes = token.encode("utf-8")
    msg_prefix = bytes.fromhex(msg_prefix_hex)
    input_msg = msg_prefix + token_bytes
    signature = bytes.fromhex(signature_hex)

    valid = _rsa_pss_verify(public_key, input_msg, signature)
    if not valid:
        return {
            "accepted": False,
            "reason": "invalid_signature",
            "token_hash": token_hash,
            "token_hash_algorithm": TOKEN_HASH_ALGORITHM,
        }

    if _is_spent(token_hash):
        return {
            "accepted": False,
            "reason": "already_spent",
            "token_hash": token_hash,
            "token_hash_algorithm": TOKEN_HASH_ALGORITHM,
        }

    spent_record = _mark_spent(token_hash, "redeem_" + secrets.token_hex(8))
    return {
        "accepted": True,
        "reason": "redeemed",
        "token_hash": token_hash,
        "token_hash_algorithm": TOKEN_HASH_ALGORITHM,
        "spent_record": spent_record,
    }


def run_blind_signature_flow(message: str) -> dict:
    """Educational all-in-one demo: the server sees the original token. Not the real privacy architecture."""
    token_record = prepare_token(message)
    blind_token(token_record)
    blind_sign(token_record)
    unblind_signature(token_record)
    verify_blind_signature(token_record)
    redeem_token(token_record)

    key_info = blind_signer_info()
    verified = bool(token_record["blind_signature_valid"])
    warnings = [
        "This is an educational all-in-one demo where the server sees the original token. In a real protocol the server only sees the blinded message.",
        "RFC9474 RSABSSA scheme is implemented for the demo key path, but production deployment still needs HSM-backed keys and operational hardening.",
        "Spent-token registry is demo JSON storage, not production-grade double-spend prevention.",
        "Cashu is only a lifecycle reference here; this flow does not claim Cashu protocol compliance.",
    ]

    return {
        "title": "RFC9474 RSABSSA token verified" if verified else "RFC9474 RSABSSA token failed",
        "message": "Blind signer signs a blinded RSASSA-PSS encoded token; Finalize verifies the unblinded RSA-PSS signature.",
        "target_scheme": TARGET_SCHEME,
        "achieved_scheme": ACHIEVED_SCHEME,
        "scheme_complete": verified,
        "production_ready": False,
        "rfc9474_test_vectors_passed": RFC9474_TEST_VECTORS_PASSED,
        "compliance_status": COMPLIANCE_STATUS,
        "compliance_note": "RFC9474 test vectors are not implemented; this is a demo implementation only.",
        "blind_signature_valid": verified,
        "verified": verified,
        "key_id": key_info["key_id"],
        "key_version": key_info["key_version"],
        "token_hash": token_record["token_hash"],
        "token_hash_algorithm": TOKEN_HASH_ALGORITHM,
        "spent_status": token_record["spent_status"],
        "redeemed": token_record["redeemed"],
        "warnings": warnings,
        "unlinkability_note": "Signer only sees the blinded encoded message; the finalized signature verifies over the randomized prepared token.",
        "steps": [
            {
                "name": "Create token",
                "state": "created",
                "explanation": "Wallet creates a privacy token and applies RFC9474 PrepareRandomize.",
                "value": token_record["token_hash"],
            },
            {
                "name": "Blind",
                "state": "blinded",
                "explanation": "Wallet PSS-encodes the prepared token and blinds the representative with a random factor.",
                "value": _short(token_record["blinded_msg"].hex()),
            },
            {
                "name": "BlindSign",
                "state": "blind_signed",
                "explanation": "Blind signer uses a dedicated RSABSSA key and returns the signed blinded representative.",
                "value": _short(token_record["blind_sig"].hex()),
            },
            {
                "name": "Finalize",
                "state": "finalized",
                "explanation": "Wallet unblinds the response and verifies the resulting RSA-PSS signature before accepting it.",
                "value": _short(token_record["signature"].hex()),
            },
            {
                "name": "Verify token",
                "state": "verified" if verified else "verification_failed",
                "explanation": "Verifier checks the signature with RSASSA-PSS using SHA-384, MGF1(SHA-384), and 48-byte salt.",
                "value": "valid" if verified else "invalid",
            },
            {
                "name": "Redeem / mark spent",
                "state": token_record["spent_status"],
                "explanation": "Demo registry records the spent token hash to reject double redemption.",
                "value": token_record["spent_status"],
            },
        ],
        "advanced": {
            "target_scheme": TARGET_SCHEME,
            "achieved_scheme": ACHIEVED_SCHEME,
            "scheme_complete": verified,
            "variant": RSABSSA_VARIANT,
            "prepare_mode": token_record["prepare_mode"],
            "hash": HASH_NAME,
            "mgf": "MGF1(SHA-384)",
            "salt_length": PSS_SALT_LENGTH,
            "msg_prefix_hex": token_record["msg_prefix"].hex(),
            "input_msg_hex": token_record["input_msg"].hex(),
            "key": key_info,
            "token_lifecycle": token_record["lifecycle"],
            "input_msg_hash_sha384": token_record["message_hash"],
            "message_representative": str(token_record["message_representative"]),
            "encoded_msg_hex": token_record["encoded_msg"].hex(),
            "blinded_msg_hex": token_record["blinded_msg"].hex(),
            "blind_sig_hex": token_record["blind_sig"].hex(),
            "signature_hex": token_record["signature"].hex(),
            "pss_retry_count": token_record["pss_retry_count"],
            "spent_record": token_record.get("spent_record"),
            "rfc9474_test_vectors_passed": RFC9474_TEST_VECTORS_PASSED,
            "compliance_status": COMPLIANCE_STATUS,
            "standards": {
                "target": "RFC 9474 / RSABSSA",
                "variant": RSABSSA_VARIANT,
                "hash": HASH_NAME,
                "mgf": "MGF1(SHA-384)",
                "salt_length": PSS_SALT_LENGTH,
                "prepare": "PrepareRandomize",
            },
        },
    }
