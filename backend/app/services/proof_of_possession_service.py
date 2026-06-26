"""
Proof-of-possession service for browser/local-key enrollment.

The browser should generate a non-extractable private key, send only the public
key, sign the challenge, and let the backend verify ownership before issuing a
certificate.
"""

import json
import re
import secrets
from datetime import datetime, timedelta, timezone

from app.core.config import settings
from app.services.certificate_lifecycle_service import create_enrollment, issue_enrollment
from app.services.pki_service import load_public_key_pem
from app.services.crypto_utils import sha256_bytes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

CHALLENGES_FILE = settings.key_enrollment_dir / "challenges.json"
CHALLENGE_TTL_SECONDS = 300
MAX_PROOF_ATTEMPTS = 5


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _now_dt() -> datetime:
    return datetime.now(timezone.utc)


def _parse_time(value: str | None) -> datetime | None:
    if not value:
        return None
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _read_challenges() -> list[dict]:
    if not CHALLENGES_FILE.exists():
        return []
    try:
        return json.loads(CHALLENGES_FILE.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return []


def _write_challenges(challenges: list[dict]):
    CHALLENGES_FILE.parent.mkdir(parents=True, exist_ok=True)
    CHALLENGES_FILE.write_text(json.dumps(challenges, indent=2, ensure_ascii=False), encoding="utf-8")


def _validate_identity(display_name: str, email: str):
    if not display_name or len(display_name.strip()) < 2:
        raise ValueError("display_name is required")
    if not email or not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email):
        raise ValueError("valid email is required")


def _load_validated_public_key(public_key_pem: str):
    public_key = load_public_key_pem(public_key_pem)
    if not isinstance(public_key, rsa.RSAPublicKey):
        raise ValueError("Only RSA public keys are supported in this demo")
    if public_key.key_size < 2048:
        raise ValueError("RSA key must be at least 2048 bits")
    return public_key


def _public_key_fingerprint(public_key_pem: str) -> str:
    public_key = _load_validated_public_key(public_key_pem)
    der = public_key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return sha256_bytes(der)


def create_key_enrollment_challenge(display_name: str, email: str, public_key_pem: str) -> dict:
    _validate_identity(display_name, email)
    fingerprint = _public_key_fingerprint(public_key_pem)
    challenge_id = "chal_" + secrets.token_hex(12)
    challenge = f"securedoc-key-enrollment-v1:{challenge_id}:{email}:{fingerprint}"
    now = _now_dt()
    expires_at = now + timedelta(seconds=CHALLENGE_TTL_SECONDS)
    record = {
        "challenge_id": challenge_id,
        "display_name": display_name,
        "email": email,
        "public_key_pem": public_key_pem,
        "public_key_fingerprint_sha256": fingerprint,
        "challenge": challenge,
        "status": "issued",
        "created_at": now.isoformat(),
        "expires_at": expires_at.isoformat(),
        "failed_attempts": 0,
        "max_attempts": MAX_PROOF_ATTEMPTS,
    }
    challenges = [item for item in _read_challenges() if item["challenge_id"] != challenge_id]
    challenges.append(record)
    _write_challenges(challenges)
    return {
        "challenge_id": challenge_id,
        "challenge": challenge,
        "public_key_fingerprint_sha256": fingerprint,
        "expires_in_seconds": CHALLENGE_TTL_SECONDS,
        "expires_at": expires_at.isoformat(),
        "replay_protection": "single_use_challenge_id",
        "max_attempts": MAX_PROOF_ATTEMPTS,
        "warning": "Demo JSON challenge store only; production should use DB-backed expiry, rate limits, and audit controls.",
    }


def _expire_if_needed(record: dict, challenges: list[dict]) -> bool:
    expires_at = _parse_time(record.get("expires_at"))
    if expires_at and _now_dt() > expires_at:
        record["status"] = "expired"
        record["expired_at"] = _now()
        _write_challenges(challenges)
        return True
    return False


def _record_failed_attempt(record: dict, challenges: list[dict], reason: str):
    attempts = int(record.get("failed_attempts", 0)) + 1
    record["failed_attempts"] = attempts
    record["last_failed_at"] = _now()
    record["last_failure_reason"] = reason
    if attempts >= int(record.get("max_attempts", MAX_PROOF_ATTEMPTS)):
        record["status"] = "locked"
        record["locked_at"] = _now()
    _write_challenges(challenges)


def submit_public_key_proof(
    challenge_id: str,
    proof_signature_base64: str,
    issue_certificate: bool = True,
    activate_certificate: bool = False,
) -> dict:
    challenges = _read_challenges()
    record = next((item for item in challenges if item["challenge_id"] == challenge_id), None)
    if not record:
        raise ValueError("Unknown key enrollment challenge")
    if record["status"] != "issued":
        raise ValueError(f"Challenge is not usable: {record['status']}")
    if _expire_if_needed(record, challenges):
        raise ValueError("Key enrollment challenge has expired")
    if int(record.get("failed_attempts", 0)) >= int(record.get("max_attempts", MAX_PROOF_ATTEMPTS)):
        record["status"] = "locked"
        record["locked_at"] = _now()
        _write_challenges(challenges)
        raise ValueError("Key enrollment challenge is locked after too many failed attempts")

    try:
        enrollment = create_enrollment(
            display_name=record["display_name"],
            email=record["email"],
            public_key_pem=record["public_key_pem"],
            proof_signature_base64=proof_signature_base64,
            proof_challenge=record["challenge"],
        )
    except ValueError as exc:
        _record_failed_attempt(record, challenges, str(exc))
        raise

    record["status"] = "used"
    record["used_at"] = _now()
    record["enrollment_id"] = enrollment["enrollment_id"]
    _write_challenges(challenges)

    response = {
        "challenge_id": challenge_id,
        "enrollment": enrollment,
        "certificate": None,
    }
    if issue_certificate:
        response["certificate"] = issue_enrollment(enrollment["enrollment_id"], activate=activate_certificate)
    return response
