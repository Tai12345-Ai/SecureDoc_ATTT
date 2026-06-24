"""
Proof-of-possession service for browser/local-key enrollment.

The browser should generate a non-extractable private key, send only the public
key, sign the challenge, and let the backend verify ownership before issuing a
certificate.
"""

import json
import secrets
from datetime import datetime, timezone

from app.core.config import settings
from app.services.certificate_lifecycle_service import create_enrollment, issue_enrollment
from app.services.pki_service import load_public_key_pem
from app.services.crypto_utils import sha256_bytes
from cryptography.hazmat.primitives import serialization

CHALLENGES_FILE = settings.key_enrollment_dir / "challenges.json"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _read_challenges() -> list[dict]:
    if not CHALLENGES_FILE.exists():
        return []
    return json.loads(CHALLENGES_FILE.read_text(encoding="utf-8"))


def _write_challenges(challenges: list[dict]):
    CHALLENGES_FILE.parent.mkdir(parents=True, exist_ok=True)
    CHALLENGES_FILE.write_text(json.dumps(challenges, indent=2, ensure_ascii=False), encoding="utf-8")


def _public_key_fingerprint(public_key_pem: str) -> str:
    public_key = load_public_key_pem(public_key_pem)
    der = public_key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return sha256_bytes(der)


def create_key_enrollment_challenge(display_name: str, email: str, public_key_pem: str) -> dict:
    fingerprint = _public_key_fingerprint(public_key_pem)
    challenge_id = "chal_" + secrets.token_hex(12)
    challenge = f"securedoc-key-enrollment-v1:{challenge_id}:{email}:{fingerprint}"
    record = {
        "challenge_id": challenge_id,
        "display_name": display_name,
        "email": email,
        "public_key_pem": public_key_pem,
        "public_key_fingerprint_sha256": fingerprint,
        "challenge": challenge,
        "status": "issued",
        "created_at": _now(),
    }
    challenges = [item for item in _read_challenges() if item["challenge_id"] != challenge_id]
    challenges.append(record)
    _write_challenges(challenges)
    return {
        "challenge_id": challenge_id,
        "challenge": challenge,
        "public_key_fingerprint_sha256": fingerprint,
        "expires_in_seconds": 300,
        "warning": "Demo challenge store has no production-grade expiry or replay protection yet.",
    }


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

    enrollment = create_enrollment(
        display_name=record["display_name"],
        email=record["email"],
        public_key_pem=record["public_key_pem"],
        proof_signature_base64=proof_signature_base64,
        proof_challenge=record["challenge"],
    )
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
