import base64
import hashlib
import json
from typing import Any, Dict


def _resolve_algorithm(algorithm: str | None = None) -> str:
    """Resolve and validate digest algorithm via AlgorithmPolicy."""
    from app.services.algorithm_policy import ALGORITHM_POLICY

    return ALGORITHM_POLICY.normalize_digest(algorithm)


def digest_bytes(data: bytes, algorithm: str | None = None) -> bytes:
    """Return raw digest bytes using the specified or default algorithm."""
    alg = _resolve_algorithm(algorithm)
    return hashlib.new(alg, data).digest()


def digest_hex(data: bytes, algorithm: str | None = None) -> str:
    """Return hex-encoded digest using the specified or default algorithm."""
    alg = _resolve_algorithm(algorithm)
    return hashlib.new(alg, data).hexdigest()


def sha256_bytes(data: bytes) -> str:
    """Legacy compatibility wrapper — always uses SHA-256."""
    return hashlib.sha256(data).hexdigest()


def canonical_json_bytes(payload: Dict[str, Any]) -> bytes:
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def b64d(data: str) -> bytes:
    return base64.b64decode(data.encode("ascii"))
