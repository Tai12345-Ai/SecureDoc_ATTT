import base64
import hashlib
import json
from typing import Any, Dict

def sha256_bytes(data: bytes) -> str:
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
