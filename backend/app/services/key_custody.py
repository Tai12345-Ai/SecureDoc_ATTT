"""Key custody constants and normalization helpers.

These values separate demo backend key custody from client-side and future
remote/HSM models. Unknown modes default to no backend private-key access.
"""

from __future__ import annotations

from typing import Any, Dict

KEY_SOURCE_DEMO_BACKEND = "DEMO_BACKEND_KEY"
KEY_SOURCE_CLIENT_SIDE = "CLIENT_SIDE_KEY"
KEY_SOURCE_REMOTE_HSM = "REMOTE_HSM_KEY"

PRIVATE_KEY_CUSTODY_DEMO_BACKEND = "BACKEND_DEMO_STORAGE"
PRIVATE_KEY_CUSTODY_CLIENT_SIDE = "USER_BROWSER_OR_DEVICE"
PRIVATE_KEY_CUSTODY_REMOTE_HSM = "REMOTE_HSM_OR_KMS"
PRIVATE_KEY_CUSTODY_UNKNOWN = "UNKNOWN_OR_EXTERNAL"

_LEGACY_KEY_SOURCE_ALIASES = {
    "demo_backend_signing_key": KEY_SOURCE_DEMO_BACKEND,
    "DEMO_BACKEND_SIGNING_KEY": KEY_SOURCE_DEMO_BACKEND,
    "demo_backend_key": KEY_SOURCE_DEMO_BACKEND,
    "external_public_key": KEY_SOURCE_CLIENT_SIDE,
    "browser_local_key": KEY_SOURCE_CLIENT_SIDE,
    "client_side_key": KEY_SOURCE_CLIENT_SIDE,
    "remote_hsm_key": KEY_SOURCE_REMOTE_HSM,
}

_CUSTODY_BY_KEY_SOURCE = {
    KEY_SOURCE_DEMO_BACKEND: {
        "key_source": KEY_SOURCE_DEMO_BACKEND,
        "private_key_custody": PRIVATE_KEY_CUSTODY_DEMO_BACKEND,
        "backend_has_private_key": True,
    },
    KEY_SOURCE_CLIENT_SIDE: {
        "key_source": KEY_SOURCE_CLIENT_SIDE,
        "private_key_custody": PRIVATE_KEY_CUSTODY_CLIENT_SIDE,
        "backend_has_private_key": False,
    },
    KEY_SOURCE_REMOTE_HSM: {
        "key_source": KEY_SOURCE_REMOTE_HSM,
        "private_key_custody": PRIVATE_KEY_CUSTODY_REMOTE_HSM,
        "backend_has_private_key": False,
    },
}


def normalize_key_source(value: str | None) -> str | None:
    if value is None:
        return None
    raw = str(value).strip()
    if raw in _CUSTODY_BY_KEY_SOURCE:
        return raw
    return _LEGACY_KEY_SOURCE_ALIASES.get(raw, raw)


def key_source_from_record(record: Dict[str, Any]) -> str:
    key_source = normalize_key_source(record.get("key_source"))
    if key_source in _CUSTODY_BY_KEY_SOURCE:
        return key_source
    if key_source:
        return key_source

    origin = record.get("origin")
    enrollment_id = record.get("enrollment_id")
    if origin == "bootstrap_demo" or enrollment_id == "demo_alice_bootstrap":
        return KEY_SOURCE_DEMO_BACKEND
    return KEY_SOURCE_CLIENT_SIDE


def key_custody_metadata(key_source: str | None) -> Dict[str, Any]:
    normalized = normalize_key_source(key_source)
    if normalized in _CUSTODY_BY_KEY_SOURCE:
        return dict(_CUSTODY_BY_KEY_SOURCE[normalized])
    return {
        "key_source": normalized or "UNKNOWN_KEY_SOURCE",
        "private_key_custody": PRIVATE_KEY_CUSTODY_UNKNOWN,
        "backend_has_private_key": False,
    }


def record_key_custody_metadata(record: Dict[str, Any]) -> Dict[str, Any]:
    return key_custody_metadata(key_source_from_record(record))


def with_key_custody_metadata(record: Dict[str, Any]) -> Dict[str, Any]:
    return {**record, **record_key_custody_metadata(record)}
