"""
Demo revocation service.

Phase 4 keeps revocation local, but records revocation time so verification can
distinguish "revoked before signing" from "revoked after a trusted timestamp".
"""

import json
from datetime import datetime, timezone
from pathlib import Path

from app.core.config import settings


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _parse_time(value: str | None):
    if not value:
        return None
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _read_records() -> list[dict]:
    path = settings.revocation_file
    if not path.exists():
        return []
    return json.loads(path.read_text(encoding="utf-8"))


def _write_records(records: list[dict]):
    settings.revocation_file.parent.mkdir(parents=True, exist_ok=True)
    settings.revocation_file.write_text(json.dumps(records, indent=2, ensure_ascii=False), encoding="utf-8")


def revoke(serial: str, reason: str = "cessationOfOperation") -> dict:
    records = [record for record in _read_records() if record["serial"] != serial]
    record = {
        "serial": serial,
        "revoked_at": _now(),
        "reason": reason,
        "source": "DEMO_LOCAL_REVOCATION_REGISTRY",
    }
    records.append(record)
    _write_records(records)
    return record


def is_revoked(serial: str) -> bool:
    return any(record["serial"] == serial for record in _read_records())


def _record_for(serial: str) -> dict | None:
    return next((record for record in _read_records() if record["serial"] == serial), None)


def status(serial: str) -> dict:
    record = _record_for(serial)
    revoked = bool(record)
    return {
        "serial": serial,
        "revoked": revoked,
        "status": "revoked" if revoked else "good",
        "revoked_at": record.get("revoked_at") if record else None,
        "reason": record.get("reason") if record else None,
        "source": "DEMO_LOCAL_REVOCATION_REGISTRY",
        "warning": "Production requires signed CRL/OCSP.",
    }


def status_at(serial: str, at_time_iso: str | None) -> dict:
    current = status(serial)
    if not current["revoked"]:
        return {**current, "status_at_time": "good", "revoked_at_time": False, "checked_at": at_time_iso}
    at_time = _parse_time(at_time_iso)
    revoked_at = _parse_time(current["revoked_at"])
    revoked_at_time = bool(at_time and revoked_at and revoked_at <= at_time)
    return {
        **current,
        "status_at_time": "revoked" if revoked_at_time else "good",
        "revoked_at_time": revoked_at_time,
        "checked_at": at_time_iso,
    }


def crl() -> dict:
    records = sorted(_read_records(), key=lambda record: record["revoked_at"])
    return {
        "crlType": "DEMO_UNSIGNED_CRL_V1",
        "issuer": "SecureDoc Demo Intermediate CA",
        "thisUpdate": _now(),
        "revokedCertificates": records,
        "warning": "Demo CRL is unsigned. Production requires signed X.509 CRL or OCSP.",
    }
