import hashlib
import json
import time
from pathlib import Path
from typing import Dict, Optional

from app.core.config import settings

def _last_hash() -> str:
    if not settings.audit_file.exists():
        return "0" * 64
    last = None
    for line in settings.audit_file.read_text(encoding="utf-8").splitlines():
        if line.strip():
            try:
                last = json.loads(line)
            except json.JSONDecodeError:
                continue
    return last.get("eventHash", "0" * 64) if last else "0" * 64

def append_event(actor: str, action: str, target: str, status: str, metadata: Optional[Dict] = None) -> Dict:
    previous = _last_hash()
    event = {
        "ts": time.time(),
        "actor": actor,
        "action": action,
        "target": target,
        "status": status,
        "metadata": metadata or {},
        "previousHash": previous,
    }
    canonical = json.dumps(event, sort_keys=True, separators=(",", ":")).encode("utf-8")
    event_hash = hashlib.sha256(previous.encode("utf-8") + canonical).hexdigest()
    event["eventHash"] = event_hash

    settings.audit_file.parent.mkdir(parents=True, exist_ok=True)
    with settings.audit_file.open("a", encoding="utf-8") as f:
        f.write(json.dumps(event, ensure_ascii=False) + "\n")
    return event

def list_events(limit: int = 20):
    if not settings.audit_file.exists():
        return []
    events = []
    for line in settings.audit_file.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            events.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return events[-limit:]
