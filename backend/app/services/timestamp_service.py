from datetime import datetime, timezone
import secrets

def issue_demo_timestamp(message_imprint_sha256: str) -> dict:
    return {
        "tokenType": "DEMO_TIMESTAMP_JSON",
        "serial": secrets.token_hex(12),
        "messageImprintSha256": message_imprint_sha256,
        "genTime": datetime.now(timezone.utc).isoformat(),
        "tsa": "SecureDoc Demo TSA",
        "warning": "Demo timestamp only. Production requires RFC3161 TSA token."
    }

def verify_demo_timestamp(token: dict, expected_imprint: str) -> dict:
    ok = token.get("messageImprintSha256") == expected_imprint
    return {
        "ok": ok,
        "message": "Timestamp imprint matches document hash." if ok else "Timestamp imprint mismatch.",
    }
