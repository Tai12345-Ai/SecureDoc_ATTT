_REVOKED_SERIALS: set[str] = set()

def revoke(serial: str):
    _REVOKED_SERIALS.add(serial)

def is_revoked(serial: str) -> bool:
    return serial in _REVOKED_SERIALS

def status(serial: str) -> dict:
    revoked = is_revoked(serial)
    return {
        "serial": serial,
        "revoked": revoked,
        "status": "revoked" if revoked else "good",
        "source": "DEMO_LOCAL_REVOCATION_LIST",
        "warning": "Production requires CRL/OCSP."
    }
