"""
Demo revocation service.

Phase 4 keeps revocation local, but records revocation time so verification can
distinguish "revoked before signing" from "revoked after a trusted timestamp".
"""

import json
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.x509 import ocsp

from app.core.config import settings
from app.services.algorithm_policy import ALGORITHM_POLICY
from app.services.crypto_utils import b64e


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _parse_time(value: str | None):
    if not value:
        return None
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _validate_decimal_serial(serial: str) -> str:
    """Validate that serial is a decimal integer string.

    Certificate serial numbers are stored as decimal strings in the revocation
    registry. Invalid values like "hh" would crash CRL generation because
    int("hh") raises ValueError.
    """
    serial = str(serial).strip()
    if not serial.isdigit():
        raise ValueError(
            f"Invalid certificate serial: {serial!r}. "
            f"Serial must be decimal digits only."
        )
    return serial


def _read_records() -> list[dict]:
    path = settings.revocation_file
    if not path.exists():
        return []
    return json.loads(path.read_text(encoding="utf-8"))


def _write_records(records: list[dict]):
    settings.revocation_file.parent.mkdir(parents=True, exist_ok=True)
    settings.revocation_file.write_text(json.dumps(records, indent=2, ensure_ascii=False), encoding="utf-8")


def revoke(serial: str, reason: str = "cessationOfOperation") -> dict:
    serial = _validate_decimal_serial(serial)
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
    serial = _validate_decimal_serial(serial)
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
    serial = _validate_decimal_serial(serial)
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


def _reason_flag(reason: str | None) -> x509.ReasonFlags:
    mapping = {
        "keyCompromise": x509.ReasonFlags.key_compromise,
        "caCompromise": x509.ReasonFlags.ca_compromise,
        "affiliationChanged": x509.ReasonFlags.affiliation_changed,
        "superseded": x509.ReasonFlags.superseded,
        "cessationOfOperation": x509.ReasonFlags.cessation_of_operation,
        "certificateHold": x509.ReasonFlags.certificate_hold,
    }
    return mapping.get(reason or "", x509.ReasonFlags.cessation_of_operation)


def _cert_to_cryptography(cert) -> x509.Certificate:
    if isinstance(cert, x509.Certificate):
        return cert
    if hasattr(cert, "dump"):
        return x509.load_der_x509_certificate(cert.dump())
    raise TypeError("Unsupported certificate type")


def generate_signed_crl() -> dict:
    """Generate a signed CRL, skipping legacy invalid serial records."""
    from app.services.pki_service import get_intermediate_certificate, get_intermediate_private_key

    issuer_cert = get_intermediate_certificate()
    issuer_key = get_intermediate_private_key()
    now = datetime.now(timezone.utc)
    builder = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(issuer_cert.subject)
        .last_update(now)
        .next_update(now + timedelta(days=1))
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_key.public_key()), critical=False)
        .add_extension(x509.CRLNumber(int(now.timestamp())), critical=False)
    )

    skipped_invalid_serials: list[str] = []
    valid_count = 0

    for record in _read_records():
        serial_str = record.get("serial", "")
        # Skip legacy invalid records gracefully
        if not str(serial_str).strip().isdigit():
            skipped_invalid_serials.append(str(serial_str))
            continue

        try:
            revoked_at = _parse_time(record.get("revoked_at")) or now
            revoked = (
                x509.RevokedCertificateBuilder()
                .serial_number(int(serial_str))
                .revocation_date(revoked_at)
                .add_extension(x509.CRLReason(_reason_flag(record.get("reason"))), critical=False)
                .build()
            )
            builder = builder.add_revoked_certificate(revoked)
            valid_count += 1
        except Exception:
            skipped_invalid_serials.append(str(serial_str))

    crl_obj = builder.sign(private_key=issuer_key, algorithm=ALGORITHM_POLICY.cryptography_hash())
    der = crl_obj.public_bytes(serialization.Encoding.DER)
    pem = crl_obj.public_bytes(serialization.Encoding.PEM).decode("ascii")
    return {
        "crl_type": "SIGNED_X509_CRL",
        "standard": "RFC5280",
        "issuer": issuer_cert.subject.rfc4514_string(),
        "this_update": crl_obj.last_update_utc.isoformat(),
        "next_update": crl_obj.next_update_utc.isoformat(),
        "revoked_certificate_count": len(crl_obj),
        "signature_algorithm": crl_obj.signature_hash_algorithm.name.upper(),
        "crl_pem": pem,
        "crl_der": der,
        "crl_der_base64": b64e(der),
        "skipped_invalid_record_count": len(skipped_invalid_serials),
        "skipped_invalid_serials": skipped_invalid_serials,
    }


def get_ocsp_response(cert) -> dict:
    from app.services.pki_service import (
        get_intermediate_certificate,
        get_ocsp_responder_certificate,
        get_ocsp_responder_private_key,
    )

    subject_cert = _cert_to_cryptography(cert)
    issuer_cert = get_intermediate_certificate()
    responder_cert = get_ocsp_responder_certificate()
    responder_key = get_ocsp_responder_private_key()
    cert_status = status(str(subject_cert.serial_number))
    revoked = cert_status["revoked"]
    now = datetime.now(timezone.utc)

    builder = ocsp.OCSPResponseBuilder().add_response(
        cert=subject_cert,
        issuer=issuer_cert,
        algorithm=ALGORITHM_POLICY.cryptography_hash(),
        cert_status=ocsp.OCSPCertStatus.REVOKED if revoked else ocsp.OCSPCertStatus.GOOD,
        this_update=now,
        next_update=now + timedelta(days=1),
        revocation_time=_parse_time(cert_status.get("revoked_at")) if revoked else None,
        revocation_reason=_reason_flag(cert_status.get("reason")) if revoked else None,
    )
    builder = builder.responder_id(ocsp.OCSPResponderEncoding.HASH, responder_cert)
    response = builder.sign(private_key=responder_key, algorithm=ALGORITHM_POLICY.cryptography_hash())
    der = response.public_bytes(serialization.Encoding.DER)
    return {
        "response_type": "OCSP_RESPONSE",
        "standard": "RFC6960",
        "serial": str(subject_cert.serial_number),
        "certificate_status": cert_status["status"],
        "responder": responder_cert.subject.rfc4514_string(),
        "produced_at": response.produced_at_utc.isoformat(),
        "ocsp_der": der,
        "ocsp_der_base64": b64e(der),
    }


def get_ocsp_response_for_serial(serial_number: int) -> dict:
    """Generate an OCSP response for a certificate identified by serial number.

    Looks up the certificate across:
    1. Active certificate store (lifecycle certificates)
    2. Bootstrap demo certificate
    """
    from app.services.pki_service import get_user_certificate
    from app.services.certificate_lifecycle_service import _read_certificates

    serial_str = str(serial_number)

    # Search lifecycle certificate records
    try:
        from app.services.pki_service import load_certificate_from_path
        for record in _read_certificates():
            if record.get("serial") == serial_str and record.get("pem_path"):
                cert = load_certificate_from_path(record["pem_path"])
                return get_ocsp_response(cert)
    except Exception:
        pass

    # Try bootstrap demo cert
    try:
        demo_cert = get_user_certificate()
        if str(demo_cert.serial_number) == serial_str:
            return get_ocsp_response(demo_cert)
    except Exception:
        pass

    raise ValueError(
        f"Certificate with serial {serial_str} is unknown. "
        f"Cannot generate OCSP response for unknown certificate."
    )


def collect_revocation_info_for_certificate(cert) -> dict:
    crl_data = generate_signed_crl()
    ocsp_data = get_ocsp_response(cert)
    return {
        "crl_der": [crl_data["crl_der"]],
        "ocsp_der": [ocsp_data["ocsp_der"]],
        "sources": [
            {
                "type": "crl",
                "standard": crl_data["standard"],
                "issuer": crl_data["issuer"],
                "revoked_certificate_count": crl_data["revoked_certificate_count"],
                "der_base64": crl_data["crl_der_base64"],
            },
            {
                "type": "ocsp",
                "standard": ocsp_data["standard"],
                "serial": ocsp_data["serial"],
                "certificate_status": ocsp_data["certificate_status"],
                "der_base64": ocsp_data["ocsp_der_base64"],
            },
        ],
        "message": "Collected signed RFC5280 CRL and RFC6960 OCSP response for the signer certificate.",
    }


def crl() -> dict:
    signed = generate_signed_crl()
    return {key: value for key, value in signed.items() if key != "crl_der"}
