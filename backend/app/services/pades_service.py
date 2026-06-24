"""
PAdES service backed by pyHanko.

Phase 1 implements PAdES-B-B only. Timestamp, LTV, CRL/OCSP and production
key custody remain separate phases.
"""

from pathlib import Path
from typing import Dict

from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign import fields, signers, validation
from pyhanko.sign.general import load_certs_from_pemder_data
from pyhanko_certvalidator import ValidationContext

from app.services.pki_service import INT_CERT, ROOT_CERT, USER_KEY


class PAdESError(ValueError):
    pass


def is_pdf_bytes(data: bytes) -> bool:
    return data.startswith(b"%PDF-")


def ensure_pdf_file(path: str | Path):
    with Path(path).open("rb") as handle:
        if handle.read(5) != b"%PDF-":
            raise PAdESError("Input file is not a PDF")


def _validation_context() -> ValidationContext:
    trust_root = next(iter(load_certs_from_pemder_data(ROOT_CERT.read_bytes())))
    intermediates = list(load_certs_from_pemder_data(INT_CERT.read_bytes()))
    return ValidationContext(
        trust_roots=[trust_root],
        other_certs=intermediates,
        allow_fetching=False,
        revocation_mode="soft-fail",
    )


def sign_pdf_pades_bb(
    input_pdf_path: str | Path,
    output_pdf_path: str | Path,
    signer_cert_path: str | Path,
    reason: str,
    field_name: str,
) -> Dict:
    input_pdf_path = Path(input_pdf_path)
    output_pdf_path = Path(output_pdf_path)
    signer_cert_path = Path(signer_cert_path)
    ensure_pdf_file(input_pdf_path)
    output_pdf_path.parent.mkdir(parents=True, exist_ok=True)

    signer = signers.SimpleSigner.load(
        key_file=str(USER_KEY),
        cert_file=str(signer_cert_path),
        ca_chain_files=[str(INT_CERT), str(ROOT_CERT)],
        prefer_pss=True,
    )
    signature_meta = signers.PdfSignatureMetadata(
        field_name=field_name,
        md_algorithm="sha256",
        reason=reason,
        name="SecureDoc Demo Signer",
        subfilter=fields.SigSeedSubFilter.PADES,
    )
    pdf_signer = signers.PdfSigner(
        signature_meta,
        signer=signer,
        new_field_spec=fields.SigFieldSpec(sig_field_name=field_name),
    )

    try:
        with input_pdf_path.open("rb") as src, output_pdf_path.open("wb") as dst:
            writer = IncrementalPdfFileWriter(src)
            pdf_signer.sign_pdf(writer, output=dst)
    except Exception as exc:
        raise PAdESError(f"Could not sign PDF: {exc}") from exc

    return {
        "pades_profile": "PAdES-B-B",
        "signature_field": field_name,
        "signed_pdf_path": str(output_pdf_path),
        "signer_certificate_path": str(signer_cert_path),
    }


def verify_pdf_signature(pdf_path: str | Path) -> Dict:
    pdf_path = Path(pdf_path)
    ensure_pdf_file(pdf_path)
    checks = []

    def add(key: str, label: str, ok: bool, message: str):
        checks.append({"key": key, "label": label, "ok": ok, "message": message})

    try:
        with pdf_path.open("rb") as src:
            reader = PdfFileReader(src)
            embedded = list(reader.embedded_signatures)
            if not embedded:
                add("signature_present", "PDF có chữ ký", False, "Không tìm thấy embedded PDF signature.")
                return _report(False, checks, {"signature_count": 0})

            embedded_sig = embedded[-1]
            add("signature_present", "PDF có chữ ký", True, f"Tìm thấy {len(embedded)} embedded signature.")
            status = validation.validate_pdf_signature(
                embedded_sig,
                signer_validation_context=_validation_context(),
            )
    except Exception as exc:
        add("pdf_structure_valid", "Cấu trúc PDF đọc được", False, str(exc))
        return _report(False, checks, {"error": str(exc)})

    add(
        "crypto_valid",
        "Chữ ký mật mã hợp lệ",
        bool(status.bottom_line),
        status.summary() if callable(status.summary) else str(status.summary),
    )
    add(
        "certificate_trusted",
        "Chứng thư ký được tin cậy",
        bool(status.trusted),
        "Certificate chain validates against SecureDoc Demo Root CA." if status.trusted else "Certificate chain is not trusted.",
    )
    integrity_ok = bool(status.bottom_line) and "ENTIRE_FILE" in str(status.coverage)
    add(
        "document_integrity_valid",
        "Tài liệu chưa bị sửa sau khi ký",
        integrity_ok,
        f"Coverage: {status.coverage}",
    )
    add(
        "docmdp_valid",
        "PDF modification policy hợp lệ",
        bool(status.docmdp_ok),
        "No disallowed modification detected." if status.docmdp_ok else "Disallowed modification detected.",
    )

    signer_cert = getattr(status, "signer_cert", None) or getattr(embedded_sig, "signer_cert", None)
    advanced = {
        "signature_count": len(embedded),
        "signature_field": embedded_sig.field_name,
        "summary": status.summary() if callable(status.summary) else str(status.summary),
        "trusted": status.trusted,
        "bottom_line": status.bottom_line,
        "coverage": str(status.coverage),
        "modification_level": str(status.modification_level),
        "signer_subject": signer_cert.subject.human_friendly if signer_cert else None,
        "signer_issuer": signer_cert.issuer.human_friendly if signer_cert else None,
        "signer_serial": str(signer_cert.serial_number) if signer_cert else None,
        "digest_algorithm": "SHA-256",
        "signature_algorithm": "RSA-PSS-SHA256",
   }
    return _report(all(c["ok"] for c in checks), checks, advanced)


def _report(accepted: bool, checks: list[Dict], advanced: Dict) -> Dict:
    return {
        "status": "accepted" if accepted else "rejected",
        "accepted": accepted,
        "title": "PDF signature is valid" if accepted else "PDF signature is not valid",
        "message": (
            "PDF có embedded signature hợp lệ theo PAdES-B-B demo."
            if accepted
            else "PDF không vượt qua một hoặc nhiều kiểm tra chữ ký."
        ),
        "checks": checks,
        "legal_ready": False,
        "warnings": [
            "Demo mode: PAdES-B-B only, chưa có RFC3161 timestamp.",
            "Demo mode: revocation chưa dùng OCSP/CRL thật.",
            "Demo mode: trust root là SecureDoc Demo Root CA local.",
        ],
        "advanced": advanced,
    }


def pades_capabilities() -> dict:
    return {
        "pyhanko_available": True,
        "target_profiles": ["PAdES-B-B", "PAdES-B-T", "PAdES-B-LT", "PAdES-B-LTA"],
        "implemented_profiles": ["PAdES-B-B"],
        "status": "pades_bb_ready",
        "note": "Phase 1 signs and verifies real PDF signatures. Timestamp/LTV are later phases.",
    }
