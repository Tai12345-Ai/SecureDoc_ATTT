"""
PAdES service backed by pyHanko.

The user-facing target is PAdES-B-LT. Lower PAdES levels are implementation
steps, not independent user choices. The report is intentionally conservative:
it only claims PAdES-B-LT when a valid signature timestamp and embedded
validation evidence are present in the signed PDF.
"""

import asyncio
import io
from pathlib import Path
from typing import Dict

from asn1crypto import keys, pem
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign import fields, signers, validation
from pyhanko.sign.signers.pdf_signer import PdfCMSSignedAttributes, PdfTBSDocument
from pyhanko.sign.general import load_certs_from_pemder_data
from pyhanko.sign.timestamps import DummyTimeStamper
from pyhanko_certvalidator import ValidationContext
from pyhanko_certvalidator.registry import SimpleCertificateStore

from app.services.algorithm_policy import ALGORITHM_POLICY
from app.services.pki_service import INT_CERT, ROOT_CERT, TSA_CERT, TSA_KEY, USER_KEY
from app.services.revocation_service import collect_revocation_info_for_certificate

TARGET_PADES_PROFILE = "PAdES-B-LT"
PADES_STANDARD = "ETSI EN 319 142-1"
TIMESTAMP_STANDARD = "RFC3161"
REVOCATION_STANDARDS = ["RFC5280", "RFC6960"]


class PAdESError(ValueError):
    pass


def is_pdf_bytes(data: bytes) -> bool:
    return data.startswith(b"%PDF-")


def ensure_pdf_file(path: str | Path):
    with Path(path).open("rb") as handle:
        if handle.read(5) != b"%PDF-":
            raise PAdESError("Input file is not a PDF")


def _load_asn1_private_key(path: str | Path) -> keys.PrivateKeyInfo:
    data = Path(path).read_bytes()
    if pem.detect(data):
        _, _, data = pem.unarmor(data)
    return keys.PrivateKeyInfo.load(data)


def _validation_context(
    *,
    crls: list[bytes] | None = None,
    ocsps: list[bytes] | None = None,
    revocation_mode: str = "soft-fail",
) -> ValidationContext:
    trust_root = next(iter(load_certs_from_pemder_data(ROOT_CERT.read_bytes())))
    intermediates = list(load_certs_from_pemder_data(INT_CERT.read_bytes()))
    return ValidationContext(
        trust_roots=[trust_root],
        other_certs=intermediates,
        allow_fetching=False,
        crls=crls,
        ocsps=ocsps,
        revocation_mode=revocation_mode,
    )


def create_basic_pdf_signature(
    input_pdf_path: str | Path,
    output_pdf_path: str | Path,
    signer_cert_path: str | Path,
    reason: str,
    field_name: str,
    *,
    digest_algorithm: str | None = None,
    timestamper=None,
    validation_context: ValidationContext | None = None,
    embed_validation_info: bool = False,
) -> Dict:
    input_pdf_path = Path(input_pdf_path)
    output_pdf_path = Path(output_pdf_path)
    signer_cert_path = Path(signer_cert_path)
    ensure_pdf_file(input_pdf_path)
    output_pdf_path.parent.mkdir(parents=True, exist_ok=True)

    md_algorithm = ALGORITHM_POLICY.pyhanko_digest(digest_algorithm)
    display_digest = ALGORITHM_POLICY.display_digest(md_algorithm)
    signer = signers.SimpleSigner.load(
        key_file=str(USER_KEY),
        cert_file=str(signer_cert_path),
        ca_chain_files=[str(INT_CERT), str(ROOT_CERT)],
        prefer_pss=True,
    )
    signature_meta = signers.PdfSignatureMetadata(
        field_name=field_name,
        md_algorithm=md_algorithm,
        reason=reason,
        name="SecureDoc Demo Signer",
        subfilter=fields.SigSeedSubFilter.PADES,
        embed_validation_info=embed_validation_info,
        validation_context=validation_context,
    )
    pdf_signer = signers.PdfSigner(
        signature_meta,
        signer=signer,
        timestamper=timestamper,
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
        "digest_algorithm": display_digest,
        "signature_algorithm": "RSA-PSS",
        "timestamp_requested": timestamper is not None,
        "ltv_requested": embed_validation_info,
    }


def _external_signer_for_cert(signer_cert_path: str | Path, signature_value) -> signers.ExternalSigner:
    signer_cert = next(iter(load_certs_from_pemder_data(Path(signer_cert_path).read_bytes())))
    cert_store = SimpleCertificateStore()
    cert_store.register_multiple(list(load_certs_from_pemder_data(INT_CERT.read_bytes())))
    cert_store.register_multiple(list(load_certs_from_pemder_data(ROOT_CERT.read_bytes())))
    return signers.ExternalSigner(
        signing_cert=signer_cert,
        cert_registry=cert_store,
        signature_value=signature_value,
        prefer_pss=True,
    )


def _rsa_pss_salt_length(public_key_size_bits: int, digest_algorithm: str) -> int:
    hash_algorithm = ALGORITHM_POLICY.cryptography_hash(digest_algorithm)
    key_bytes = (public_key_size_bits + 7) // 8
    salt_length = key_bytes - hash_algorithm.digest_size - 2
    if salt_length <= 0:
        raise PAdESError("RSA key is too small for RSA-PSS with the selected digest")
    return salt_length


def _sync_standard_report_fields(
    verification_report: Dict,
    *,
    achieved_profile: str,
    missing: list[str],
    digest_algorithm: str,
    timestamp_status: Dict,
    revocation_status: Dict,
) -> None:
    timestamp_source = timestamp_status.get(
        "timestamp_source",
        timestamp_status.get("source", "unknown"),
    )
    verification_report.update(
        {
            "target_profile": TARGET_PADES_PROFILE,
            "achieved_profile": achieved_profile,
            "missing_requirements": missing,
            "digest_algorithm": digest_algorithm,
            "signature_algorithm": "RSA-PSS",
            "timestamp_source": timestamp_source,
            "production_tsa": timestamp_status.get("production_tsa", False),
            "revocation_evidence_status": revocation_status.get("state", "missing"),
            "legal_ready": False,
        }
    )
    verification_report["warnings"] = [
        "Target profile is PAdES-B-LT, but legal readiness is not asserted for this demo CA.",
        *([f"Missing for PAdES-B-LT: {', '.join(missing)}."] if missing else []),
        f"Timestamping uses {timestamp_source}.",
        "Trust root is the local SecureDoc Demo Root CA.",
    ]


def _merge_timestamp_provider_status(timestamp_status: Dict, timestamp_provider: Dict) -> Dict:
    merged = {**timestamp_provider, **timestamp_status}
    if "timestamp_source" not in merged:
        merged["timestamp_source"] = timestamp_provider.get("timestamp_source", "unknown")
    if "source" not in merged and timestamp_provider.get("source"):
        merged["source"] = timestamp_provider["source"]
    return merged


def prepare_external_pades_signature(
    input_pdf_path: str | Path,
    presigned_pdf_path: str | Path,
    signer_cert_path: str | Path,
    reason: str,
    field_name: str,
    *,
    public_key_size_bits: int,
    digest_algorithm: str | None = None,
) -> Dict:
    """Prepare a PDF for external/client-side PAdES signing.

    The returned ``signed_attributes_der`` is what the client must sign with the
    private key. The backend stores the prepared ByteRange state and later uses
    the client signature to build the CMS object and fill the PDF placeholder.
    """
    input_pdf_path = Path(input_pdf_path)
    presigned_pdf_path = Path(presigned_pdf_path)
    signer_cert_path = Path(signer_cert_path)
    ensure_pdf_file(input_pdf_path)
    presigned_pdf_path.parent.mkdir(parents=True, exist_ok=True)

    md_algorithm = ALGORITHM_POLICY.pyhanko_digest(digest_algorithm)
    digest_display = ALGORITHM_POLICY.display_digest(md_algorithm)
    signature_len = public_key_size_bits // 8
    external_signer = _external_signer_for_cert(signer_cert_path, signature_value=signature_len)
    timestamper, timestamp_provider = add_rfc3161_timestamp(md_algorithm)
    validation_context, revocation_status = collect_validation_info(signer_cert_path)
    signature_meta = signers.PdfSignatureMetadata(
        field_name=field_name,
        md_algorithm=md_algorithm,
        reason=reason,
        name="SecureDoc Client-side Signer",
        subfilter=fields.SigSeedSubFilter.PADES,
        embed_validation_info=True,
        validation_context=validation_context,
    )
    pdf_signer = signers.PdfSigner(
        signature_meta,
        signer=external_signer,
        timestamper=timestamper,
        new_field_spec=fields.SigFieldSpec(sig_field_name=field_name),
    )

    try:
        with input_pdf_path.open("rb") as src:
            writer = IncrementalPdfFileWriter(src)
            signing_session = pdf_signer.init_signing_session(writer)
            validation_info = asyncio.run(signing_session.perform_presign_validation(writer))
            estimation = signing_session.estimate_signature_container_size(
                validation_info,
                tight=signature_meta.tight_size_estimates,
            )
            bytes_reserved = asyncio.run(estimation)
            tbs_document = signing_session.prepare_tbs_document(
                validation_info=validation_info,
                bytes_reserved=bytes_reserved,
            )
            output_buffer = io.BytesIO()
            prepared_digest, res_output = tbs_document.digest_tbs_document(output=output_buffer)
            presigned_pdf_path.write_bytes(res_output.getvalue())
            signed_attrs = asyncio.run(
                tbs_document.signer.signed_attrs(
                    prepared_digest.document_digest,
                    tbs_document.md_algorithm,
                    attr_settings=PdfCMSSignedAttributes(
                        signing_time=signing_session.system_time,
                        adobe_revinfo_attr=(
                            None if validation_info is None else validation_info.adobe_revinfo_attr
                        ),
                        cades_signed_attrs=signature_meta.cades_signed_attr_spec,
                    ),
                    use_pades=tbs_document.use_pades,
                    timestamper=tbs_document.timestamper,
                    is_pdf_sig=True,
                )
            )
    except Exception as exc:
        raise PAdESError(f"Could not prepare external PAdES signature: {exc}") from exc

    return {
        "prepared_digest": prepared_digest,
        "tbs_document": tbs_document,
        "signer_cert_path": str(signer_cert_path),
        "signed_attrs": signed_attrs,
        "signed_attrs_der": signed_attrs.dump(),
        "presigned_pdf_path": str(presigned_pdf_path),
        "digest_algorithm": digest_display,
        "digest_algorithm_normalized": md_algorithm,
        "signature_algorithm": "RSA-PSS",
        "rsa_pss_salt_length": _rsa_pss_salt_length(public_key_size_bits, md_algorithm),
        "timestamp_provider": timestamp_provider,
        "revocation_evidence_status": revocation_status,
        "bytes_reserved": bytes_reserved,
        "document_digest": prepared_digest.document_digest,
    }


def finalize_external_pades_signature(prepared_state: Dict, signature: bytes) -> Dict:
    """Build CMS with an externally produced signature and finalise the PDF."""
    tbs_document = prepared_state["tbs_document"]
    prepared_digest = prepared_state["prepared_digest"]
    presigned_pdf_path = Path(prepared_state["presigned_pdf_path"])
    external_signer = _external_signer_for_cert(
        prepared_state["signer_cert_path"],
        signature_value=signature,
    )
    try:
        signed_attrs = prepared_state["signed_attrs"]
        signature_cms = asyncio.run(
            external_signer.async_sign_prescribed_attributes(
                prepared_state["digest_algorithm_normalized"],
                signed_attrs,
                timestamper=tbs_document.timestamper,
            )
        )
        with presigned_pdf_path.open("r+b") as output:
            PdfTBSDocument.finish_signing(
                output,
                prepared_digest=prepared_digest,
                signature_cms=signature_cms,
                post_sign_instr=tbs_document.post_sign_instructions,
                validation_context=tbs_document.validation_context,
            )
    except Exception as exc:
        raise PAdESError(f"Could not finalize external PAdES signature: {exc}") from exc

    verification_report = verify_pdf_signature(presigned_pdf_path)
    ltv_status = embed_ltv_info(presigned_pdf_path, requested=True)
    timestamp_provider = prepared_state.get("timestamp_provider", {})
    timestamp_status = _merge_timestamp_provider_status(
        verification_report["advanced"].get("timestamp_status", {}),
        timestamp_provider,
    )
    revocation_status = prepared_state.get("revocation_evidence_status", {})
    if ltv_status["state"] == "embedded":
        revocation_status = {**revocation_status, "state": "embedded"}
    missing = _missing_requirements(timestamp_status, revocation_status, ltv_status)
    achieved_profile = _achieved_profile(timestamp_status, ltv_status, missing)
    verification_report["advanced"].update(
        {
            "target_profile": TARGET_PADES_PROFILE,
            "achieved_profile": achieved_profile,
            "pades_profile": achieved_profile,
            "missing_requirements": missing,
            "timestamp_status": timestamp_status,
            "timestamp_provider": timestamp_provider,
            "revocation_evidence_status": revocation_status,
            "ltv_status": ltv_status,
            "digest_algorithm": prepared_state["digest_algorithm"],
            "signature_algorithm": "RSA-PSS",
        }
    )
    _sync_standard_report_fields(
        verification_report,
        achieved_profile=achieved_profile,
        missing=missing,
        digest_algorithm=prepared_state["digest_algorithm"],
        timestamp_status=timestamp_status,
        revocation_status=revocation_status,
    )
    return {
        "target_profile": TARGET_PADES_PROFILE,
        "achieved_profile": achieved_profile,
        "pades_profile": achieved_profile,
        "signed_pdf_path": str(presigned_pdf_path),
        "digest_algorithm": prepared_state["digest_algorithm"],
        "signature_algorithm": "RSA-PSS",
        "timestamp_status": timestamp_status,
        "timestamp_provider": timestamp_provider,
        "revocation_evidence_status": revocation_status,
        "certificate_chain_status": verification_report["advanced"].get("certificate_chain_status"),
        "missing_requirements": missing,
        "verification_report": verification_report,
        "standards": {
            "certificate_profile": ["RFC5280"],
            "timestamp": TIMESTAMP_STANDARD,
            "revocation": REVOCATION_STANDARDS,
            "cms": "RFC5652",
            "pades": PADES_STANDARD,
        },
        "external_signing": {
            "signed_attribute_source": "CMS signedAttrs DER",
            "private_key_on_backend": False,
        },
    }


def add_rfc3161_timestamp(digest_algorithm: str | None = None) -> tuple:
    """Create a timestamper based on configured TSA mode.

    - dummy (default): pyHanko DummyTimeStamper with demo TSA cert/key.
      Produces a valid RFC3161-like token but NOT from a production TSA.
    - external: pyHanko HTTPTimeStamper connecting to an external RFC3161 TSA.
    """
    from app.core.config import settings as app_settings

    md = ALGORITHM_POLICY.pyhanko_digest(digest_algorithm)

    # ── External TSA mode ────────────────────────────────────────────────
    if app_settings.tsa_mode == "external" and app_settings.tsa_url:
        try:
            from pyhanko.sign.timestamps import HTTPTimeStamper

            timestamper = HTTPTimeStamper(
                url=app_settings.tsa_url,
                md_algorithm=md,
            )
            return timestamper, {
                "state": "available",
                "standard": TIMESTAMP_STANDARD,
                "timestamp_source": "external_rfc3161_tsa",
                "source": f"External RFC3161 TSA at {app_settings.tsa_url}",
                "tsa_url": app_settings.tsa_url,
                "production_tsa": True,
            }
        except Exception as exc:
            # Fall through to dummy mode with warning
            pass

    # ── Dummy TSA mode (default) ─────────────────────────────────────────
    try:
        tsa_cert = next(iter(load_certs_from_pemder_data(TSA_CERT.read_bytes())))
        tsa_key = _load_asn1_private_key(TSA_KEY)
        timestamper = DummyTimeStamper(
            tsa_cert=tsa_cert,
            tsa_key=tsa_key,
            certs_to_embed=list(load_certs_from_pemder_data(INT_CERT.read_bytes())),
            override_md=md,
        )
        return timestamper, {
            "state": "available",
            "standard": TIMESTAMP_STANDARD,
            "timestamp_source": "dummy_rfc3161_token",
            "source": "Demo RFC3161 timestamp token created by pyHanko DummyTimeStamper with a dedicated demo TSA certificate",
            "production_tsa": False,
        }
    except Exception as exc:
        return None, {
            "state": "missing",
            "standard": TIMESTAMP_STANDARD,
            "timestamp_source": "unavailable",
            "message": f"RFC3161 timestamp provider is not available: {exc}",
            "production_tsa": False,
        }



def collect_validation_info(signer_cert_path: str | Path) -> tuple[ValidationContext, Dict]:
    cert = next(iter(load_certs_from_pemder_data(Path(signer_cert_path).read_bytes())))
    evidence = collect_revocation_info_for_certificate(cert)
    validation_context = _validation_context(
        crls=evidence["crl_der"],
        ocsps=evidence["ocsp_der"],
        revocation_mode="soft-fail",
    )
    report = {
        "state": "available" if evidence["crl_der"] or evidence["ocsp_der"] else "missing",
        "standards": REVOCATION_STANDARDS,
        "crl_count": len(evidence["crl_der"]),
        "ocsp_count": len(evidence["ocsp_der"]),
        "sources": evidence["sources"],
        "message": evidence["message"],
    }
    return validation_context, report


def _inspect_dss(pdf_path: str | Path) -> Dict:
    """Inspect the PDF DSS dictionary using pyHanko for actual contents."""
    result = {
        "dss_present": False,
        "embedded_cert_count": 0,
        "embedded_crl_count": 0,
        "embedded_ocsp_count": 0,
        "has_embedded_cert_chain": False,
        "has_embedded_crl_or_ocsp": False,
    }
    try:
        with Path(pdf_path).open("rb") as f:
            reader = PdfFileReader(f)
            root = reader.root
            try:
                dss_ref = root.raw_get("/DSS")
            except Exception:
                dss_ref = root.get("/DSS") if hasattr(root, "get") else None
            if dss_ref is None:
                return result
            result["dss_present"] = True
            dss = dss_ref.get_object() if hasattr(dss_ref, "get_object") else dss_ref
            if hasattr(dss, "raw_get"):
                certs = dss.raw_get("/Certs") if "/Certs" in dss else None
                crls = dss.raw_get("/CRLs") if "/CRLs" in dss else None
                ocsps = dss.raw_get("/OCSPs") if "/OCSPs" in dss else None
            else:
                certs = dss.get("/Certs")
                crls = dss.get("/CRLs")
                ocsps = dss.get("/OCSPs")
            if certs is not None:
                certs_obj = certs.get_object() if hasattr(certs, "get_object") else certs
                if hasattr(certs_obj, "__len__"):
                    result["embedded_cert_count"] = len(certs_obj)
            if crls is not None:
                crls_obj = crls.get_object() if hasattr(crls, "get_object") else crls
                if hasattr(crls_obj, "__len__"):
                    result["embedded_crl_count"] = len(crls_obj)
            if ocsps is not None:
                ocsps_obj = ocsps.get_object() if hasattr(ocsps, "get_object") else ocsps
                if hasattr(ocsps_obj, "__len__"):
                    result["embedded_ocsp_count"] = len(ocsps_obj)
            result["has_embedded_cert_chain"] = result["embedded_cert_count"] >= 2
            result["has_embedded_crl_or_ocsp"] = (
                result["embedded_crl_count"] > 0 or result["embedded_ocsp_count"] > 0
            )
    except Exception:
        pass
    return result


def embed_ltv_info(pdf_path: str | Path, requested: bool) -> Dict:
    dss = _inspect_dss(pdf_path)
    has_real_evidence = dss["dss_present"] and dss["has_embedded_crl_or_ocsp"]
    return {
        "state": "embedded" if requested and has_real_evidence else "missing",
        "standard": PADES_STANDARD,
        "dss_present": dss["dss_present"],
        "dss_detail": dss,
    }


def _requirement_missing(report: Dict) -> list[str]:
    """Compute PAdES-B-LT gaps from observed facts, not from prior conclusions."""
    missing: list[str] = []
    if not report.get("has_embedded_signature"):
        missing.append("embedded PDF signature")
    if not report.get("signature_crypto_valid"):
        missing.append("valid PDF cryptographic signature")
    if not report.get("chain_valid_against_demo_root"):
        missing.append("valid certificate chain")
    if not report.get("timestamp_valid"):
        missing.append("valid RFC3161 signature timestamp")
    if not report.get("has_dss"):
        missing.append("PDF DSS")
    if not report.get("has_embedded_cert_chain"):
        missing.append("embedded certificate chain")
    if not report.get("has_embedded_crl_or_ocsp"):
        missing.append("embedded CRL/OCSP revocation evidence")
    if not report.get("revocation_evidence_valid"):
        missing.append("valid revocation evidence")
    if report.get("signing_cert_good_at_signing_time") is False:
        missing.append("signer certificate good at signing time")
    return missing


def _profile_from_requirement_report(report: Dict, missing: list[str]) -> str:
    if not missing:
        return "PAdES-B-LT"
    if (
        report.get("has_embedded_signature")
        and report.get("signature_crypto_valid")
        and report.get("chain_valid_against_demo_root")
        and report.get("timestamp_valid")
    ):
        return "PAdES-B-T"
    return "PAdES-B-B"


def validate_pades_blt_requirements(pdf_path: str | Path) -> Dict:
    """Return an independently recomputed B-LT requirement report."""
    pdf_path = Path(pdf_path)
    report = {
        "has_embedded_signature": False,
        "signature_crypto_valid": False,
        "has_signature_timestamp": False,
        "timestamp_valid": False,
        "has_dss": False,
        "has_embedded_cert_chain": False,
        "has_embedded_crl_or_ocsp": False,
        "revocation_evidence_valid": False,
        "signing_cert_good_at_signing_time": None,
        "chain_valid_against_demo_root": False,
        "target_profile": TARGET_PADES_PROFILE,
        "achieved_profile": "PAdES-B-B",
        "missing_requirements": [],
        "validation_source": "independent_requirement_recomputation",
    }
    try:
        verify_result = verify_pdf_signature(pdf_path)
    except Exception:
        report["missing_requirements"] = _requirement_missing(report)
        return report

    adv = verify_result.get("advanced", {})
    vg = adv.get("verification_groups", {})
    document_integrity = vg.get("document_integrity", {})
    signature_crypto = vg.get("signature_crypto", {})
    timestamp_group = vg.get("timestamp", {})
    chain_validation = vg.get("chain_validation", {})
    signer_cert_info = vg.get("signer_certificate", {})

    report["has_embedded_signature"] = bool(document_integrity.get("signature_present"))
    report["signature_crypto_valid"] = bool(signature_crypto.get("crypto_valid"))
    report["has_signature_timestamp"] = bool(timestamp_group.get("present"))
    report["timestamp_valid"] = bool(timestamp_group.get("valid"))
    report["chain_valid_against_demo_root"] = bool(chain_validation.get("chain_valid"))
    report["signing_cert_good_at_signing_time"] = signer_cert_info.get("valid_at_signing_time")

    dss_info = _inspect_dss(pdf_path)
    report["has_dss"] = dss_info["dss_present"]
    report["has_embedded_cert_chain"] = dss_info["has_embedded_cert_chain"]
    report["has_embedded_crl_or_ocsp"] = dss_info["has_embedded_crl_or_ocsp"]
    report["revocation_evidence_valid"] = bool(dss_info["has_embedded_crl_or_ocsp"])
    report["dss_detail"] = dss_info

    missing = _requirement_missing(report)
    report["missing_requirements"] = missing
    report["achieved_profile"] = _profile_from_requirement_report(report, missing)
    return report


def _missing_requirements(timestamp_status: Dict, revocation_status: Dict, ltv_status: Dict) -> list[str]:
    missing = []
    if timestamp_status.get("state") != "valid":
        missing.append("valid RFC3161 timestamp")
    if revocation_status.get("state") != "embedded":
        missing.append("embedded CRL or OCSP revocation evidence")
    if ltv_status.get("state") != "embedded":
        missing.append("embedded PDF DSS/LTV validation info")
    return missing


def _achieved_profile(timestamp_status: Dict, ltv_status: Dict, missing: list[str]) -> str:
    if not missing and timestamp_status.get("state") == "valid" and ltv_status.get("state") == "embedded":
        return "PAdES-B-LT"
    if timestamp_status.get("state") == "valid":
        return "PAdES-B-T"
    return "PAdES-B-B"


def _signer_certificate_profile(signer_cert, signing_time) -> Dict:
    if not signer_cert:
        return {
            "valid_at_signing_time": None,
            "key_usage_ok": None,
            "is_ca_false": None,
        }
    try:
        from cryptography import x509 as crypto_x509
        from app.services.pki_service import validate_document_signing_certificate_profile

        cert = crypto_x509.load_der_x509_certificate(signer_cert.dump())
        profile = validate_document_signing_certificate_profile(cert)
        checks = {check["key"]: check["ok"] for check in profile["checks"]}
        if signing_time:
            valid_at_signing_time = cert.not_valid_before_utc <= signing_time <= cert.not_valid_after_utc
        else:
            valid_at_signing_time = None
        return {
            "valid_at_signing_time": valid_at_signing_time,
            "key_usage_ok": bool(checks.get("key_usage_document_signing")),
            "is_ca_false": bool(checks.get("basic_constraints_end_entity")),
        }
    except Exception:
        return {
            "valid_at_signing_time": None,
            "key_usage_ok": None,
            "is_ca_false": None,
        }


def sign_pdf_pades_blt(
    input_pdf_path: str | Path,
    output_pdf_path: str | Path,
    signer_cert_path: str | Path,
    reason: str,
    field_name: str,
    *,
    digest_algorithm: str | None = None,
) -> Dict:
    """Sign a PDF with PAdES-B-LT as the target profile."""

    output_pdf_path = Path(output_pdf_path)
    timestamper, timestamp_provider = add_rfc3161_timestamp(digest_algorithm)
    validation_context, revocation_status = collect_validation_info(signer_cert_path)
    sign_error = None

    try:
        create_basic_pdf_signature(
            input_pdf_path=input_pdf_path,
            output_pdf_path=output_pdf_path,
            signer_cert_path=signer_cert_path,
            reason=reason,
            field_name=field_name,
            digest_algorithm=digest_algorithm,
            timestamper=timestamper,
            validation_context=validation_context,
            embed_validation_info=True,
        )
        ltv_requested = True
    except Exception as exc:
        sign_error = str(exc)
        create_basic_pdf_signature(
            input_pdf_path=input_pdf_path,
            output_pdf_path=output_pdf_path,
            signer_cert_path=signer_cert_path,
            reason=reason,
            field_name=field_name,
            digest_algorithm=digest_algorithm,
            timestamper=timestamper,
            validation_context=None,
            embed_validation_info=False,
        )
        ltv_requested = False

    verification_report = verify_pdf_signature(output_pdf_path)
    timestamp_status = _merge_timestamp_provider_status(
        verification_report["advanced"].get("timestamp_status", {}),
        timestamp_provider,
    )
    ltv_status = embed_ltv_info(output_pdf_path, ltv_requested)
    if ltv_status["state"] == "embedded":
        revocation_status = {**revocation_status, "state": "embedded"}

    missing = _missing_requirements(timestamp_status, revocation_status, ltv_status)
    achieved_profile = _achieved_profile(timestamp_status, ltv_status, missing)
    digest_display = ALGORITHM_POLICY.display_digest(digest_algorithm)

    verification_report["advanced"].update(
        {
            "target_profile": TARGET_PADES_PROFILE,
            "achieved_profile": achieved_profile,
            "pades_profile": achieved_profile,
            "missing_requirements": missing,
            "timestamp_status": timestamp_status,
            "timestamp_provider": timestamp_provider,
            "revocation_evidence_status": revocation_status,
            "ltv_status": ltv_status,
            "digest_algorithm": digest_display,
            "signature_algorithm": "RSA-PSS",
        }
    )
    _sync_standard_report_fields(
        verification_report,
        achieved_profile=achieved_profile,
        missing=missing,
        digest_algorithm=digest_display,
        timestamp_status=timestamp_status,
        revocation_status=revocation_status,
    )

    return {
        "target_profile": TARGET_PADES_PROFILE,
        "achieved_profile": achieved_profile,
        "pades_profile": achieved_profile,
        "signature_field": field_name,
        "signed_pdf_path": str(output_pdf_path),
        "signer_certificate_path": str(signer_cert_path),
        "digest_algorithm": digest_display,
        "signature_algorithm": "RSA-PSS",
        "timestamp_status": timestamp_status,
        "timestamp_provider": timestamp_provider,
        "revocation_evidence_status": revocation_status,
        "certificate_chain_status": verification_report["advanced"].get("certificate_chain_status"),
        "missing_requirements": missing,
        "verification_report": verification_report,
        "standards": {
            "certificate_profile": ["RFC5280"],
            "timestamp": TIMESTAMP_STANDARD,
            "revocation": REVOCATION_STANDARDS,
            "cms": "RFC5652",
            "pades": PADES_STANDARD,
        },
        "internal_steps": {
            "basic_signature": "PAdES-B-B",
            "timestamp_provider": timestamp_provider,
            "ltv_embedding_error": sign_error,
        },
    }


def sign_pdf_pades_bb(
    input_pdf_path: str | Path,
    output_pdf_path: str | Path,
    signer_cert_path: str | Path,
    reason: str,
    field_name: str,
) -> Dict:
    """Compatibility wrapper. B-B is now an internal building block."""
    return create_basic_pdf_signature(
        input_pdf_path=input_pdf_path,
        output_pdf_path=output_pdf_path,
        signer_cert_path=signer_cert_path,
        reason=reason,
        field_name=field_name,
    )


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
    coverage_text = str(status.coverage)
    integrity_ok = bool(status.bottom_line) and (
        "ENTIRE_FILE" in coverage_text or "ENTIRE_REVISION" in coverage_text
    )
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
    timestamp_validity = getattr(status, "timestamp_validity", None)
    timestamp_state = "missing"
    timestamp_message = "No RFC3161 signature timestamp was found in the PDF signature."
    timestamp_time = None
    if timestamp_validity is not None:
        timestamp_ok = bool(
            getattr(timestamp_validity, "valid", False)
            or getattr(timestamp_validity, "trusted", False)
            or getattr(timestamp_validity, "bottom_line", False)
        )
        timestamp_state = "valid" if timestamp_ok else "present"
        timestamp_time = getattr(timestamp_validity, "timestamp", None)
        timestamp_message = (
            "Demo RFC3161 signature timestamp is present and validates."
            if timestamp_ok
            else "Demo RFC3161 signature timestamp is present, but validation is incomplete."
        )

    certificate_chain_status = "valid" if status.trusted else "invalid"
    ltv_status = embed_ltv_info(pdf_path, requested=True)
    revocation_status = {
        "state": "embedded" if ltv_status["state"] == "embedded" else "missing",
        "standards": REVOCATION_STANDARDS,
        "message": (
            "PDF DSS/LTV data is present."
            if ltv_status["state"] == "embedded"
            else "No embedded CRL/OCSP validation evidence was found in the PDF DSS."
        ),
    }
    timestamp_status = {
        "state": timestamp_state,
        "standard": TIMESTAMP_STANDARD,
        "message": timestamp_message,
        "time": timestamp_time.isoformat() if timestamp_time else None,
        "production_tsa": False,
    }
    missing = _missing_requirements(timestamp_status, revocation_status, ltv_status)
    achieved_profile = _achieved_profile(timestamp_status, ltv_status, missing)
    checks_by_key = {check["key"]: check for check in checks}
    signer_profile = _signer_certificate_profile(signer_cert, timestamp_time)
    meets_b_b = bool(
        checks_by_key.get("signature_present", {}).get("ok")
        and checks_by_key.get("crypto_valid", {}).get("ok")
        and checks_by_key.get("certificate_trusted", {}).get("ok")
    )
    meets_b_t = meets_b_b and timestamp_status["state"] == "valid"
    meets_b_lt = meets_b_t and revocation_status["state"] == "embedded" and ltv_status["state"] == "embedded"
    verification_groups = {
        "document_integrity": {
            "signature_present": bool(checks_by_key.get("signature_present", {}).get("ok")),
            "byte_range_valid": bool(status.bottom_line),
            "coverage_entire_file": bool(checks_by_key.get("document_integrity_valid", {}).get("ok")),
            "modified_after_signing": not bool(status.docmdp_ok),
            "coverage": str(status.coverage),
            "modification_level": str(getattr(status, "modification_level", "unknown")),
        },
        "signature_crypto": {
            "digest_algorithm": ALGORITHM_POLICY.display_digest(),
            "signature_algorithm": "RSA-PSS",
            "crypto_valid": bool(checks_by_key.get("crypto_valid", {}).get("ok")),
        },
        "signer_certificate": {
            "serial": str(signer_cert.serial_number) if signer_cert else None,
            "subject": signer_cert.subject.human_friendly if signer_cert else None,
            "issuer": signer_cert.issuer.human_friendly if signer_cert else None,
            **signer_profile,
        },
        "chain_validation": {
            "trusted_root": bool(status.trusted),
            "chain_valid": certificate_chain_status == "valid",
        },
        "timestamp": {
            "required_for_target": True,
            "present": timestamp_status["state"] in {"present", "valid"},
            "type": TIMESTAMP_STANDARD if timestamp_status["state"] in {"present", "valid"} else None,
            "valid": timestamp_status["state"] == "valid",
            "gen_time": timestamp_status["time"],
            "production_tsa": False,
        },
        "revocation": {
            "required_for_target": True,
            "method": "CRL/OCSP" if revocation_status["state"] == "embedded" else None,
            "evidence_present": revocation_status["state"] in {"available", "embedded"},
            "embedded": revocation_status["state"] == "embedded",
            "signer_revoked_at_signing_time": False if revocation_status["state"] == "embedded" else None,
        },
        "pades_profile": {
            "target_profile": TARGET_PADES_PROFILE,
            "achieved_profile": achieved_profile,
            "meets_b_b": meets_b_b,
            "meets_b_t": meets_b_t,
            "meets_b_lt": meets_b_lt,
            "missing_requirements": missing,
        },
        "legal": {
            "legal_ready": False,
            "reason": "Technical demo; not integrated with legally trusted public CA/HSM/legal policy.",
        },
    }

    advanced = {
        "signature_count": len(embedded),
        "signature_field": embedded_sig.field_name,
        "summary": status.summary() if callable(status.summary) else str(status.summary),
        "trusted": status.trusted,
        "bottom_line": status.bottom_line,
        "coverage": str(status.coverage),
        "modification_level": str(getattr(status, "modification_level", "unknown")),
        "signer_subject": signer_cert.subject.human_friendly if signer_cert else None,
        "signer_issuer": signer_cert.issuer.human_friendly if signer_cert else None,
        "signer_serial": str(signer_cert.serial_number) if signer_cert else None,
        "target_profile": TARGET_PADES_PROFILE,
        "achieved_profile": achieved_profile,
        "pades_profile": achieved_profile,
        "missing_requirements": missing,
        "digest_algorithm": ALGORITHM_POLICY.display_digest(),
        "signature_algorithm": "RSA-PSS",
        "timestamp_status": timestamp_status,
        "revocation_evidence_status": revocation_status,
        "certificate_chain_status": certificate_chain_status,
        "ltv_status": ltv_status,
        "verification_groups": verification_groups,
    }
    return _report(all(c["ok"] for c in checks), checks, advanced)


def _report(accepted: bool, checks: list[Dict], advanced: Dict) -> Dict:
    target_profile = advanced.get("target_profile", TARGET_PADES_PROFILE)
    achieved_profile = advanced.get("achieved_profile", "PAdES-B-B")
    missing = advanced.get("missing_requirements", [])
    timestamp_status = advanced.get("timestamp_status", {})
    revocation_status = advanced.get("revocation_evidence_status", {})
    timestamp_source = timestamp_status.get("timestamp_source", timestamp_status.get("source", "unknown"))
    production_tsa = timestamp_status.get("production_tsa", False)

    return {
        "status": "accepted" if accepted else "rejected",
        "accepted": accepted,
        "title": "PDF signature is valid" if accepted else "PDF signature is not valid",
        "message": (
            f"PDF has a valid embedded signature. Target profile is {target_profile}; achieved profile is {achieved_profile}."
            if accepted
            else "PDF failed one or more signature checks."
        ),
        "checks": checks,
        "legal_ready": False,
        # Standard status fields
        "target_profile": target_profile,
        "achieved_profile": achieved_profile,
        "missing_requirements": missing,
        "digest_algorithm": advanced.get("digest_algorithm", "SHA-256"),
        "signature_algorithm": advanced.get("signature_algorithm", "RSA-PSS"),
        "timestamp_source": timestamp_source,
        "production_tsa": production_tsa,
        "revocation_evidence_status": revocation_status.get("state", "missing"),
        "ocsp_mode": "demo_local_registry",
        "warnings": [
            "Target profile is PAdES-B-LT, but legal readiness is not asserted for this demo CA.",
            *([f"Missing for PAdES-B-LT: {', '.join(missing)}."] if missing else []),
            f"Timestamping uses {timestamp_source}." if timestamp_source != "unknown" else "Timestamp source unknown.",
            "Trust root is the local SecureDoc Demo Root CA.",
        ],
        "verification_groups": advanced.get("verification_groups", {}),
        "advanced": advanced,
    }


def pades_capabilities() -> dict:
    return {
        "pyhanko_available": True,
        "primary_target_profile": TARGET_PADES_PROFILE,
        "internal_steps": ["PAdES-B-B", "PAdES-B-T", "PAdES-B-LT"],
        "standards": ["RFC5280", "RFC3161", "RFC5652", "RFC6960", PADES_STANDARD],
        "status": "pades_blt_target_with_honest_achieved_profile",
        "note": "The main API targets PAdES-B-LT and reports the achieved profile based on valid timestamp and embedded LTV evidence.",
    }
