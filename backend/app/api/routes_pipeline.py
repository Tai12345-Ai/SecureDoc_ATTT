from fastapi import APIRouter
from app.domain.schemas import PipelineStep
from app.services.pki_service import init_demo_pki, describe_demo_pki
from app.services.signing_service import prepare_request, confirm_intent, sign_and_verify
from app.services.pades_service import pades_capabilities
from app.services.audit_service import append_event
from app.services.certificate_lifecycle_service import create_demo_backend_enrollment, get_certificate_status

router = APIRouter()

STEPS = [
    PipelineStep(
        id="digital-signature-overview",
        title="Chữ ký số",
        user_explanation="Chữ ký số giúp xác minh ai ký, nội dung có bị sửa không và hỗ trợ chống chối bỏ.",
        technical_explanation="Ký hash/canonical payload bằng private key; verify bằng public key trong certificate.",
        service="Signing Service + Verification Service",
        artifacts=["documentHash", "signature", "certificate", "verificationReport"],
    ),
    PipelineStep(
        id="mechanisms",
        title="Cơ chế tạo chữ ký số",
        user_explanation="Hệ thống băm tài liệu, tạo payload chuẩn hóa, xác nhận ý chí ký rồi mới ký.",
        technical_explanation="SHA-256(document), canonical JSON, nonce, RSA-PSS-SHA256 signature.",
        service="Signing Service",
        artifacts=["sha256", "canonicalPayload", "nonce", "signatureBase64"],
    ),
    PipelineStep(
        id="protocol",
        title="Giao thức chữ ký số",
        user_explanation="Người dùng không ký trực tiếp dữ liệu tự do; mọi bước đi qua signing request.",
        technical_explanation="prepare → confirm intent → sign → submit/verify → report.",
        service="Signing Protocol Controller",
        artifacts=["requestId", "intentConfirmation", "signedPackage"],
    ),
    PipelineStep(
        id="services",
        title="Các dịch vụ chữ ký số",
        user_explanation="Các service tách riêng như DSS/SignServer: CA, signing, verification, timestamp, audit.",
        technical_explanation="PKI Service, Certificate Service, Signing Service, Verification Service, Timestamp Service, Audit Service.",
        service="Service Architecture",
        artifacts=["certificateChain", "timestampToken", "auditHashChain"],
    ),
    PipelineStep(
        id="blind-signature",
        title="Chữ ký mù",
        user_explanation="Dùng khi cần ẩn danh: signer ký nhưng không biết nội dung gốc.",
        technical_explanation="blind(m) → sign(blinded m) → unblind(sig) → verify(m, sig).",
        service="Blind Signature Service",
        artifacts=["blindedToken", "blindSignature", "unblindedSignature"],
    ),
    PipelineStep(
        id="applications",
        title="Ứng dụng",
        user_explanation="Ký hợp đồng PDF, ký hồ sơ, ký container tài liệu, timestamp, privacy token.",
        technical_explanation="PAdES/PDF via pyHanko boundary, ASiC/XAdES reference via DSS/DigiDoc, blind token inspired by Cashu.",
        service="Application Layer",
        artifacts=["signedDocument", "validationReport", "privacyToken"],
    ),
]

@router.get("/steps")
def steps():
    return [s.model_dump() for s in STEPS]

@router.get("/steps/{step_id}")
def step_detail(step_id: str):
    step = next((s for s in STEPS if s.id == step_id), None)
    if not step:
        return {"error": "unknown step"}
    return {
        "step": step.model_dump(),
        "thinking_panel": {
            "what_user_sees": step.user_explanation,
            "what_system_does": step.technical_explanation,
            "service_boundary": step.service,
            "artifacts": step.artifacts,
        },
    }

@router.post("/run-full")
def run_full_pipeline():
    pki = init_demo_pki()
    lifecycle_cert = create_demo_backend_enrollment(activate=True)
    document = b"SecureDoc v4 demo contract"
    cert_serial = lifecycle_cert["serial"]
    prepared = prepare_request("demo_contract.txt", document, "Ky xac nhan hop dong demo", cert_serial)
    confirm = confirm_intent(prepared["request_id"])
    result = sign_and_verify(prepared["request_id"])
    pades = pades_capabilities()
    audit = append_event("system", "run_full_pipeline", prepared["request_id"], "ok")

    return {
        "title": "Full digital signature pipeline completed",
        "summary": "PKI, X.509 certificate, signing request, intent confirmation, signature, verification, timestamp and audit were executed.",
        "pki": pki,
        "certificateLifecycle": {
            "issued_certificate": lifecycle_cert,
            "status": get_certificate_status(cert_serial),
        },
        "prepared": prepared,
        "confirmation": confirm,
        "result": result,
        "padesAdapter": pades,
        "audit": audit,
    }
