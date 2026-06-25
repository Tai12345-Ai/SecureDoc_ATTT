from pydantic import BaseModel
from typing import Any, Dict, List, Optional

class CheckItem(BaseModel):
    key: str
    label: str
    ok: bool
    message: str

class CertificateView(BaseModel):
    serial: str
    subject: str
    issuer: str
    status: str
    valid_from: str
    valid_to: str
    public_key_algorithm: str
    public_key_size: int
    certificate_signature_algorithm: str
    document_signature_algorithm: str
    digest_algorithm: str
    key_usage: List[str]
    certificate_profile: str
    standards: List[str]

class CertificateEnrollmentRequest(BaseModel):
    display_name: str
    email: str
    public_key_pem: str
    proof_signature_base64: str
    proof_challenge: Optional[str] = None

class CertificateStatusView(BaseModel):
    serial: str
    lifecycle_status: str
    revocation_status: str
    effective_status: str
    revoked: bool
    profile_id: str
    profile_validation: Dict[str, Any]
    subject: str
    issuer: str
    valid_from: str
    valid_to: str
    key_source: str
    certificate_origin: str
    is_bootstrap_demo_certificate: bool
    source: str
    warning: str

class SigningPrepareView(BaseModel):
    request_id: str
    document_name: str
    document_hash: str
    hash_algorithm: str
    certificate_serial: str
    signing_purpose: str
    nonce: str
    next_action: str
    advanced: Dict[str, Any]

class SigningResultView(BaseModel):
    request_id: str
    status: str
    title: str
    message: str
    checks: List[CheckItem]
    legal_ready: bool
    warnings: List[str]
    verification_groups: Optional[Dict[str, Any]] = None
    advanced: Dict[str, Any]

class PipelineStep(BaseModel):
    id: str
    title: str
    user_explanation: str
    technical_explanation: str
    service: str
    artifacts: List[str]

class BlindSignatureResult(BaseModel):
    title: str
    message: str
    target_scheme: str
    achieved_scheme: str
    scheme_complete: bool
    production_ready: bool
    blind_signature_valid: bool
    key_id: str
    token_hash: str
    spent_status: str
    warnings: List[str]
    steps: List[Dict[str, Any]]
    verified: bool
    unlinkability_note: str
    advanced: Dict[str, Any]
