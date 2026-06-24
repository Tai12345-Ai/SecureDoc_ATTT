from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.routes_pipeline import router as pipeline_router
from app.api.routes_user_signing import router as user_signing_router
from app.api.routes_certificates import router as certificate_router
from app.api.routes_blind_signature import router as blind_router
from app.api.routes_audit import router as audit_router
from app.api.routes_verification import router as verification_router
from app.api.routes_timestamp import router as timestamp_router
from app.api.routes_revocation import router as revocation_router
from app.api.routes_key_enrollment import router as key_enrollment_router
from app.api.routes_remote_signing import router as remote_signing_router

app = FastAPI(
    title="SecureDoc Full Demo v4",
    description="Educational end-to-end digital signature demo: PKI, X.509, signing protocol, PAdES boundary, timestamp, audit, blind signature.",
    version="0.4.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(pipeline_router, prefix="/api/pipeline", tags=["Pipeline Demo"])
app.include_router(user_signing_router, prefix="/api/user-signing", tags=["User Signing"])
app.include_router(certificate_router, prefix="/api/certificates", tags=["Certificates"])
app.include_router(blind_router, prefix="/api/blind-signature", tags=["Blind Signature"])
app.include_router(audit_router, prefix="/api/audit", tags=["Audit"])
app.include_router(verification_router, prefix="/api/verification", tags=["Verification"])
app.include_router(timestamp_router, prefix="/api/timestamp", tags=["Timestamp"])
app.include_router(revocation_router, prefix="/api/revocation", tags=["Revocation"])
app.include_router(key_enrollment_router, prefix="/api/key-enrollment", tags=["Key Enrollment"])
app.include_router(remote_signing_router, prefix="/api/remote-signing", tags=["Remote Signing"])

@app.get("/api/health")
def health():
    return {
        "status": "ok",
        "service": "SecureDoc Full Demo v4",
        "modes": [
            "pipeline",
            "user-signing",
            "certificate-lifecycle",
            "security-services",
            "blind-signature",
        ],
    }
