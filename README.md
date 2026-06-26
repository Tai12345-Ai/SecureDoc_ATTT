# SecureDoc Full Demo v4

Educational mini digital-signature system for an ATTT (Information Security) course. **This is not a legally trusted production signing system.**

## Two Independent Pipelines

### 1. Document Signing Pipeline

**Target:** PAdES-B-LT signed PDF.

**Technical standards:**

| Standard | Scope |
|----------|-------|
| RFC 5280 | X.509 certificates, CA profile, CRL, path validation |
| RFC 3161 | Timestamping |
| RFC 6960 | OCSP |
| RFC 5652 | CMS |
| ETSI EN 319 142-1 | PAdES baseline signatures |

The user-facing flow has one main signing action: **Sign PDF PAdES-B-LT**. B-B and B-T are internal building blocks only — they are not exposed as separate UI choices.

The system reports:
- `target_profile`: always PAdES-B-LT
- `achieved_profile`: PAdES-B-LT only when a valid signature timestamp + embedded validation evidence + DSS/LTV evidence are present and validated at demo level
- `missing_requirements`: explicit list when achieved ≠ target

### 2. Blind Signature Pipeline

**Completely separate from PDF/PAdES document signing.** This is for privacy token signing, not PDF signing.

**Target scheme:** RFC9474-RSABSSA (RSABSSA-SHA384-PSS-Randomized)

- Uses a **dedicated blind-signature-only key** — no reuse with CA, TSA, OCSP, user document-signing, or PAdES keys.
- Educational all-in-one demo is available, plus protocol-correct endpoints:
  - `GET /api/blind-signature/signer-info` — public key data for client
  - `POST /api/blind-signature/blind-sign` — server signs only blinded message
  - `POST /api/blind-signature/redeem` — verify + check spent registry
- **No Cashu compliance claim.** Cashu is mentioned only as a lifecycle reference.
- `compliance_status = not_test_vector_verified`
- `rfc9474_test_vectors_passed = false`
- `production_ready = false`

## Architecture

```text
frontend/
├── Pipeline Demo
├── User Signing
├── Certificate Lifecycle
└── Blind Signature

backend/
├── PKI Service          (RFC 5280)
├── Certificate Service
├── Signing Service
├── Verification Service
├── Timestamp Service    (RFC 3161)
├── Revocation Service   (RFC 5280/RFC 6960 CRL+OCSP)
├── Key Enrollment Service
├── Remote Signing Service
├── Audit Service
├── PAdES Adapter        (ETSI EN 319 142-1)
└── Blind Signature Service (RFC 9474)
```

## Key Custody Modes

SecureDoc now records key custody explicitly for each user certificate:

| Mode | Private key location | Backend can sign PDF/PAdES |
|------|----------------------|-----------------------------|
| `DEMO_BACKEND_KEY` | Backend demo storage | Yes, demo only |
| `CLIENT_SIDE_KEY` | Browser/user device/external client | No |
| `REMOTE_HSM_KEY` | HSM/KMS/remote signing service | Not implemented for PDF yet |

Certificates issued from a submitted public key are `CLIENT_SIDE_KEY` records:
the backend stores the public key and proof-of-possession result, but not the
private key. Backend PDF/PAdES signing rejects these certificates instead of
falling back to Alice's demo backend key.

More detail: [`docs/KEY_CUSTODY_AND_CERTIFICATE_LIFECYCLE.md`](docs/KEY_CUSTODY_AND_CERTIFICATE_LIFECYCLE.md).

## How to Run

### Requirements

- Python 3.11+
- Node.js 18 or 20+

### 1. Backend

```powershell
cd securedoc_full_demo_v4
python -m venv .venv
.\.venv\Scripts\activate
pip install -r requirements.txt
mkdir data
cd backend
$env:PYTHONPATH="."
uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```

API docs: http://127.0.0.1:8000/docs

### 2. Frontend

```bash
cd frontend
npm install
npm run dev
```

Frontend: http://localhost:5173

## CRL / OCSP / AIA Endpoints

Certificates advertise these endpoints in their extensions:

| Endpoint | Format | Media Type |
|----------|--------|------------|
| `GET /api/revocation/crl.der` | DER X.509 CRL | `application/pkix-crl` |
| `GET /api/revocation/crl.pem` | PEM X.509 CRL | `application/x-pem-file` |
| `POST /api/revocation/ocsp` | Binary OCSP endpoint (parses request) | `application/ocsp-response` |
| `GET /api/revocation/ocsp-demo` | JSON debug only | `application/json` |
| `GET /api/certificates/demo-pki/root.der` | DER certificate | `application/pkix-cert` |
| `GET /api/certificates/demo-pki/root.pem` | PEM certificate | `application/x-pem-file` |
| `GET /api/certificates/demo-pki/intermediate.der` | DER certificate | `application/pkix-cert` |
| `GET /api/certificates/demo-pki/intermediate.pem` | PEM certificate | `application/x-pem-file` |

The OCSP endpoint now parses binary OCSP requests using `cryptography.x509.ocsp.load_der_ocsp_request` to extract the requested serial number and generates a response for that specific certificate. If the serial is unknown, it returns HTTP 400.

## Demo Flow

### User Signing Mode

1. Load active certificate
2. Upload PDF
3. **Select digest algorithm** (SHA-256 default, SHA-384, SHA-512, or experimental SHA-3)
4. Prepare signing request (policy-controlled digest algorithm)
5. Confirm signing intent
6. **Sign PDF PAdES-B-LT** (single action targeting B-LT)
7. Download signed PDF
8. View verification report with target/achieved profile, timestamp source, and standard status fields
9. Verify another signed PDF independently

### Remote Signing Mode

1. Prepare and confirm a signing request
2. Provide demo MFA code (default: `000000`)
3. **Remote sign PDF** — server-side key with policy enforcement
4. Key custody: `DEMO_BACKEND_KEY`; production requires HSM/KMS

### Blind Signature Mode

**Protocol-correct flow:**
1. Client gets signer info → `GET /api/blind-signature/signer-info`
2. Client prepares/blinds token locally
3. Server blind-signs only blinded message → `POST /api/blind-signature/blind-sign`
4. Client unblinds/verifies locally
5. Verifier redeems → `POST /api/blind-signature/redeem`

**Educational demo:** `POST /api/blind-signature/run` runs the entire flow server-side for demonstration.

## Digest Algorithm Policy

The `AlgorithmPolicy` controls which digest algorithm is used:

| Category | Algorithms | PAdES Compatible |
|----------|-----------|-----------------|
| Default | SHA-256 | ✅ |
| Supported | SHA-384, SHA-512 | ✅ |
| Experimental | SHA3-256, SHA3-384, SHA3-512 | ❌ |
| Disallowed | MD5, SHA-1 | ❌ |

- **SHA-256** is the default and recommended for maximum PDF validator compatibility.
- **SHA-384/SHA-512** are fully supported for PAdES signing.
- **SHA-3** (SHA3-256/SHA3-384/SHA3-512) is available for canonical payload demo and advanced research. SHA-3 is NOT enabled for PAdES/PDF signing because most PDF validators do not support SHA-3 in CMS/PAdES signatures.
- **MD5/SHA-1** are disallowed and will be rejected.

## Timestamp Modes

| Mode | Description | Production |
|------|-------------|-----------|
| `dummy` (default) | pyHanko `DummyTimeStamper` with demo TSA certificate. Produces a valid RFC3161-like ASN.1 token but from a local demo CA. | No |
| `external` | pyHanko `HTTPTimeStamper` connecting to a real RFC3161 TSA service. Set `SECUREDOC_TSA_MODE=external` and `SECUREDOC_TSA_URL=https://...` | Closer to production |

The JSON demo timestamp service (`/api/timestamp/`) is a separate signed demo token (SECUREDOC_DEMO_TSA_TOKEN_V1) — it is NOT an RFC3161 TimeStampToken.

## Revocation

- **CRL**: Signed X.509 CRL (RFC 5280) generated from the demo revocation registry.
- **OCSP**: Binary OCSP endpoint (RFC 6960) that parses the OCSP request to extract the requested serial number.
- Serial validation: only decimal digit serials are accepted. Invalid serials like `"hh"` are rejected with a clear error.
- CRL generation gracefully skips legacy invalid serial records.

## Limitations

This is an educational demo, **not production-ready**:

- Local demo CA — not a public trusted CA.
- No HSM/KMS.
- Local/demo storage (JSON files, in-memory).
- Demo TSA uses pyHanko `DummyTimeStamper` by default; not an external production TSA service. External TSA mode available via config.
- OCSP endpoint parses binary OCSP requests but uses a simplified certificate store (lifecycle + bootstrap demo cert).
- PAdES verification uses SecureDoc Demo Root CA, not a public trust anchor.
- Legal readiness is always `false`.
- RFC 9474 test vectors are not implemented (`compliance_status = not_test_vector_verified`).
- Blind signature does NOT sign PDFs — it is a separate privacy token pipeline. No Cashu compliance claim.
- Signing history is in-memory; backend restart clears history.
- Certificate lifecycle uses JSON in `data/certificates`.
- Remote signing uses a demo backend key; production requires HSM/KMS/qualified service.
- SHA-3 digests are experimental and not enabled for PAdES signing.
