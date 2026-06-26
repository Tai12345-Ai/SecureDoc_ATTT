# V5 Standardization Plan — SecureDoc ATTT

## Summary

V5 standardization pass improves SecureDoc across 8 areas while maintaining educational demo status and honest reporting.

## Changes

### 1. Digest Selection Per Signing Request

- `AlgorithmPolicy` extended with SHA-3 experimental digests (SHA3-256, SHA3-384, SHA3-512).
- PAdES-compatible digests: SHA-256, SHA-384, SHA-512.
- SHA-3 available for canonical payload / advanced digest demo only.
- SHA-3 is NOT enabled for PAdES/PDF signing — `sign_pdf_request()` rejects experimental digests.
- MD5/SHA-1 remain disallowed.
- Digest selection stored per signing request; verification recomputes hash using declared digest.
- Frontend dropdown with 6 options + experimental warnings.

### 2. Revocation Serial Validation

- `_validate_decimal_serial()` ensures only decimal digit strings enter the revocation registry.
- Applied to `revoke()`, `status()`, `status_at()`.
- `generate_signed_crl()` gracefully skips legacy invalid serial records, reports `skipped_invalid_record_count` and `skipped_invalid_serials`.
- Routes return HTTP 400 for invalid serials.

### 3. Timestamp Standardization

- Config: `tsa_mode` ("dummy" or "external"), `tsa_url`, `tsa_timeout`.
- External mode: pyHanko `HTTPTimeStamper` for real RFC3161 TSA.
- Dummy mode: pyHanko `DummyTimeStamper` (default, demo).
- Reports `timestamp_source` clearly: `"dummy_rfc3161_token"` or `"external_rfc3161_tsa"`.
- Reports `production_tsa: true/false`.
- JSON demo timestamp service clarified as not RFC3161 TimeStampToken.

### 4. OCSP Request Parsing

- Binary OCSP endpoint parses `application/ocsp-request` using `load_der_ocsp_request`.
- Extracts requested serial number from the OCSP request.
- Looks up certificate across lifecycle records and bootstrap demo cert.
- Returns OCSP response for the specific certificate, not just active signer.
- Unknown serial returns HTTP 400.
- `/ocsp-demo` remains JSON debug endpoint.

### 5. Remote PDF/PAdES Signing

- New endpoint: `POST /api/remote-signing/sign-pdf`.
- Requires: confirmed request + demo MFA + active certificate + PDF document.
- Calls `sign_pdf_request()` server-side with demo backend key.
- Reports key custody honestly: `DEMO_BACKEND_KEY`, `privateKeyExposed = false`.
- Existing canonical payload remote signing preserved.

### 6. Verification Report Standard-Status

- PDF verification report includes: `target_profile`, `achieved_profile`, `missing_requirements`, `digest_algorithm`, `signature_algorithm`, `timestamp_source`, `production_tsa`, `revocation_evidence_status`, `ocsp_mode`, `legal_ready`.
- PAdES-B-LT claimed only when timestamp valid + DSS evidence present.
- Frontend `VerificationSummary` displays all standard fields.

### 7. Documentation

- README updated with digest policy table, timestamp modes, revocation fixes, remote signing, OCSP parsing.
- This V5 plan document created.

### 8. Testing

- Tests added for: digest policy (SHA-3, MD5/SHA1 rejection), PAdES SHA-3 rejection, revocation serial validation, CRL with dirty records, timestamp source fields, OCSP serial parsing, remote PDF signing, verification standard fields.

## What Remains Demo / Not Production

- Local demo CA — not public trusted.
- No HSM/KMS — private key in file on backend.
- JSON file storage — not database.
- DummyTimeStamper default — not external TSA.
- OCSP uses simplified certificate store.
- Legal readiness is always `false`.
- Blind signature: no Cashu compliance, no RFC9474 test vectors.
- SHA-3: experimental only, not for PAdES.
