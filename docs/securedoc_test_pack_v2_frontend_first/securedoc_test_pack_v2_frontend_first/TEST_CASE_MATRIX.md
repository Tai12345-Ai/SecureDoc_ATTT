# SecureDoc_ATTT test case matrix

Base URL: `http://127.0.0.1:8000`

Important dynamic values:
- `SERIAL`: certificate serial returned by `/api/certificates/my-active` or `/api/certificates/enroll-demo-backend-key?activate=true`.
- `REQ_ID`: request id returned by `/api/user-signing/prepare`.
- `FILE_ID`: PDF file id returned by `/api/user-signing/sign-pdf` or `/api/remote-signing/sign-pdf`.

## A. Smoke and service availability

### TC-A01 Health check
Input: none.
Steps:
1. `GET /api/health`.
Expected:
- HTTP 200.
- JSON contains `status="ok"`, `service="SecureDoc Full Demo v4"`, and modes including `user-signing`, `certificate-lifecycle`, `blind-signature`.

### TC-A02 Pipeline metadata
Input: none.
Steps:
1. `GET /api/pipeline/steps`.
Expected:
- HTTP 200.
- List contains step ids such as `digital-signature-overview`, `mechanisms`, `protocol`, `services`, `blind-signature`, `applications`.

### TC-A03 Run full demo pipeline
Input: none.
Steps:
1. `POST /api/pipeline/run-full`.
Expected:
- HTTP 200.
- `title="Full digital signature pipeline completed"`.
- Contains `pki`, `certificateLifecycle`, `prepared`, `confirmation`, `result`, `audit`.
- `result.accepted=true` for canonical package.

## B. Certificate lifecycle and PKI

### TC-B01 Init demo PKI
Input: `force=true` optional.
Steps:
1. `POST /api/certificates/init-demo-pki?force=true`.
Expected:
- HTTP 200.
- Demo PKI artifacts are created.

### TC-B02 Issue active demo backend certificate
Input: none.
Steps:
1. `POST /api/certificates/enroll-demo-backend-key?activate=true`.
Expected:
- HTTP 200.
- Response contains `serial`, `status="active"`, `key_source="DEMO_BACKEND_KEY"`.

### TC-B03 Read active certificate
Input: none.
Steps:
1. `GET /api/certificates/my-active`.
Expected:
- HTTP 200 if an active cert exists.
- Subject is Alice Demo Signer or same active certificate identity.
- Contains key custody fields.
Negative expectation:
- If no active cert exists, HTTP 404 with `detail="No active certificate"`.

### TC-B04 Certificate status
Input: `SERIAL`.
Steps:
1. `GET /api/certificates/{SERIAL}/status`.
Expected:
- HTTP 200.
- `effective_status="active"` for signing tests.
- `profile_validation.valid=true`.

### TC-B05 Certificate chain
Input: `SERIAL`.
Steps:
1. `GET /api/certificates/chain/{SERIAL}`.
Expected:
- HTTP 200.
- `chain` has user cert, intermediate CA, root CA.

### TC-B06 Revoke certificate and prevent new signing
Input: `SERIAL`.
Steps:
1. `POST /api/certificates/{SERIAL}/revoke`.
2. `GET /api/certificates/{SERIAL}/status`.
3. Try `POST /api/user-signing/prepare` using this `SERIAL`.
Expected:
- Step 1/2: effective status becomes `revoked`.
- Step 3: HTTP 400, detail includes certificate not active/good.
Cleanup:
- Recreate active demo cert with TC-B02 before later signing tests.

## C. User signing - canonical payload

### TC-C01 Prepare canonical request with SHA-256
Input file: `inputs/04_plain_text_for_canonical_payload.txt`; purpose `Ky xac nhan tai lieu text`; digest `sha256`; active `SERIAL`.
Steps:
1. `POST /api/user-signing/prepare` multipart form.
Expected:
- HTTP 200.
- Response contains `request_id`, `document_hash`, `hash_algorithm="SHA-256"`, `next_action="confirm_signing_intent"`.
- `advanced.canonical_payload` binds `requestId`, `documentHash`, `certificateSerial`, `signingPurpose`, `nonce`.

### TC-C02 Confirm signing intent
Input: `REQ_ID` from TC-C01.
Steps:
1. `POST /api/user-signing/confirm?request_id={REQ_ID}`.
Expected:
- HTTP 200.
- `confirmed=true`, `method="DEMO_OTP"`.

### TC-C03 Sign and verify canonical request
Input: confirmed `REQ_ID`.
Steps:
1. `POST /api/user-signing/sign-and-verify?request_id={REQ_ID}`.
Expected:
- HTTP 200.
- `accepted=true`, `status="accepted"`.
- Checks include cryptographic signature valid, document hash valid, context bound, certificate chain valid, timestamp valid, revocation valid.
- `advanced.signed_package.signatureAlgorithm="RSA-PSS"`.

### TC-C04 Reject signing before intent confirmation
Input: new prepared request id not confirmed.
Steps:
1. Prepare request.
2. Immediately `POST /api/user-signing/sign-and-verify?request_id={REQ_ID}`.
Expected:
- HTTP 400.
- detail includes `Signing intent has not been confirmed`.

### TC-C05 Reject double signing same request
Input: `REQ_ID` already signed in TC-C03.
Steps:
1. Call `POST /api/user-signing/sign-and-verify?request_id={REQ_ID}` again.
Expected:
- HTTP 400.
- detail includes `Signing request has already been signed`.

### TC-C06 SHA3 accepted for canonical payload demo
Input file: `inputs/04_plain_text_for_canonical_payload.txt`; digest `sha3-256`.
Steps:
1. Prepare, confirm, sign-and-verify canonical request.
Expected:
- Prepare returns `hash_algorithm="SHA3-256"` and `advanced.digest_policy.is_experimental=true`.
- Canonical sign-and-verify can be accepted.

### TC-C07 Reject MD5/SHA-1 digest
Input: same text file; digest `md5` or `sha1`.
Steps:
1. `POST /api/user-signing/prepare`.
Expected:
- HTTP 400.
- detail includes `Digest algorithm is disallowed`.

## D. PDF/PAdES signing and verification

### TC-D01 Prepare PDF signing request
Input file: `inputs/01_contract_basic_unsigned.pdf`; purpose `Ky hop dong demo`; digest `sha256`; active `SERIAL`.
Steps:
1. `POST /api/user-signing/prepare`.
2. `POST /api/user-signing/confirm?request_id={REQ_ID}`.
Expected:
- Prepare HTTP 200; hash algorithm `SHA-256`.
- Confirm HTTP 200; `confirmed=true`.

### TC-D02 Sign PDF PAdES
Input: confirmed PDF `REQ_ID`.
Steps:
1. `POST /api/user-signing/sign-pdf?request_id={REQ_ID}`.
Expected:
- HTTP 200.
- Response contains `file_id`, `download_url`, `metadata`, `verification`.
- `metadata.target_profile="PAdES-B-LT"`.
- `metadata.signature_algorithm="RSA-PSS"`.
- `verification.accepted=true` if pyHanko validation succeeds.
- `verification.legal_ready=false` because this is demo CA.

### TC-D03 Download signed PDF
Input: `FILE_ID` from TC-D02.
Steps:
1. `GET /api/user-signing/signed-files/{FILE_ID}`.
Expected:
- HTTP 200.
- Content-Type PDF.
- Save file to `outputs/signed_01_contract.pdf`.

### TC-D04 Verify downloaded signed PDF independently
Input file: `outputs/signed_01_contract.pdf`.
Steps:
1. `POST /api/verification/verify-pdf` multipart form.
Expected:
- HTTP 200.
- `accepted=true`, `status="accepted"`.
- Checks include `signature_present=true`, `crypto_valid=true`, `document_integrity_valid=true`, `certificate_trusted=true`.
- `target_profile="PAdES-B-LT"`; `achieved_profile` may be B-LT or lower depending on embedded LTV evidence.

### TC-D05 Verify signed file by server file id
Input: `FILE_ID`.
Steps:
1. `POST /api/verification/verify-signed-file/{FILE_ID}`.
Expected:
- HTTP 200.
- Same style verification report as TC-D04.

### TC-D06 Tamper signed PDF and verify rejection
Input file: signed PDF from TC-D03.
Steps:
1. Run `python scripts/tamper_pdf.py outputs/signed_01_contract.pdf outputs/signed_01_contract_tampered.pdf`.
2. `POST /api/verification/verify-pdf` with tampered PDF.
Expected:
- HTTP 200 or 400 depending parser outcome.
- Verification must not be accepted: `accepted=false` or error detail indicates PDF/signature check failed.
- This is the key integrity attack test.

### TC-D07 Reject non-PDF for PAdES signing
Input file: `inputs/04_plain_text_for_canonical_payload.txt`.
Steps:
1. Prepare and confirm request.
2. `POST /api/user-signing/sign-pdf?request_id={REQ_ID}`.
Expected:
- HTTP 400.
- detail includes `Input file is not a PDF` or `Could not sign PDF`.

### TC-D08 Reject empty upload
Input file: `inputs/05_empty_file.pdf`.
Steps:
1. `POST /api/user-signing/prepare`.
Expected:
- HTTP 400.
- detail `Empty file`.

### TC-D09 Reject SHA3 for PAdES
Input file: `inputs/01_contract_basic_unsigned.pdf`; digest `sha3-256`.
Steps:
1. Prepare and confirm.
2. `POST /api/user-signing/sign-pdf?request_id={REQ_ID}`.
Expected:
- HTTP 400.
- detail includes `experimental and not enabled for PAdES signing`.

### TC-D10 SHA-384 and SHA-512 PAdES variants
Input file: `inputs/02_contract_two_pages_unsigned.pdf`; digest `sha384`, then `sha512` in a separate fresh request.
Steps:
1. Prepare, confirm, sign-pdf.
2. Verify output.
Expected:
- HTTP 200 for signing and verification.
- Metadata reports `digest_algorithm="SHA-384"` or `"SHA-512"`.

## E. Timestamp service

### TC-E01 Issue demo timestamp for SHA-256 imprint
Input: 64 hex chars, e.g. `aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa`.
Steps:
1. `POST /api/timestamp/issue` JSON body `{ "message_imprint_sha256": "aaaa..." }`.
Expected:
- HTTP 200.
- Token contains `tokenType="SECUREDOC_DEMO_TSA_TOKEN_V1"`, `messageImprintSha256`, `genTime`, `signatureBase64`.
- Warning says production requires RFC3161 TimeStampToken.

### TC-E02 Verify timestamp success
Input: token from TC-E01 and same imprint.
Steps:
1. `POST /api/timestamp/verify` with token and expected imprint.
Expected:
- HTTP 200.
- `ok=true`, `trusted=true`, `checks.imprintMatches=true`, `checks.tsaSignatureValid=true`.

### TC-E03 Verify timestamp imprint mismatch
Input: token from TC-E01 and different 64-char hex imprint.
Steps:
1. `POST /api/timestamp/verify`.
Expected:
- HTTP 200.
- `ok=false`, `trusted=true`, `checks.imprintMatches=false`.

### TC-E04 Reject invalid timestamp imprint
Input: `xyz` or too-short hex.
Steps:
1. `POST /api/timestamp/issue`.
Expected:
- HTTP 400.
- detail says imprint must be valid hex or unexpected length.

## F. Revocation, CRL, OCSP debug

### TC-F01 Check revocation status good
Input: active `SERIAL`.
Steps:
1. `GET /api/revocation/status/{SERIAL}`.
Expected:
- HTTP 200.
- Status indicates good/not revoked.

### TC-F02 CRL JSON and PEM/DER generation
Input: none.
Steps:
1. `GET /api/revocation/crl`.
2. `GET /api/revocation/crl.pem`.
3. `GET /api/revocation/crl.der`.
Expected:
- HTTP 200.
- JSON debug view for `/crl`.
- PEM/DER endpoints return CRL data with correct media types.

### TC-F03 Revoke through revocation service
Input: `SERIAL`.
Steps:
1. `POST /api/revocation/revoke/{SERIAL}?reason=cessationOfOperation`.
2. `GET /api/revocation/status/{SERIAL}`.
3. `GET /api/revocation/ocsp-demo`.
Expected:
- Revocation status becomes revoked.
- OCSP debug reflects revoked state for active/current certificate if applicable.
Cleanup:
- Re-issue active cert before signing tests.

### TC-F04 Reject unknown serial in revocation status
Input: serial `999999999999999999` or invalid `hh`.
Steps:
1. `GET /api/revocation/status/hh`.
Expected:
- HTTP 400.
- detail indicates invalid/unknown serial.

## G. Remote signing

### TC-G01 Remote sign canonical request with MFA
Input: text file request prepared and confirmed; MFA `000000`.
Steps:
1. Prepare with `inputs/04_plain_text_for_canonical_payload.txt`.
2. Confirm.
3. `POST /api/remote-signing/sign` JSON `{ "request_id": "REQ_ID", "mfa_code": "000000" }`.
Expected:
- HTTP 200.
- `remote_signing.policy="confirmed_intent + demo_mfa + active_certificate"`.
- `report.accepted=true`.

### TC-G02 Reject wrong MFA
Input: confirmed request; MFA `123456`.
Steps:
1. `POST /api/remote-signing/sign`.
Expected:
- HTTP 400.
- detail `Invalid demo MFA code`.

### TC-G03 Remote sign PDF
Input: PDF request prepared and confirmed; MFA `000000`.
Steps:
1. Prepare with `inputs/03_invoice_unsigned.pdf`.
2. Confirm.
3. `POST /api/remote-signing/sign-pdf` JSON `{ "request_id": "REQ_ID", "mfa_code": "000000" }`.
Expected:
- HTTP 200.
- Response contains `file_id`, `download_url`, `metadata`, `verification`, `remote_signing`.
- Verification accepted if pyHanko validation succeeds.

### TC-G04 Reject remote PDF signing for non-PDF
Input: text request confirmed; MFA `000000`.
Steps:
1. Prepare and confirm text file.
2. `POST /api/remote-signing/sign-pdf`.
Expected:
- HTTP 400.
- detail `Document is not a PDF. Remote PDF signing requires a PDF file.`

## H. Key enrollment and client-side key custody

### TC-H01 Create key enrollment challenge
Input: RSA public key PEM from a locally generated test key.
Steps:
1. Generate local RSA keypair.
2. `POST /api/key-enrollment/challenge` with `display_name`, `email`, `public_key_pem`.
Expected:
- HTTP 200.
- Response contains `challenge_id`, `challenge`, `expires_in_seconds=300`, `replay_protection="single_use_challenge_id"`.

### TC-H02 Submit proof-of-possession and issue client certificate
Input: sign challenge bytes with local private key using RSA-PSS SHA-256; submit base64 signature.
Steps:
1. `POST /api/key-enrollment/submit-public-key` with `challenge_id`, `proof_signature_base64`, `issue_certificate=true`, `activate_certificate=true`.
Expected:
- HTTP 200.
- Response contains `enrollment.proof_verified=true` and `certificate.key_source="CLIENT_SIDE_KEY"`.

### TC-H03 Backend must refuse to sign with CLIENT_SIDE_KEY
Input: active client-side certificate serial.
Steps:
1. Prepare and confirm PDF request using client-side cert.
2. Call `/api/user-signing/sign-pdf`.
Expected:
- HTTP 400.
- detail says backend cannot sign PDF with client-side private key custody.

### TC-H04 Client-side PAdES prepare requires client-side cert
Input: PDF request using client-side cert.
Steps:
1. Prepare and confirm.
2. `POST /api/user-signing/client-pades/prepare?request_id={REQ_ID}`.
Expected:
- HTTP 200.
- Response contains `signed_attributes_base64`, `signed_attributes_sha256`, `signature_algorithm="RSA-PSS"`, `next_action="sign_signed_attributes_with_client_private_key"`.

### TC-H05 Client-side PAdES finalize with invalid signature
Input: `REQ_ID`, bogus `signature_base64`.
Steps:
1. Call `/api/user-signing/client-pades/finalize` with invalid signature.
Expected:
- HTTP 400.
- detail `Client PDF signature does not verify against certificate public key`.

## I. Blind signature

### TC-I01 Blind signer info
Input: none.
Steps:
1. `GET /api/blind-signature/signer-info`.
Expected:
- HTTP 200.
- Contains `key_id`, `public_key_algorithm="RSA"`, `scheme="RSABSSA-SHA384-PSS-Randomized"`, `purpose="blind-signature-only"`.

### TC-I02 Educational all-in-one blind signature flow
Input: JSON `{ "message": "privacy-token-demo-001" }`.
Steps:
1. `POST /api/blind-signature/run`.
Expected:
- HTTP 200.
- `blind_signature_valid=true`, `verified=true`, `redeemed=true`, `spent_status="spent"` unless token hash was already spent.
- `production_ready=false`, `compliance_status="not_test_vector_verified"`.

### TC-I03 Reject empty blind signature message
Input: JSON `{ "message": "" }`.
Steps:
1. `POST /api/blind-signature/run`.
Expected:
- HTTP 400.
- detail `message is required`.

### TC-I04 Blind-sign endpoint must not receive original token
Input: JSON includes `blinded_msg`, `key_id`, and forbidden `token` field.
Steps:
1. `POST /api/blind-signature/blind-sign`.
Expected:
- HTTP 400.
- detail says field `token` must not be sent.

### TC-I05 Redeem duplicate token
Input: token/signature from a valid blind flow.
Steps:
1. Redeem once.
2. Redeem same `token_hash` and signature again.
Expected:
- First: `accepted=true`, reason `redeemed`.
- Second: `accepted=false`, reason `already_spent`.

## J. Audit trail

### TC-J01 Audit events after core operations
Input: none.
Steps:
1. Run at least TC-C01..TC-C03 or TC-D01..TC-D02.
2. `GET /api/audit/events?limit=20`.
Expected:
- HTTP 200.
- Events include actions such as `prepare_signing_request`, `confirm_signing_intent`, `sign_and_verify`, `sign_pdf_pades_blt`, `remote_signing_policy_check`, or blind-signature events depending on tests run.

## K. UI checks

### TC-K01 User Signing Mode happy path
Input: `inputs/01_contract_basic_unsigned.pdf`.
Steps:
1. Open frontend `/` and User Signing Mode.
2. Click `Enroll + Issue demo cert` if no active cert.
3. Upload PDF, purpose text, digest SHA-256.
4. Create request, confirm OTP/TOTP, sign PDF PAdES-B-LT.
5. Download and verify.
Expected:
- Active certificate panel loads.
- Red `No active certificate` disappears after issuing cert.
- Signed PDF result shows accepted verification or explicit achieved-profile warnings.

### TC-K02 Trust & Key Services panels
Input: SHA-256 imprint `aaaaaaaa...`.
Steps:
1. Timestamp: issue and verify.
2. Revocation: status, CRL/OCSP debug.
3. Remote signing: use MFA `000000`.
Expected:
- Timestamp token is created and verified.
- Revocation status updates after revoke.
- Wrong MFA rejected; correct MFA accepted.

### TC-K03 Blind Signature Mode UI
Input: token `privacy-token-demo-001-UI`.
Steps:
1. Open Blind Signature Mode.
2. Run all-in-one demo.
Expected:
- UI shows Prepare, Blind, BlindSign, Finalize, Verify, Redeem/mark spent stages.
- It clearly states this is privacy token signing, not PDF signing.
