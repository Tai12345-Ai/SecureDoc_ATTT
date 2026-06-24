# SecureDoc Full Test Guide

## 0. Setup

Open two terminals.

Backend:

```powershell
cd securedoc_full_demo_v4
.\.venv\Scripts\activate
pip install -r requirements.txt
cd backend
$env:PYTHONPATH="."
uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```

Frontend:

```powershell
cd securedoc_full_demo_v4\frontend
npm install
npm run dev
```

Open:

```text
http://localhost:5173
```

## 1. Build and unit tests

```powershell
cd frontend
npm install
npm run build
```

```powershell
cd ..\backend
$env:PYTHONPATH="."
python -m pytest -q
```

Expected: frontend build passes and backend tests pass.

## 2. Test A - User Signing happy path

Input PDF:

```text
pdfs/01_contract_basic_unsigned.pdf
```

Steps:

1. Open `User Signing`.
2. Check active certificate is loaded.
3. Upload `01_contract_basic_unsigned.pdf`.
4. Click `Tạo yêu cầu ký`.
5. Click `Xác nhận OTP/TOTP`.
6. Click `Ký PDF/PAdES`.
7. Download the signed PDF.
8. Use `Verify another signed PDF` to verify the downloaded file.

Expected:

```text
- PDF signed PAdES-B-B.
- Verification accepted.
- legal_ready = false.
- Warnings mention demo CA, no RFC3161, no real OCSP/CRL/HSM.
```

## 3. Test B - Multi-page PDF signing

Input PDF:

```text
pdfs/02_contract_multipage_unsigned.pdf
```

Repeat Test A.

Expected: accepted signed PDF, document coverage indicates the signed document is protected.

## 4. Test C - Invoice/table PDF signing

Input PDF:

```text
pdfs/03_invoice_table_unsigned.pdf
```

Repeat Test A.

Expected: accepted signed PDF.

## 5. Test D - Unicode/text PDF signing

Input PDF:

```text
pdfs/04_unicode_text_unsigned.pdf
```

Repeat Test A.

Expected: accepted signed PDF. Text rendering is not important for cryptography; the PDF bytes are hashed and signed.

## 6. Test E - Minimal smoke PDF

Input PDF:

```text
pdfs/05_minimal_smoke_unsigned.pdf
```

Use this when you only want a quick signing sanity check.

Expected: accepted signed PDF.

## 7. Test F - Invalid fake PDF rejection

Input file:

```text
pdfs/06_fake_pdf_extension_should_reject.pdf
```

Steps:

1. Open `User Signing`.
2. Upload this fake PDF.
3. Prepare and confirm if the frontend accepts it.
4. Try `Ký PDF/PAdES`.

Expected:

```text
- Backend rejects it.
- Error should be similar to: Input file is not a PDF.
```

## 8. Test G - Tampered signed PDF should fail

Steps:

1. First sign any valid PDF, e.g. `01_contract_basic_unsigned.pdf`.
2. Download the signed PDF.
3. Run:

```powershell
python scripts\tamper_signed_pdf.py path\to\downloaded_signed.pdf
```

4. In `User Signing`, use `Verify another signed PDF` and upload the generated `_tampered.pdf`.

Expected:

```text
- Verification is not accepted.
- Report shows crypto/coverage/document integrity failure.
```

## 9. Test H - Unsigned PDF should fail verification

Input PDF:

```text
pdfs/01_contract_basic_unsigned.pdf
```

Steps:

1. Open `User Signing`.
2. Go to `Verify another signed PDF`.
3. Upload the original unsigned PDF.
4. Click `Verify PDF`.

Expected:

```text
- Verification is not accepted.
- Report says no embedded PDF signature.
```

## 10. Test I - Certificate lifecycle and revocation

Steps:

1. Open `CA / Certificate Lifecycle`.
2. Enroll/issue/activate certificate if needed.
3. Copy the active certificate serial.
4. Open `Trust & Key Services`.
5. Paste serial into Revocation Service.
6. Click `Check status`.
7. Click `Revoke serial`.
8. Check status again.
9. Return to `User Signing` and try preparing a new request with the revoked certificate.

Expected:

```text
- Before revoke: good/active.
- After revoke: revoked.
- New signing request with revoked certificate is rejected.
```

## 11. Test J - Timestamp service

Steps:

1. Open `User Signing`.
2. Upload a valid PDF and click `Tạo yêu cầu ký`.
3. Copy the full `document_hash` from Advanced Details.
4. Open `Trust & Key Services`.
5. Paste the hash into `Message imprint SHA-256`.
6. Click `Issue signed timestamp`.
7. Click `Verify timestamp`.

Expected:

```text
- Signed demo TSA token is issued.
- Verification is OK.
- UI/documentation still says this is not RFC3161.
```

## 12. Test K - Browser local key enrollment

Steps:

1. Open `Trust & Key Services`.
2. Click `Generate browser key`.
3. Click `Request challenge`.
4. Click `Submit proof`.
5. Check Advanced Details.

Expected:

```text
- Backend receives only public key + proof-of-possession.
- Certificate can be issued/activated.
- Private key is not exported to backend.
```

## 13. Test L - Remote signing

Steps:

1. Open `User Signing`.
2. Use a backend demo signing certificate.
3. Upload PDF, prepare request, confirm intent.
4. Copy request ID.
5. Open `Trust & Key Services`.
6. Paste request ID into Remote Signing.
7. Click `Remote sign`.

Expected:

```text
- Demo MFA 000000 is used internally.
- Remote signing policy check passes.
- Result contains privateKeyExposed=false.
```

## 14. Test M - Blind signature

Steps:

1. Open `Blind Signature`.
2. Run the demo with a token/message.
3. Check the steps: blind -> sign blinded -> unblind -> verify.

Expected:

```text
- Unblinded signature verifies.
- UI explains unlinkability.
```

## 15. Test N - End-to-End Pipeline walkthrough

Steps:

1. Open `End-to-End Pipeline`.
2. Click each timeline step.
3. Confirm each step shows actor, artifact and baseline.
4. Click `Run full pipeline`.

Expected:

```text
- Page works as educational walkthrough, not primary operation UI.
- Full pipeline result shows verification checks and advanced artifacts.
```

## 16. Final acceptance checklist

```text
[ ] npm run build passes.
[ ] pytest passes.
[ ] Valid PDF signing accepted.
[ ] Multi-page PDF signing accepted.
[ ] Unsigned PDF verification rejected.
[ ] Tampered signed PDF verification rejected.
[ ] Fake PDF rejected.
[ ] Certificate revoke blocks new signing request.
[ ] Timestamp issue/verify works.
[ ] Browser key enrollment works.
[ ] Remote signing works.
[ ] Blind signature works.
[ ] End-to-End Pipeline explains actor/artifact/baseline.
[ ] UI/docs never claim legal_ready=true.
```
