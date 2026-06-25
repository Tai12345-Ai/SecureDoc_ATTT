# SecureDoc ATTT - repo context for report

## 1. Repo snapshot

- Branch hiện tại: `main`
- Commit hash hiện tại: `f37b995c262ba29289f9c0a7582f191a54b4e55e`

### requirements.txt hiện tại

```text
fastapi>=0.115.6,<1.0.0
uvicorn[standard]>=0.34.0,<1.0.0
pydantic>=2.12,<3.0.0
python-multipart>=0.0.20,<1.0.0

cryptography>=46.0.0,<49.0.0
pycryptodome>=3.21.0,<4.0.0

pyHanko>=0.32.0,<0.36.0
pyhanko-certvalidator>=0.26.5,<0.32.0

sqlalchemy>=2.0.36,<3.0.0
aiosqlite>=0.20.0,<1.0.0
pytest>=8.3.4,<9.0.0
```

### frontend/package.json hiện tại

```json
{
  "name": "securedoc-full-demo-v4-frontend",
  "version": "0.4.0",
  "private": true,
  "scripts": {
    "dev": "vite",
    "build": "vite build",
    "preview": "vite preview"
  },
  "dependencies": {
    "@gsap/react": "^2.1.2",
    "@vitejs/plugin-react": "latest",
    "gsap": "^3.15.0",
    "react": "latest",
    "react-dom": "latest",
    "typescript": "latest",
    "vite": "latest"
  }
}
```

### Cấu trúc thư mục chính

```text
backend/
  app/
    api/
      routes_audit.py
      routes_blind_signature.py
      routes_certificates.py
      routes_key_enrollment.py
      routes_pipeline.py
      routes_remote_signing.py
      routes_revocation.py
      routes_timestamp.py
      routes_user_signing.py
      routes_verification.py
    core/
    domain/
    services/
      audit_service.py
      blind_signature_service.py
      certificate_lifecycle_service.py
      pades_service.py
      pki_service.py
      proof_of_possession_service.py
      remote_signing_service.py
      revocation_service.py
      signing_service.py
      timestamp_service.py
    storage/
  tests/
    test_services.py

frontend/
  index.html
  package.json
  src/
    api/client.ts
    components/
    modes/
    styles/main.css

docs/
  BASELINE_MAPPING.md
  FINAL_STANDARDIZATION_PLAN.md
  FULL_REQUIREMENTS_COVERAGE.md
  README_TEST_GUIDE.md
  securedoc_test_pack/
    pdfs/
    scripts/tamper_signed_pdf.py
```

## 2. Trạng thái các chức năng chính trong repo

| Phần | Trạng thái | File chính liên quan | Giới hạn hiện tại |
| --- | --- | --- | --- |
| User Signing | implemented, demo-only | `backend/app/api/routes_user_signing.py`, `backend/app/services/signing_service.py`, `frontend/src/modes/UserSigningPage.tsx` | Signing requests/history lưu in-memory; dùng demo user/certificate/key; PDF signing phụ thuộc `pyhanko` trong môi trường runtime. |
| CA / Certificate Lifecycle | implemented, demo-only | `backend/app/api/routes_certificates.py`, `backend/app/services/certificate_lifecycle_service.py`, `frontend/src/modes/CertificateLifecyclePage.tsx` | Lưu JSON trong `data/certificates`; local demo CA; chưa có DB/RBAC/production CA process. |
| Trust & Key Services | partial, demo-only | `frontend/src/modes/SecurityServicesPage.tsx`, routes timestamp/revocation/key-enrollment/remote-signing | Là console demo cho nhiều service; chưa phải trust service production. |
| End-to-End Pipeline | implemented, demo-only | `backend/app/api/routes_pipeline.py`, `frontend/src/modes/PipelineDemoPage.tsx` | Walkthrough giáo dục; `run-full` dùng payload demo và phụ thuộc signing/PAdES imports. |
| Blind Signature | implemented, demo-only | `backend/app/api/routes_blind_signature.py`, `backend/app/services/blind_signature_service.py`, `frontend/src/modes/BlindSignaturePage.tsx` | Educational blind RSA; không dùng cho document signing; không xử lý double-spend/privacy token production. |
| PAdES-B-B signing/verification | implemented in code, blocked in current test env | `backend/app/services/pades_service.py`, `backend/app/services/signing_service.py`, `backend/app/api/routes_verification.py` | Chỉ PAdES-B-B; thiếu RFC3161/LTV/OCSP/CRL thật; hiện pytest fail vì môi trường thiếu module `pyhanko`. |
| Timestamp | demo-only | `backend/app/services/timestamp_service.py`, `backend/app/api/routes_timestamp.py` | Signed demo TSA token `SECUREDOC_DEMO_TSA_TOKEN_V1`; chưa phải RFC3161 TimeStampToken. |
| Revocation | demo-only | `backend/app/services/revocation_service.py`, `backend/app/api/routes_revocation.py` | Local JSON registry + unsigned demo CRL; chưa có signed X.509 CRL hoặc OCSP thật. |
| Remote Signing | demo-only | `backend/app/services/remote_signing_service.py`, `backend/app/api/routes_remote_signing.py` | Fixed demo MFA `000000`; backend demo key; chưa có HSM/KMS/qualified remote signing. |
| Browser Key Enrollment | partial, demo-only | `backend/app/api/routes_key_enrollment.py`, `backend/app/services/proof_of_possession_service.py`, `frontend/src/modes/SecurityServicesPage.tsx` | Browser key flow dùng WebCrypto và proof-of-possession; PDF/PAdES browser signing chưa implemented, mới có browser payload signing. |
| Audit | partial, demo-only | `backend/app/services/audit_service.py`, `backend/app/api/routes_audit.py` | JSONL hash chain in `data/audit_events.jsonl`; chưa có DB, retention, RBAC, tamper-proof storage production. |

## 3. Trạng thái PAdES cụ thể

Đọc từ `backend/app/services/pades_service.py`:

- Đang ký PAdES level: `PAdES-B-B`.
- Có embedded PDF signature không: có, code dùng `pyHanko` `PdfSigner.sign_pdf(...)` và verify đọc `reader.embedded_signatures`.
- Có visible signature appearance chưa: not found in repo. Code tạo signature field bằng `fields.SigFieldSpec(sig_field_name=field_name)` nhưng không cấu hình visible box/appearance.
- Verify kiểm tra:
  - file bắt đầu bằng `%PDF-`;
  - có embedded signature;
  - `validation.validate_pdf_signature(...)`;
  - cryptographic bottom line;
  - certificate chain trusted against SecureDoc Demo Root CA local;
  - coverage chứa `ENTIRE_FILE`;
  - `docmdp_ok`;
  - advanced info: signature count, field name, trusted/bottom_line/coverage/modification level, signer subject/issuer/serial, digest/signature algorithm.
- `legal_ready`: `False`.
- Còn thiếu PAdES-B-T/B-LT/B-LTA:
  - chưa có RFC3161 timestamp gắn vào PDF/PAdES;
  - chưa có OCSP/CRL thật hoặc signed CRL;
  - chưa có LTV validation material;
  - chưa có document timestamp/archive timestamp cho B-LTA;
  - trust root là local demo CA, không phải public/qualified trust anchor.

## 4. Trạng thái kiểm thử tự động

### Frontend

Lệnh đã chạy:

```powershell
cd frontend
npm install
npm run build
```

Kết quả:

```text
npm install: pass, "up to date"
npm run build: pass
Vite output:
- 31 modules transformed
- dist/index.html 0.34 kB
- CSS asset 22.28 kB gzip 5.17 kB
- JS asset 346.83 kB gzip 114.78 kB
```

### Backend

Lệnh đã chạy:

```powershell
cd backend
$env:PYTHONPATH="."
python -m pytest -q
```

Kết quả:

```text
backend pytest: fail
tests pass/fail: 5 passed, 12 failed
lỗi chính: ModuleNotFoundError: No module named 'pyhanko'
vị trí lỗi: backend/app/services/pades_service.py:11
```

Các test fail đều bị chặn khi import `app.services.pades_service` hoặc `app.services.signing_service` vì thiếu dependency runtime `pyhanko` trong môi trường hiện tại.

## 5. Trạng thái test thủ công với PDF

Test pack có sẵn:

```text
docs/securedoc_test_pack/pdfs/01_contract_basic_unsigned.pdf
docs/securedoc_test_pack/pdfs/02_contract_multipage_unsigned.pdf
docs/securedoc_test_pack/pdfs/03_invoice_table_unsigned.pdf
docs/securedoc_test_pack/pdfs/04_unicode_text_unsigned.pdf
docs/securedoc_test_pack/pdfs/05_minimal_smoke_unsigned.pdf
docs/securedoc_test_pack/pdfs/06_fake_pdf_extension_should_reject.pdf
docs/securedoc_test_pack/scripts/tamper_signed_pdf.py
```

Manual tests không chạy được trong môi trường hiện tại vì backend PAdES/signing import fail với `ModuleNotFoundError: No module named 'pyhanko'`.

| Test | Input | Steps ngắn | Expected | Actual result |
| --- | --- | --- | --- | --- |
| Ký PDF happy path | `01_contract_basic_unsigned.pdf` | User Signing -> upload -> prepare -> confirm -> sign PDF/PAdES | Signed PDF PAdES-B-B, verification accepted, `legal_ready=false` | Not run; blocked by missing `pyhanko`. |
| Download signed PDF | Signed PDF từ happy path | Click Download signed PDF | PDF tải về được | Not run; no signed PDF produced because signing blocked by missing `pyhanko`. |
| Verify signed PDF | Signed PDF từ happy path | Upload signed PDF in Verify another signed PDF | Accepted verification | Not run; no signed PDF produced because signing blocked by missing `pyhanko`. |
| Verify unsigned PDF | `01_contract_basic_unsigned.pdf` | Upload original unsigned PDF in Verify another signed PDF | Rejected, no embedded PDF signature | Not run; verify path imports `pades_service.py` and is blocked by missing `pyhanko`. |
| Verify tampered PDF | `_tampered.pdf` generated by `tamper_signed_pdf.py` from a signed PDF | Generate tampered copy, upload to verify | Rejected crypto/coverage/integrity check | Not run; no signed PDF produced and verify path blocked by missing `pyhanko`. |
| Reject fake PDF | `06_fake_pdf_extension_should_reject.pdf` | Upload fake PDF, prepare/confirm if accepted, try sign PDF/PAdES | Backend rejects with "Input file is not a PDF" or similar | Not run through backend; PAdES signing path blocked by missing `pyhanko`. File exists and is 108 bytes. |

## 6. Các lỗi/điểm cần sửa trước khi viết báo cáo cuối

- Môi trường test hiện tại thiếu `pyhanko`; cần cài đúng `requirements.txt` trước khi claim backend tests/PAdES pass.
- `README.md` và `docs/README_TEST_GUIDE.md` nói expected backend tests pass, nhưng lần chạy hiện tại fail 12/17 vì missing dependency.
- PAdES chỉ nên ghi là PAdES-B-B demo; không claim PAdES-B-T/B-LT/B-LTA.
- `legal_ready` đang là `False`; không claim legal-ready/production-ready.
- Timestamp là signed demo TSA token, không phải RFC3161.
- Revocation là local registry/unsigned demo CRL, không phải OCSP/CRL thật.
- Remote signing dùng demo backend key và fixed MFA, cần ghi rõ demo-only.
- Browser key enrollment có proof-of-possession và payload signing demo, nhưng PDF/PAdES browser signing chưa implemented.
- Audit là JSONL hash chain demo; chưa có DB/RBAC/tamper-proof production storage.
- Signing history/request store là in-memory demo; backend restart mất history.
- Certificate lifecycle lưu JSON trong `data/certificates`; chưa có DB/RBAC/CA officer workflow production.
- UI đã có nhiều demo/advanced flows; khi viết báo cáo cần phân biệt rõ User Signing flow chính với advanced canonical payload/browser/remote demos.
