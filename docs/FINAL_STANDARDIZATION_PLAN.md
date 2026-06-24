# CODEX_FINAL_STANDARDIZATION_PLAN.md

## 1. Mục tiêu

Bản này dùng để ném cho Codex sau khi SecureDoc_ATTT đã có các cải thiện giao diện chính:

- `User Signing`: người dùng ký PDF.
- `CA / Certificate Lifecycle`: CA/PKI, X.509, enroll/issue/revoke/status.
- `Trust & Key Services`: timestamp, revocation, browser key, remote signing.
- `End-to-End Pipeline`: timeline thuyết trình pipeline chữ ký số.
- `Blind Signature`: chữ ký mù.

Mục tiêu không phải biến hệ thống thành production/legal-ready, mà là hoàn thiện **educational prototype** đủ chuẩn để báo cáo học phần ATTT.

---

## 2. Baseline traceability

| Hướng cải thiện | Baseline khớp | Ý nghĩa trong SecureDoc |
|---|---|---|
| Service architecture | DSS | Tách signing, verification, certificate, timestamp, revocation, audit |
| CA/PKI lifecycle | EJBCA | Root CA, Intermediate CA, enrollment, issue, revoke, status, chain |
| X.509/crypto primitives | pyca/cryptography | RSA-PSS, X.509 certificate, proof-of-possession |
| PDF/PAdES signing | pyHanko | Ký và verify PDF/PAdES-B-B |
| Remote signing | SignServer | Signing service boundary, policy check, MFA demo, audit |
| Browser key custody | WebCrypto + PKI direction | Private key non-extractable, backend chỉ nhận public key + PoP |
| Timestamp | DSS + pyHanko direction | Demo signed TSA token, hướng nâng RFC3161 |
| Revocation | EJBCA + DSS direction | Local revocation, demo CRL, hướng nâng signed CRL/OCSP |
| Blind signature | PyCryptodome + Cashu-inspired | Blind RSA, hướng nâng privacy token/double-spend |

---

## 3. Đã cải thiện gần nhất

### 3.1. App navigation

File:

```text
frontend/src/App.tsx
```

Đã đổi tab theo vai trò:

```text
User Signing
CA / Certificate Lifecycle
Trust & Key Services
End-to-End Pipeline
Blind Signature
```

### 3.2. End-to-End Pipeline

File:

```text
frontend/src/modes/PipelineDemoPage.tsx
```

Đã bổ sung:

```text
- role cards: CA/PKI, User/Signer, Verifier, Trust Services
- timeline end-to-end 11 bước
- artifact ở từng bước
- baseline mapping ở từng bước
- Run full pipeline để chạy demo tự động
- Mapping với đề tài ATTT: chữ ký số, cơ chế, giao thức, dịch vụ, chữ ký mù, ứng dụng
```

### 3.3. Trust & Key Services

File:

```text
frontend/src/modes/SecurityServicesPage.tsx
```

Đã làm rõ đây là console kỹ thuật, không phải user flow chính:

```text
Timestamp:
- message imprint là SHA-256 hash, không phải tài liệu gốc
- hiện là signed demo TSA token, chưa phải RFC3161

Revocation:
- hiện là demo CRL chưa ký
- production cần signed CRL hoặc OCSP

Browser key:
- private key ở browser session
- backend chỉ nhận public key + proof-of-possession

Remote signing:
- demo SignServer-like boundary
- production cần HSM/KMS/qualified remote signing
```

### 3.4. CSS

File:

```text
frontend/src/styles/main.css
```

Đã thêm style cho:

```text
role-grid
role-card
pipeline-guide
timeline-list
timeline-step
```

---

## 4. Những việc Codex cần làm tiếp

## Task A — Build check và sửa lỗi TypeScript nếu có

Chạy:

```powershell
cd frontend
npm install
npm run build
```

Acceptance criteria:

```text
- npm run build pass.
- Không có TypeScript error.
- Không có unused import gây fail build.
```

---

## Task B — Thêm trạng thái visual cho Pipeline timeline

File:

```text
frontend/src/modes/PipelineDemoPage.tsx
frontend/src/styles/main.css
```

Cần thêm status cho từng step:

```text
completed
demo_ready
warning
future_work
```

Ví dụ:

```ts
{
  title: "Sign PDF/PAdES-B-B",
  status: "demo_ready"
}
```

Hiển thị badge:

```text
Implemented
Demo-ready
Future work
```

Acceptance criteria:

```text
- Người xem biết bước nào đã implement, bước nào demo, bước nào là future work.
- PAdES-B-B là demo-ready.
- RFC3161, OCSP/CRL, PAdES-B-LT/B-LTA là future work.
```

---

## Task C — Thêm tab hint cho từng timeline step

Trong timeline, thêm trường:

```ts
openTabHint: "CA / Certificate Lifecycle"
```

Mapping:

```text
Step 1–3 → CA / Certificate Lifecycle
Step 4–8 → User Signing
Step 9–10 → Trust & Key Services
Step 11 → Audit/Advanced details
Blind Signature → Blind Signature
```

Acceptance criteria:

```text
- Mỗi step hiển thị “Thao tác ở tab: ...”.
- Người mới không nhầm Pipeline là nơi thao tác chính.
```

---

## Task D — Auto-fill active certificate serial trong Trust & Key Services

File:

```text
frontend/src/modes/SecurityServicesPage.tsx
frontend/src/api/client.ts
```

Cần làm:

```text
- Khi mở Trust & Key Services, gọi getMyActiveCertificate().
- Nếu có active cert, auto-fill serial vào ô Certificate serial.
- Hiển thị subject/status bên dưới.
```

Acceptance criteria:

```text
- User không cần copy serial từ Certificate Lifecycle.
- Revocation demo dễ dùng hơn.
```

---

## Task E — Copy document hash từ User Signing sang Timestamp Service

File:

```text
frontend/src/modes/UserSigningPage.tsx
frontend/src/modes/SecurityServicesPage.tsx
```

Cần làm:

```text
- Sau prepare request, thêm nút Copy document hash.
- Trust & Key Services giải thích paste hash đó vào Message imprint.
```

Acceptance criteria:

```text
- Sau prepare, user copy được documentHash.
- Timestamp demo dùng được hash thật thay vì aaaa...
```

---

## Task F — Hoàn thiện verification report theo hướng DSS-style

File:

```text
backend/app/services/signing_service.py
backend/app/services/pades_service.py
frontend/src/components/VerificationSummary.tsx
```

Report nên có:

```text
signatureValid
documentIntegrityValid
certificateTrusted
certificateProfileValid
revocationStatus
timestampStatus
padesProfile
legalReady=false
warnings
```

Nếu timestamp/revocation chưa gắn trực tiếp vào PDF/PAdES, report cần ghi rõ:

```text
timestampStatus = demo_external_token_only
revocationStatus = local_demo_policy
```

Không được báo `legalReady=true`.

---

## Task G — Thêm kịch bản demo báo cáo

Tạo file:

```text
docs/DEMO_SCRIPT.md
```

Nội dung demo:

```text
1. Mở CA / Certificate Lifecycle
   - giải thích Root CA, Intermediate CA, User Certificate
   - enroll/issue/activate cert

2. Mở User Signing
   - chọn PDF
   - prepare request
   - confirm intent
   - ký PDF/PAdES-B-B
   - download signed PDF
   - verify lại signed PDF

3. Mở Trust & Key Services
   - dùng document hash để issue timestamp
   - verify timestamp
   - check revocation status bằng certificate serial
   - view demo CRL

4. Mở End-to-End Pipeline
   - giải thích timeline và artifact
   - bấm Run full pipeline

5. Mở Blind Signature
   - demo blind → sign blinded → unblind → verify
```

README cần link đến `docs/DEMO_SCRIPT.md`.

---

## Task H — Chuẩn hóa Limitations / Future Work

README cần ghi rõ:

```text
Current scope:
- educational prototype
- PAdES-B-B demo
- signed demo TSA token
- local revocation + unsigned demo CRL
- demo Root CA local
- signing history in-memory
- certificate lifecycle JSON storage
- no production RBAC/HSM/KMS/public CA

Future work:
- database persistence
- RBAC CA Officer/Admin/Auditor
- RFC3161 timestamp
- signed X.509 CRL or OCSP
- PAdES-B-T/B-LT/B-LTA
- HSM/KMS/smartcard/qualified remote signing
```

---

## 5. Checklist đủ chuẩn báo cáo

### Functional checklist

```text
[ ] Backend chạy được.
[ ] Frontend build được.
[ ] User ký được PDF/PAdES-B-B.
[ ] Download signed PDF được.
[ ] Verify signed PDF accepted.
[ ] Verify PDF bị sửa rejected/not accepted.
[ ] Verify unsigned PDF rejected/not accepted.
[ ] CA lifecycle có enroll/issue/activate/revoke/status/chain.
[ ] Revoked cert không ký request mới.
[ ] Timestamp demo issue/verify được.
[ ] Revocation status/CRL demo xem được.
[ ] Browser key enrollment demo chạy được.
[ ] Remote signing demo chạy được với MFA demo.
[ ] Blind signature demo chạy được.
```

### Report checklist

```text
[ ] Có sơ đồ kiến trúc 5 khối.
[ ] Có pipeline end-to-end.
[ ] Có baseline traceability.
[ ] Có kịch bản demo.
[ ] Có test âm tính.
[ ] Có limitations/future work.
[ ] Có kết luận: educational prototype, not legal-ready.
```

---

## 6. Prompt ném cho Codex

```text
Bạn đang làm việc trong repo SecureDoc_ATTT. Hãy đọc docs/CODEX_FINAL_STANDARDIZATION_PLAN.md và hoàn thiện các Task A–H theo thứ tự ưu tiên.

Mục tiêu không phải biến hệ thống thành production/legal-ready, mà là hoàn thiện educational prototype cho báo cáo học phần ATTT về chữ ký số.

Yêu cầu:
1. Đảm bảo frontend npm run build pass.
2. Làm End-to-End Pipeline dễ hiểu hơn bằng visual status, artifact, baseline và tab hint.
3. Làm Trust & Key Services dễ dùng hơn: auto-fill active certificate serial.
4. Thêm copy document hash từ User Signing để dùng cho Timestamp Service.
5. Hoàn thiện VerificationSummary theo hướng DSS-style nhưng không overclaim legal-ready.
6. Thêm docs/DEMO_SCRIPT.md với kịch bản demo thuyết trình.
7. Cập nhật README Limitations/Future Work.
8. Không xóa các mode hiện có.
9. Không báo legalReady=true.
10. Không đưa private key PEM lên UI.

Sau khi sửa, chạy:
- cd frontend && npm install && npm run build
- cd backend && $env:PYTHONPATH="." && python -m pytest -q

Nếu test nào fail, sửa nguyên nhân thay vì bỏ test.
```

---

## 7. Kết luận

Hướng cải thiện khớp với baseline:

```text
DSS        → service architecture
EJBCA      → CA/PKI, certificate lifecycle
pyHanko    → PDF/PAdES signing and verification
SignServer → remote signing, policy, audit, key custody
WebCrypto  → browser local key enrollment
Cashu/PyCryptodome → blind signature direction
```

Chốt phạm vi:

```text
Educational prototype mô phỏng hệ thống chữ ký số hiện đại, đủ để báo cáo ATTT, chưa production/legal-ready.
```
