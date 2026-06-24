# CODEX_FINAL_STANDARDIZATION_PLAN.md

## 1. Mục tiêu

Tài liệu này là bản hướng dẫn để dùng với Codex sau khi SecureDoc_ATTT đã có các cải thiện giao diện và luồng demo chính:

- Tab `User Signing` cho người ký PDF.
- Tab `CA / Certificate Lifecycle` cho CA/PKI.
- Tab `Trust & Key Services` cho timestamp, revocation, browser key, remote signing.
- Tab `End-to-End Pipeline` cho thuyết trình pipeline chữ ký số.
- Tab `Blind Signature` cho chữ ký mù.

Mục tiêu tiếp theo không phải biến hệ thống thành production/legal-ready, mà là hoàn thiện hệ thống ở mức **educational prototype chuẩn để báo cáo học phần ATTT**.

---

## 2. Baseline traceability

| Hướng cải thiện | Baseline khớp | Ý nghĩa trong SecureDoc |
|---|---|---|
| Service architecture | DSS | Tách signing, verification, certificate, timestamp, revocation, audit |
| CA/PKI lifecycle | EJBCA | Root CA, Intermediate CA, enrollment, issue, revoke, status, chain |
| X.509/crypto primitives | pyca/cryptography | RSA-PSS, X.509 certificate, proof-of-possession, certificate profile checks |
| PDF/PAdES signing | pyHanko | Ký và verify PDF/PAdES-B-B |
| Remote signing | SignServer | Signing service boundary, policy check, MFA demo, audit |
| Browser key custody | WebCrypto + PKI direction | Private key non-extractable, backend chỉ nhận public key + proof-of-possession |
| Timestamp | DSS + pyHanko direction | Demo signed TSA token, hướng nâng lên RFC3161 |
| Revocation | EJBCA + DSS direction | Local revocation, demo CRL, hướng nâng lên signed CRL/OCSP |
| Blind signature | PyCryptodome + Cashu-inspired | Blind RSA, hướng nâng lên privacy token + double-spend detection |

---

## 3. Những cải thiện đã thực hiện gần nhất

### 3.1. App navigation

File:

```text
frontend/src/App.tsx
```

Đã đổi cách đặt tên tab theo vai trò:

```text
User Signing
CA / Certificate Lifecycle
Trust & Key Services
End-to-End Pipeline
Blind Signature
```

Mục tiêu: người xem hiểu ngay tab nào là user flow, tab nào là CA, tab nào là service kỹ thuật, tab nào là màn thuyết trình.

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
- Run full pipeline vẫn giữ để chạy demo tự động
- phần Mapping với đề tài ATTT vẫn giữ để giải thích các mục: chữ ký số, cơ chế, giao thức, dịch vụ, chữ ký mù, ứng dụng
```

### 3.3. Trust & Key Services

File:

```text
frontend/src/modes/SecurityServicesPage.tsx
```

Đã làm rõ đây là technical console, không phải user flow chính. Đã thêm mô tả:

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

## 4. Những việc Codex cần làm tiếp để hoàn thiện chuẩn báo cáo

## Task A — Build check và sửa lỗi TypeScript nếu có

### Mục tiêu

Đảm bảo frontend build được sau các thay đổi UI.

### Lệnh kiểm tra

```powershell
cd frontend
npm install
npm run build
```

Nếu lỗi, sửa trực tiếp các file liên quan.

### Acceptance criteria

```text
- npm run build pass.
- Không có TypeScript error.
- Không có unused import gây fail build.
```

---

## Task B — Làm Pipeline timeline rõ hơn bằng trạng thái visual

### File chính

```text
frontend/src/modes/PipelineDemoPage.tsx
frontend/src/styles/main.css
```

### Cần làm

Hiện timeline là explain timeline. Cần thêm trạng thái visual:

```text
not_run
ready
completed
warning
future_work
```

Gợi ý:

```ts
const timeline = [
  {
    phase: "CA setup",
    title: "Init CA hierarchy",
    status: "completed",
    ...
  }
]
```

Hiển thị status badge cho từng step:

```text
Completed
Demo
Future phase
```

### Acceptance criteria

```text
- Người xem nhìn timeline biết bước nào đã implement, bước nào mới demo, bước nào là future work.
- PAdES-B-B là completed/demo-ready.
- RFC3161, OCSP/CRL, PAdES-B-LT/B-LTA là future work.
```

---

## Task C — Gắn link điều hướng giữa các tab theo actor

### Mục tiêu

Pipeline cần chỉ người dùng nên mở tab nào để thao tác thật.

### Cần làm

Trong timeline, mỗi step thêm trường:

```ts
openTabHint: "CA / Certificate Lifecycle"
```

Ví dụ:

```text
Step 1–3 → mở CA / Certificate Lifecycle
Step 4–8 → mở User Signing
Step 9–10 → mở Trust & Key Services
Step 11 → xem Audit/Advanced details
Blind Signature → mở Blind Signature
```

Vì App đang quản lý tab bằng state local, cách đơn giản nhất là chỉ hiển thị hint text, chưa cần auto-navigate.

### Acceptance criteria

```text
- Mỗi timeline step hiển thị “Thao tác ở tab: ...”.
- Người mới không còn nhầm Pipeline là nơi thao tác chính.
```

---

## Task D — Tự động lấy active certificate serial trong Trust & Key Services

### File chính

```text
frontend/src/modes/SecurityServicesPage.tsx
frontend/src/api/client.ts
```

### Cần làm

Hiện Revocation Service bắt user paste serial thủ công. Cần cải thiện:

```text
- Khi mở Trust & Key Services, gọi getMyActiveCertificate().
- Nếu có active cert, auto-fill serial vào ô Certificate serial.
- Hiển thị subject/status bên dưới.
```

### Acceptance criteria

```text
- User không cần copy serial từ Certificate Lifecycle.
- Revocation demo dễ thao tác hơn.
```

---

## Task E — Timestamp demo dùng document hash thật từ signed flow nếu có

### Mục tiêu

Hiện Timestamp Service dùng mặc định `aaaa...`. Cần hướng người dùng dùng hash thật.

### Cách đơn giản

Trong User Signing sau khi prepare request, document hash đã có trong `prepared.document_hash`. Cần thêm nút copy:

```text
Copy document hash for Timestamp Service
```

Nếu chưa muốn dùng state global, chỉ cần thêm nút copy clipboard.

### File chính

```text
frontend/src/modes/UserSigningPage.tsx
frontend/src/modes/SecurityServicesPage.tsx
```

### Acceptance criteria

```text
- Sau prepare, user copy được documentHash.
- Trust & Key Services giải thích paste hash đó vào Message imprint.
```

---

## Task F — Hoàn thiện verification report theo hướng DSS-style

### File chính

```text
backend/app/services/signing_service.py
backend/app/services/pades_service.py
frontend/src/components/VerificationSummary.tsx
```

### Cần có trong report

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

### Lưu ý

Nếu timestamp/revocation chưa gắn trực tiếp vào PDF/PAdES, report cần ghi rõ:

```text
timestampStatus = demo_external_token_only
revocationStatus = local_demo_policy
```

Không được báo `legalReady=true`.

### Acceptance criteria

```text
- VerificationSummary dễ hiểu, không chỉ JSON.
- Report phân biệt accepted/rejected/warning.
- Report không nhận nhầm demo thành legal-ready.
```

---

## Task G — Test E2E thủ công và bổ sung README demo script

### File cần thêm hoặc sửa

```text
README.md
docs/DEMO_SCRIPT.md
```

### Nội dung DEMO_SCRIPT.md

Cần có kịch bản demo theo thứ tự:

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
   - giải thích lại timeline và artifact
   - bấm Run full pipeline

5. Mở Blind Signature
   - demo blind → sign blinded → unblind → verify
```

### Acceptance criteria

```text
- README có link đến docs/DEMO_SCRIPT.md.
- Người khác clone repo có thể chạy demo theo script.
```

---

## Task H — Chuẩn hóa phần “Limitations / Future Work”

### File cần sửa

```text
README.md
```

### Nội dung cần ghi rõ

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

### Acceptance criteria

```text
- Báo cáo trung thực, không overclaim.
- Người xem hiểu hệ thống đạt chuẩn demo học thuật, chưa legal-ready.
```

---

## 5. Checklist để coi repo đủ chuẩn báo cáo

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

## 6. Prompt gợi ý ném cho Codex

```text
Bạn đang làm việc trong repo SecureDoc_ATTT. Hãy đọc docs/CODEX_FINAL_STANDARDIZATION_PLAN.md và hoàn thiện các Task A–H theo thứ tự ưu tiên.

Mục tiêu không phải biến hệ thống thành production/legal-ready, mà là hoàn thiện educational prototype cho báo cáo học phần ATTT về chữ ký số.

Yêu cầu chính:
1. Đảm bảo frontend npm run build pass.
2. Làm End-to-End Pipeline dễ hiểu hơn bằng visual status, artifact, baseline và tab hint.
3. Làm Trust & Key Services dễ dùng hơn: auto-fill active certificate serial, giải thích rõ timestamp/revocation/key custody.
4. Thêm copy document hash từ User Signing để dùng cho Timestamp Service.
5. Hoàn thiện VerificationSummary theo hướng DSS-style nhưng không overclaim legal-ready.
6. Thêm docs/DEMO_SCRIPT.md với kịch bản demo thuyết trình.
7. Cập nhật README Limitations/Future Work.
8. Không xóa các mode hiện có: User Signing, CA/Certificate Lifecycle, Trust & Key Services, End-to-End Pipeline, Blind Signature.
9. Không báo legalReady=true.
10. Không đưa private key PEM lên UI.

Sau khi sửa, chạy:
- cd frontend && npm install && npm run build
- cd backend && $env:PYTHONPATH="." && python -m pytest -q

Nếu test nào fail, sửa nguyên nhân thay vì bỏ test.
```

---

## 7. Kết luận

Hướng cải thiện hiện tại khớp với các baseline đã chọn:

```text
DSS        → service architecture, validation, timestamp/revocation separation
EJBCA      → CA/PKI, certificate lifecycle
pyHanko    → PDF/PAdES signing and verification
SignServer → remote signing, policy, audit, key custody boundary
WebCrypto  → browser local key enrollment
Cashu/PyCryptodome → blind signature direction
```

Repo nên được chốt ở mức:

```text
Educational prototype mô phỏng hệ thống chữ ký số hiện đại, đủ để báo cáo ATTT, chưa production/legal-ready.
```
