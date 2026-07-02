
# Kịch bản sử dụng hệ thống

## Kịch bản 1 — User ký PDF thành công

```text
1. Mở User Signing Mode.
2. Hệ thống hiển thị người ký và active certificate.
3. User chọn file PDF.
4. User nhập mục đích ký.
5. User bấm “Tạo yêu cầu ký”.
6. Backend tính SHA-256 và tạo signing request.
7. User bấm “Xác nhận OTP/TOTP”.
8. User bấm “Ký PDF/PAdES”.
9. Backend dùng pyHanko ký PDF/PAdES-B-B.
10. Backend verify signed PDF.
11. Frontend hiển thị verification summary.
12. User tải signed PDF.
```

Kết quả mong đợi:

```text
PDF được ký thành công.
Có signed file id.
Có nút Download signed PDF.
Verification report báo accepted.
```

## Kịch bản 2 — Verify lại signed PDF

```text
1. Mở User Signing Mode.
2. Chọn “Verify another signed PDF”.
3. Upload signed PDF vừa tải.
4. Bấm Verify PDF.
5. Hệ thống hiển thị report.
```

Kết quả mong đợi:

```text
Chữ ký tồn tại.
Crypto signature valid.
Document integrity valid.
Certificate trusted trong demo trust root.
```

## Kịch bản 3 — PDF bị sửa sau khi ký

```text
1. Lấy signed PDF đã tải.
2. Sửa file PDF.
3. Upload file đã sửa vào Verify another signed PDF.
4. Bấm Verify PDF.
```

Kết quả mong đợi:

```text
Hệ thống không accepted.
Report cảnh báo document integrity invalid hoặc signature invalid.
```

## Kịch bản 4 — Certificate bị revoke

```text
1. Mở Swagger tại http://127.0.0.1:8000/docs.
2. Gọi GET /api/certificates/my-active để lấy serial.
3. Gọi POST /api/certificates/{serial}/revoke.
4. Quay lại User Signing Mode.
5. Thử tạo signing request mới.
```

Kết quả mong đợi:

```text
Hệ thống reject request mới.
Certificate status hiển thị revoked.
User không ký được tài liệu mới bằng certificate đã bị thu hồi.
```

# Kịch bản test hệ thống

## Backend test

```powershell
cd D:\projects\SecureDoc_ATTT\backend
$env:PYTHONPATH="."
python -m pytest -q
```

Các test hiện có nên pass:

```text
test_demo_pki_and_signing_flow
test_pades_sign_and_verify_pdf
test_pades_sign_rejects_non_pdf
test_pades_sign_requires_confirmed_request
test_certificate_lifecycle_demo_enrollment_and_revocation
```

Test nên bổ sung:

```text
test_pades_verify_rejects_tampered_pdf
test_pades_verify_rejects_unsigned_pdf
test_certificate_enrollment_rejects_invalid_pop
test_pades_sign_rejects_revoked_certificate
test_certificate_profile_validation
```

## Manual API test

Mở:

```text
http://127.0.0.1:8000/docs
```

Test Phase 2:

```text
POST /api/certificates/init-demo-pki
GET  /api/certificates/demo-pki
GET  /api/certificates/my-active
GET  /api/certificates/{serial}/status
GET  /api/certificates/chain/{serial}
```

Test Phase 1:

```text
POST /api/user-signing/prepare
POST /api/user-signing/confirm
POST /api/user-signing/sign-pdf
GET  /api/user-signing/signed-files/{file_id}
POST /api/verification/verify-pdf
```

## Frontend test

```powershell
cd D:\projects\SecureDoc_ATTT\frontend
npm install
npm run dev
```

Mở:

```text
http://localhost:5173
```

Checklist:

```text
[ ] Trang load được workspace.
[ ] Hiển thị người ký.
[ ] Hiển thị active certificate.
[ ] Chọn PDF được.
[ ] Prepare signing request thành công.
[ ] Confirm intent thành công.
[ ] Ký PDF/PAdES thành công.
[ ] Có nút Download signed PDF.
[ ] Download mở được file PDF.
[ ] Verification summary dễ hiểu, không chỉ JSON.
[ ] Advanced details có thể mở nếu cần.
[ ] Verify another signed PDF hoạt động.
```



# Kịch bản demo/test SecureDoc_ATTT

## 0. Chuẩn bị trước khi demo

### Mục tiêu

Chạy hệ thống và đảm bảo backend/frontend hoạt động.

### Lệnh chạy backend

```powershell
cd SecureDoc_ATTT
python -m venv .venv
.\.venv\Scripts\activate
pip install -r requirements.txt
cd backend
$env:PYTHONPATH="."
uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```

### Lệnh chạy frontend

```powershell
cd frontend
npm install
npm run dev
```

Mở:

```text
Frontend: http://localhost:5173
API docs: http://127.0.0.1:8000/docs
```

### Kết quả mong đợi

* Backend chạy ở port 8000.
* Frontend chạy ở port 5173.
* Truy cập được các tab: Pipeline Demo, User Signing, Certificate Lifecycle, Blind Signature.

---

# LUỒNG 1 — Demo PKI / Certificate Lifecycle

## Mục tiêu demo

Cho thấy hệ thống có PKI nội bộ, có CA, có certificate của người ký, và certificate có vòng đời.

## Thao tác

1. Vào tab **Certificate Lifecycle**.
2. Bấm init/demo PKI nếu UI có nút này.
3. Load active certificate.
4. Quan sát certificate hiện tại:

   * signer
   * email
   * serial
   * status
   * public key
   * key usage
   * profile
   * issuer

## Kết quả mong đợi

Certificate active có dạng:

```text
Status: active
Public key: RSA 3072
Profile: RFC5280 document signing demo
Key usage: digitalSignature, contentCommitment
Issuer: SecureDoc Demo Intermediate CA
```

## Ý nói khi thuyết trình

```text
Trước khi ký tài liệu, hệ thống cần một PKI nội bộ. Root CA là gốc tin cậy, Intermediate CA cấp chứng thư cho người ký. User signing certificate dùng riêng cho ký tài liệu, không dùng để ký CA hoặc timestamp. Đây là nền tảng để người verify biết public key này thật sự thuộc về người ký nào.
```

---

# LUỒNG 2 — Demo ký PDF PAdES-B-LT happy path

## Mục tiêu demo

Cho thấy hệ thống ký một file PDF và trả ra signed PDF với target profile là PAdES-B-LT.

## Thao tác UI

1. Vào tab **User Signing**.
2. Kiểm tra sidebar có active certificate.
3. Chọn một file PDF mẫu.
4. Nhập mục đích ký, ví dụ:

```text
Xác nhận nội dung tài liệu demo ATTT
```

5. Bấm **Tạo yêu cầu ký**.
6. Bấm **Xác nhận ý chí ký**.
7. Bấm **Ký PDF PAdES-B-LT**.
8. Tải file PDF đã ký.

## Kết quả mong đợi

Sau khi ký, report hiển thị:

```text
Target profile: PAdES-B-LT
Achieved profile: PAdES-B-B / PAdES-B-T / PAdES-B-LT
Digest: SHA-256
Signature algorithm: RSA-PSS
Timestamp: valid hoặc missing/present
Revocation evidence: embedded hoặc missing
Legal readiness: false
```

Nếu đạt đủ:

```text
Achieved profile: PAdES-B-LT
Missing requirements: rỗng
```

Nếu chưa đủ:

```text
Achieved profile: PAdES-B-T hoặc PAdES-B-B
Missing requirements: hiện rõ phần còn thiếu
```

## Ý nói khi thuyết trình

```text
Ở luồng này, người dùng không chọn B-B, B-T, B-LT riêng lẻ. Hệ thống luôn target PAdES-B-LT. Tuy nhiên phần achieved profile được báo cáo trung thực: nếu thiếu timestamp hoặc thiếu CRL/OCSP/DSS thì hệ thống không claim B-LT. Đây là cách tránh gắn nhãn sai chuẩn.
```

---

# LUỒNG 3 — Demo verification report của PDF đã ký

## Mục tiêu demo

Cho thấy hệ thống không chỉ ký xong là xong, mà còn verify chữ ký PDF theo nhiều nhóm kiểm tra.

## Thao tác

1. Sau khi tải signed PDF ở luồng 2.
2. Vào phần verify PDF nếu UI có.
3. Upload lại signed PDF.
4. Xem verification report.

## Kết quả mong đợi

Report có các nhóm:

```text
document_integrity
signature_crypto
signer_certificate
chain_validation
timestamp
revocation
pades_profile
legal
```

Các check quan trọng:

```text
PDF có chữ ký: true
Chữ ký mật mã hợp lệ: true
Tài liệu chưa bị sửa sau khi ký: true
Certificate chain trusted: true
Target profile: PAdES-B-LT
Achieved profile: tùy bằng chứng thực tế
Legal readiness: false
```

## Ý nói khi thuyết trình

```text
Verification pipeline kiểm tra nhiều tầng: chữ ký có tồn tại không, chữ ký mật mã có đúng không, PDF có bị sửa sau khi ký không, certificate chain có tin được không, có timestamp không, có CRL/OCSP evidence không, và cuối cùng đạt profile PAdES nào.
```

---

# LUỒNG 4 — Demo negative test: PDF bị sửa sau khi ký

## Mục tiêu demo

Chứng minh chữ ký bảo vệ tính toàn vẹn của PDF.

## Cách demo đơn giản

1. Lấy signed PDF từ luồng 2.
2. Copy thành file khác, ví dụ:

```text
signed_tampered.pdf
```

3. Dùng script nhỏ để sửa 1 byte trong file.

Ví dụ PowerShell:

```powershell
$path = "signed_tampered.pdf"
$bytes = [System.IO.File]::ReadAllBytes($path)
$bytes[200] = ($bytes[200] + 1) % 255
[System.IO.File]::WriteAllBytes($path, $bytes)
```

4. Upload file đã sửa vào phần verify.

## Kết quả mong đợi

Verification phải fail:

```text
Status: rejected
accepted: false
document_integrity_valid: false
crypto_valid: false hoặc bottom_line false
```

## Ý nói khi thuyết trình

```text
Chỉ cần thay đổi một byte sau khi ký, ByteRange/hash/signature không còn khớp. Vì vậy verification reject file. Đây là tính toàn vẹn của chữ ký số.
```

---

# LUỒNG 5 — Demo certificate revocation

## Mục tiêu demo

Cho thấy certificate có thể bị thu hồi và hệ thống không cho dùng certificate bị revoke để tạo chữ ký mới.

## Thao tác

1. Vào tab **Certificate Lifecycle**.
2. Chọn active certificate.
3. Bấm revoke certificate.
4. Quay lại **User Signing**.
5. Thử tạo signing request mới bằng certificate đó.

## Kết quả mong đợi

Hệ thống không cho ký mới:

```text
Certificate is not active/good: revoked
```

hoặc thông báo tương tự.

## Ý nói khi thuyết trình

```text
Certificate không hợp lệ vĩnh viễn. Nếu private key bị lộ hoặc user không còn quyền ký, CA có thể revoke certificate. Từ thời điểm revoke, hệ thống không cho tạo chữ ký mới bằng certificate đó.
```

---

# LUỒNG 6 — Demo timestamp và ý nghĩa ký trước/sau khi revoke

## Mục tiêu demo

Giải thích tại sao timestamp quan trọng.

## Kịch bản nói

```text
Giả sử Alice ký PDF lúc 10:00.
Đến 12:00 certificate của Alice bị revoke.
Nếu chữ ký có timestamp hợp lệ lúc 10:00, hệ thống có thể kiểm tra rằng tại thời điểm ký certificate vẫn tốt.
Nếu không có timestamp, hệ thống chỉ biết lúc verify certificate đã bị revoke, nên khó kết luận chữ ký được tạo trước hay sau khi revoke.
```

## Thao tác demo gợi ý

1. Ký một PDF trước.
2. Xem report có timestamp status.
3. Revoke certificate.
4. Giải thích rằng hệ thống nên kiểm tra trạng thái certificate tại signing time, không chỉ tại verification time.

## Kết quả mong đợi

* New signing request sau revoke bị chặn.
* Với chữ ký đã có từ trước, report phải thể hiện logic kiểm tra tại thời điểm ký nếu có timestamp.

## Ý nói khi thuyết trình

```text
Timestamp là một phần quan trọng để long-term validation. Nó giúp chứng minh chữ ký đã tồn tại trước khi certificate bị revoke.
```

---

# LUỒNG 7 — Demo CRL / OCSP / AIA endpoint

## Mục tiêu demo

Cho thấy hệ thống có service phục vụ revocation evidence cho PAdES-B-LT.

## Test bằng browser hoặc API docs

Mở các endpoint:

```text
GET http://127.0.0.1:8000/api/revocation/crl.der
GET http://127.0.0.1:8000/api/revocation/crl.pem
GET http://127.0.0.1:8000/api/revocation/ocsp-demo
GET http://127.0.0.1:8000/api/certificates/demo-pki/root.der
GET http://127.0.0.1:8000/api/certificates/demo-pki/intermediate.der
```

## Kết quả mong đợi

```text
crl.der: trả file DER CRL
crl.pem: trả PEM CRL
ocsp-demo: trả JSON debug
root.der/intermediate.der: trả certificate issuer
```

## Ý nói khi thuyết trình

```text
PAdES-B-LT cần bằng chứng lâu dài, gồm certificate chain và revocation evidence. Vì vậy certificate có CRLDistributionPoints và AIA trỏ đến các endpoint CRL/OCSP/CA issuers. Trong demo, OCSP binary response đã có nhưng request parsing vẫn simplified.
```

---

# LUỒNG 8 — Demo Blind Signature all-in-one

## Mục tiêu demo

Cho thấy chữ ký mù là pipeline riêng, dùng cho privacy token, không ký PDF.

## Thao tác UI

1. Vào tab **Blind Signature**.
2. Nhập token:

```text
privacy-token-demo-001
```

3. Bấm **Run educational end-to-end demo**.
4. Xem các bước:

   * Create token
   * Blind
   * BlindSign
   * Finalize
   * Verify
   * Redeem

## Kết quả mong đợi

```text
Target scheme: RFC9474-RSABSSA
Achieved scheme: RSABSSA-SHA384-PSS-Randomized demo implementation
Valid: true
Production ready: false
Test vectors: false
Spent status: spent
```

## Ý nói khi thuyết trình

```text
Khác với PAdES, blind signature không ký PDF. Nó ký token ẩn danh. Signer chỉ ký blinded message, không thấy token gốc. Mục tiêu là unlinkability/privacy, không phải xác thực danh tính người ký tài liệu.
```

---

# LUỒNG 9 — Demo Blind Signature protocol-correct endpoint

## Mục tiêu demo

Cho thấy hệ thống đã tách đúng vai trò: server blind signer không được thấy token gốc.

## Test API

### 1. Lấy signer info

```powershell
curl.exe http://127.0.0.1:8000/api/blind-signature/signer-info
```

Kết quả mong đợi:

```text
key_id
key_version
public_key_algorithm: RSA
public_key_size
scheme
status: active
purpose: blind-signature-only
```

### 2. Test endpoint reject token gốc

Gửi sai cố ý:

```powershell
curl.exe -X POST http://127.0.0.1:8000/api/blind-signature/blind-sign `
  -H "Content-Type: application/json" `
  -d "{\"blinded_msg\":\"aabbcc\",\"key_id\":\"wrong\",\"message\":\"privacy-token-demo-001\"}"
```

Kết quả mong đợi:

```text
HTTP 400
Field 'message' must not be sent to the blind-sign endpoint
```

## Ý nói khi thuyết trình

```text
Đây là điểm quan trọng của blind signature. Endpoint blind-sign không được nhận message gốc. Nếu client gửi message/token gốc, backend reject ngay. Trong protocol thật, client sẽ tự blind ở phía client, server chỉ ký blinded_msg.
```

---

# LUỒNG 10 — Demo double-spend protection

## Mục tiêu demo

Cho thấy token ẩn danh không được redeem nhiều lần.

## Cách demo dễ nhất

Chạy all-in-one demo 2 lần với cùng token:

```text
privacy-token-demo-001
```

Lần 1:

```text
spent_status: spent
redeemed: true
```

Lần 2:

```text
spent_status: already_spent
redeemed: false
```

## Ý nói khi thuyết trình

```text
Vì blind signature dùng cho token ẩn danh, hệ thống phải chống dùng lại token. Spent-token registry lưu token_hash đã redeem. Nếu token được dùng lần hai, hệ thống reject với trạng thái already_spent.
```

---

# LUỒNG 11 — Demo legal readiness false

## Mục tiêu demo

Tránh claim quá mức.

## Thao tác

Ở bất kỳ verification report nào, chỉ ra:

```text
Legal readiness: false
```

## Ý nói khi thuyết trình

```text
Repo này là educational demo. Nó mô phỏng đúng pipeline kỹ thuật: PKI, certificate, PAdES, timestamp, CRL/OCSP, blind signature. Nhưng nó không dùng public trusted CA, không dùng HSM, không có policy pháp lý thật, nên legal_ready luôn là false.
```

---

# Thứ tự demo khuyến nghị khi báo cáo

Nếu chỉ có 10–15 phút, demo theo thứ tự này:

```text
1. Certificate / PKI
2. Ký PDF PAdES-B-LT
3. Verify PDF đã ký
4. Tamper PDF để chứng minh reject
5. Revoke certificate để chặn ký mới
6. Xem CRL/OCSP endpoint
7. Blind Signature all-in-one demo
8. Blind Signature protocol endpoint reject token gốc
9. Double-spend already_spent
10. Kết luận legal_ready=false
```

Nếu chỉ có 5 phút:

```text
1. Load active certificate
2. Ký PDF PAdES-B-LT
3. Show target_profile vs achieved_profile
4. Verify signed PDF
5. Blind signature demo
6. Nói rõ: PAdES ký PDF, blind signature ký token ẩn danh
```

---

# Kết luận demo

Câu kết có thể nói:

```text
Hệ thống SecureDoc_ATTT triển khai hai pipeline độc lập. Pipeline thứ nhất là ký tài liệu PDF với target PAdES-B-LT, có PKI, certificate, timestamp, revocation evidence và verification report. Pipeline thứ hai là blind signature cho privacy token, không ký PDF và không dùng chung key với hệ thống PAdES. Toàn bộ hệ thống là demo học thuật nên không claim legal readiness hay production compliance.
```
