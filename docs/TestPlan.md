
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
