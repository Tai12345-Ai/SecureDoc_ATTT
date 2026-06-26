# SecureDoc_ATTT — Frontend-first test plan

Mục tiêu của file này: ưu tiên kiểm thử theo góc nhìn người dùng trên UI trước, sau đó mới dùng backend/API để đối chiếu. Mỗi test case đều có **đầu vào**, **bước thao tác**, và **kết quả mong đợi**.

## 0. Điều kiện trước khi test

### Môi trường
- Backend: `http://127.0.0.1:8000`
- Frontend: `http://localhost:5173`
- Browser đề xuất: Chrome hoặc Edge.
- Mở DevTools → Network để quan sát request khi cần đối chiếu.

### Chạy hệ thống
Backend:
```powershell
cd securedoc_full_demo_v4
.\.venv\Scripts\activate
cd backend
$env:PYTHONPATH="."
uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```

Frontend:
```bash
cd securedoc_full_demo_v4/frontend
npm install
npm run dev
```

### Test data dùng chung
| Mã input | File/giá trị | Dùng cho |
|---|---|---|
| PDF-1 | `inputs/01_contract_basic_unsigned.pdf` | Ký PDF cơ bản |
| PDF-2 | `inputs/02_contract_two_pages_unsigned.pdf` | Ký PDF nhiều trang, SHA-384/SHA-512 |
| PDF-3 | `inputs/03_invoice_unsigned.pdf` | Remote PDF signing |
| TXT-1 | `inputs/04_plain_text_for_canonical_payload.txt` | Canonical payload signing |
| EMPTY | `inputs/05_empty_file.pdf` | Negative test empty file |
| FAKE-PDF | `inputs/06_fake_pdf_header_corrupt.pdf` | Negative test PDF lỗi |
| TOKEN | `privacy-token-demo-001-UI` | Blind signature UI |
| IMPRINT | `aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa` | Timestamp UI |
| MFA-OK | `000000` | Remote signing thành công |
| MFA-BAD | `123456` | Remote signing thất bại |

---

# PHẦN A — FRONTEND TEST CASES

## FE-00. Smoke test: mở frontend và kiểm tra menu chính

**Mục tiêu:** xác nhận frontend chạy, điều hướng được giữa các mode chính.

**Đầu vào:** không cần file.

**Bước thực hiện:**
1. Mở `http://localhost:5173`.
2. Quan sát thanh menu dưới/cuối trang hoặc navigation của app.
3. Lần lượt chuyển qua các tab/mode: `Pipeline`, `User signing`, `Timestamp`, `Revocation`, `Remote signing`, `Blind signature`, `Audit trail`, `PDF/PAdES X.509` nếu UI đang hiển thị đủ.

**Kết quả mong đợi:**
- Trang không trắng, không crash.
- Không có lỗi đỏ dạng `Failed to fetch` khi backend đang chạy.
- Các trang/mode đổi nội dung đúng theo tiêu đề.
- Nếu backend tắt, UI có thể báo lỗi kết nối; đây không phải lỗi UI logic mà là lỗi môi trường.

**Backend đối chiếu sau UI:** `GET /api/health` phải trả `status=ok`.

---

## FE-01. User Signing Mode — trạng thái ban đầu chưa có active certificate

**Mục tiêu:** kiểm tra UI xử lý trạng thái chưa có chứng thư đang dùng.

**Đầu vào:** không cần file.

**Bước thực hiện:**
1. Mở `User Signing Mode`.
2. Nhìn panel bên trái `Người ký` và `Chứng thư đang dùng`.
3. Quan sát khu vực certificate phía dưới nếu có thông báo lỗi.

**Kết quả mong đợi:**
- Hiển thị user demo: `Alice Demo Signer`, `alice@example.com`.
- Nếu chưa có chứng thư active, UI hiển thị lỗi đỏ tương tự `No active certificate`.
- Nút `Enroll + Issue demo cert` phải bấm được.
- Các nút ký như `Tạo yêu cầu ký`, `Xác nhận OTP/TOTP`, `Ký PDF PAdES-B-LT` chưa nên cho chạy hoàn chỉnh nếu chưa có certificate/file/request hợp lệ.

**Backend đối chiếu sau UI:** `GET /api/certificates/my-active` có thể trả 404 nếu chưa có active cert.

---

## FE-02. User Signing Mode — cấp demo certificate thành công

**Mục tiêu:** kiểm tra luồng tạo chứng thư demo cho người ký.

**Đầu vào:** không cần file.

**Bước thực hiện:**
1. Trong `User Signing Mode`, bấm `Enroll + Issue demo cert`.
2. Chờ UI tải lại thông tin certificate.
3. Quan sát panel `My active certificate` hoặc `Chứng thư đang dùng`.

**Kết quả mong đợi:**
- Thông báo đỏ `No active certificate` biến mất.
- UI hiển thị certificate active.
- Có `serial`, subject/issuer hoặc thông tin chứng thư tương đương.
- Key custody nên thể hiện là `DEMO_BACKEND_KEY` hoặc mô tả backend demo key.
- Nút `Revoke active cert` chuyển sang trạng thái có thể dùng.

**Backend đối chiếu sau UI:** `GET /api/certificates/my-active` trả 200, certificate có trạng thái active.

---

## FE-03. User Signing Mode — ký PDF PAdES-B-LT happy path

**Mục tiêu:** kiểm tra luồng người dùng chính: chọn tài liệu → tạo request → xác nhận ý chí ký → ký PDF → xem verify report.

**Đầu vào:**
- File: `inputs/01_contract_basic_unsigned.pdf`
- Mục đích ký: `Ký xác nhận hợp đồng demo FE-03`
- Digest algorithm: `SHA-256 (recommended)`

**Bước thực hiện:**
1. Mở `User Signing Mode`.
2. Nếu chưa có certificate active, chạy FE-02 trước.
3. Tại `Tài liệu cần ký`, chọn `01_contract_basic_unsigned.pdf`.
4. Nhập mục đích ký: `Ký xác nhận hợp đồng demo FE-03`.
5. Chọn digest `SHA-256 (recommended)`.
6. Bấm `Tạo yêu cầu ký`.
7. Sau khi request tạo thành công, bấm `Xác nhận OTP/TOTP`.
8. Bấm `Ký PDF PAdES-B-LT`.
9. Quan sát khu vực kết quả/verification report.

**Kết quả mong đợi:**
- Sau bước 6: UI hiển thị request id hoặc phần thông tin request/canonical payload; không báo lỗi.
- Sau bước 7: UI báo ý chí ký đã xác nhận.
- Sau bước 8: UI trả kết quả có `accepted` hoặc trạng thái verify thành công.
- Có thông tin `target_profile = PAdES-B-LT`.
- Có `achieved_profile`; có thể là `PAdES-B-LT`, `PAdES-B-T` hoặc `PAdES-B-B` tùy evidence thực tế. Không được coi đây là lỗi nếu UI giải thích rõ `missing_requirements`.
- Có `signature_algorithm = RSA-PSS`.
- Có `digest_algorithm = SHA-256`.
- Có cảnh báo demo/legal readiness false nếu UI hiển thị.
- Có link/nút download signed PDF nếu signing thành công.

**Backend đối chiếu sau UI:** request tương ứng là `prepare → confirm → sign-pdf`; file id có thể verify qua `/api/verification/verify-signed-file/{file_id}`.

---

## FE-04. User Signing Mode — verify PDF đã ký độc lập trên UI

**Mục tiêu:** kiểm tra tính xác minh độc lập sau khi tải PDF đã ký.

**Đầu vào:**
- File signed PDF tải về từ FE-03, lưu vào `outputs/signed_01_contract.pdf`.

**Bước thực hiện:**
1. Sau FE-03, bấm download signed PDF.
2. Lưu file vào `outputs/signed_01_contract.pdf`.
3. Tìm khu vực `Verify another signed PDF` hoặc chức năng verify PDF độc lập trên UI.
4. Upload `outputs/signed_01_contract.pdf`.
5. Bấm verify nếu UI có nút riêng.

**Kết quả mong đợi:**
- UI báo PDF có chữ ký hợp lệ.
- Các check quan trọng pass: có embedded signature, chữ ký mật mã hợp lệ, tài liệu chưa bị sửa sau khi ký, certificate trusted theo demo root.
- `legal_ready=false` vẫn là đúng vì demo CA không phải public trusted CA.

**Backend đối chiếu sau UI:** `POST /api/verification/verify-pdf` với file signed PDF trả `accepted=true` nếu pyHanko validate thành công.

---

## FE-05. User Signing Mode — tamper signed PDF rồi verify phải fail

**Mục tiêu:** chứng minh tính toàn vẹn: sửa PDF sau khi ký thì xác minh không được chấp nhận.

**Đầu vào:**
- Signed PDF từ FE-03: `outputs/signed_01_contract.pdf`
- Tampered PDF tạo bằng script:
```powershell
python scripts/tamper_pdf.py outputs/signed_01_contract.pdf outputs/signed_01_contract_tampered.pdf
```

**Bước thực hiện:**
1. Tạo file tampered bằng lệnh trên.
2. Trên UI, vào chức năng verify PDF độc lập.
3. Upload `outputs/signed_01_contract_tampered.pdf`.
4. Bấm verify.

**Kết quả mong đợi:**
- UI không được báo `accepted=true`.
- Hoặc UI báo `PDF signature is not valid`, hoặc hiển thị check fail, hoặc backend trả lỗi verify.
- Check `document_integrity_valid`, `crypto_valid`, hoặc `docmdp_valid` có thể fail tùy vị trí byte bị sửa.
- Đây là test quan trọng nhất để trình bày trong báo cáo: thay đổi nội dung sau khi ký bị phát hiện.

**Backend đối chiếu sau UI:** `POST /api/verification/verify-pdf` với tampered PDF phải không accepted.

---

## FE-06. User Signing Mode — canonical payload signing với TXT

**Mục tiêu:** kiểm tra phần advanced demo: ký payload chuẩn hóa thay vì ký PDF.

**Đầu vào:**
- File: `inputs/04_plain_text_for_canonical_payload.txt`
- Mục đích ký: `Ký canonical payload demo FE-06`
- Digest: `SHA-256`

**Bước thực hiện:**
1. Mở `User Signing Mode`.
2. Chọn file TXT-1.
3. Nhập mục đích ký.
4. Chọn SHA-256.
5. Bấm `Tạo yêu cầu ký`.
6. Bấm `Xác nhận OTP/TOTP`.
7. Mở phần `Advanced demo: ký canonical payload` nếu đang đóng.
8. Bấm nút ký canonical payload hoặc `sign-and-verify` nếu UI đặt tên như vậy.

**Kết quả mong đợi:**
- UI hiển thị chữ ký canonical payload thành công.
- Verification report có `accepted=true`.
- Payload có các trường ràng buộc: requestId, documentHash, certificateSerial, signingPurpose, nonce.
- Signature algorithm là RSA-PSS.
- Có timestamp demo token cho document hash.

**Backend đối chiếu sau UI:** `/api/user-signing/sign-and-verify` trả report accepted.

---

## FE-07. User Signing Mode — không được ký nếu chưa confirm intent

**Mục tiêu:** kiểm tra UI enforce giao thức ký: prepare xong phải xác nhận ý chí ký trước.

**Đầu vào:**
- File: `inputs/01_contract_basic_unsigned.pdf`
- Purpose: `Negative test no confirm FE-07`

**Bước thực hiện:**
1. Upload PDF-1.
2. Bấm `Tạo yêu cầu ký`.
3. Không bấm `Xác nhận OTP/TOTP`.
4. Thử bấm `Ký PDF PAdES-B-LT` hoặc nút ký canonical payload nếu nút có thể bấm.

**Kết quả mong đợi:**
- Tốt nhất: UI disable nút ký trước khi confirm.
- Nếu UI vẫn cho bấm: phải hiện lỗi từ backend `Signing intent has not been confirmed`.
- Không được tạo signed PDF.

**Backend đối chiếu sau UI:** `/api/user-signing/sign-pdf` hoặc `/sign-and-verify` trả HTTP 400.

---

## FE-08. User Signing Mode — reject empty file

**Mục tiêu:** kiểm tra input validation ở frontend/backend khi upload file rỗng.

**Đầu vào:**
- File: `inputs/05_empty_file.pdf`
- Purpose: `Empty file test FE-08`

**Bước thực hiện:**
1. Chọn EMPTY.
2. Nhập purpose.
3. Bấm `Tạo yêu cầu ký`.

**Kết quả mong đợi:**
- UI hiển thị lỗi rõ ràng.
- Backend trả `Empty file`.
- Không sinh request id.

---

## FE-09. User Signing Mode — reject SHA3 khi ký PDF/PAdES

**Mục tiêu:** kiểm tra chính sách thuật toán: SHA3 có thể dùng cho canonical payload demo, nhưng không dùng cho PAdES/PDF.

**Đầu vào:**
- File: `inputs/01_contract_basic_unsigned.pdf`
- Purpose: `SHA3 PAdES negative FE-09`
- Digest: `SHA3-256`

**Bước thực hiện:**
1. Chọn PDF-1.
2. Chọn digest `SHA3-256` nếu UI có option.
3. Bấm `Tạo yêu cầu ký`.
4. Bấm `Xác nhận OTP/TOTP`.
5. Bấm `Ký PDF PAdES-B-LT`.

**Kết quả mong đợi:**
- Prepare có thể thành công và UI nên cảnh báo SHA3 là experimental.
- Khi ký PDF, UI phải hiển thị lỗi: SHA3 experimental/not enabled for PAdES.
- Không sinh signed PDF.

**Backend đối chiếu sau UI:** `/api/user-signing/sign-pdf` trả HTTP 400.

---

## FE-10. User Signing Mode — SHA-384/SHA-512 ký PDF vẫn pass

**Mục tiêu:** kiểm tra các digest PAdES-compatible ngoài SHA-256.

**Đầu vào:**
- File: `inputs/02_contract_two_pages_unsigned.pdf`
- Purpose: `SHA384 PDF FE-10` rồi `SHA512 PDF FE-10`
- Digest: chạy 2 lượt riêng: `SHA-384`, `SHA-512`

**Bước thực hiện:**
1. Với SHA-384: upload PDF-2, prepare, confirm, ký PDF.
2. Download/verify nếu ký thành công.
3. Lặp lại từ đầu với SHA-512, dùng request mới.

**Kết quả mong đợi:**
- Cả 2 lượt không bị reject vì digest policy.
- Kết quả hiển thị đúng `digest_algorithm = SHA-384` hoặc `SHA-512`.
- Verification accepted nếu PDF signing/validation ổn.

---

## FE-11. Certificate Lifecycle UI — revoke active certificate

**Mục tiêu:** kiểm tra thu hồi chứng thư từ UI và tác động đến ký mới.

**Đầu vào:** active certificate hiện tại.

**Bước thực hiện:**
1. Trong `User Signing Mode` hoặc `Certificate Lifecycle`, bấm `Revoke active cert`.
2. Quan sát trạng thái certificate.
3. Thử upload PDF-1 và bấm `Tạo yêu cầu ký` với certificate đã revoke.

**Kết quả mong đợi:**
- Certificate chuyển sang revoked hoặc không còn usable.
- Signing request mới bị từ chối với thông báo certificate not active/good.
- Nút ký không nên cho chạy thành công.

**Cleanup:** bấm `Enroll + Issue demo cert` để có certificate active mới trước các test tiếp theo.

---

## FE-12. Trust & Key Services — Timestamp issue/verify thành công

**Mục tiêu:** kiểm tra UI timestamp service.

**Đầu vào:**
- Message imprint SHA-256: `aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa`

**Bước thực hiện:**
1. Mở `Trust & Key Services` hoặc tab `Timestamp`.
2. Nhập IMPRINT vào ô `Message imprint SHA-256`.
3. Bấm issue/create timestamp token.
4. Bấm verify timestamp với cùng imprint.

**Kết quả mong đợi:**
- UI tạo được token có genTime/serial/signature.
- Verify báo `ok=true` hoặc trạng thái hợp lệ.
- UI nên có cảnh báo đây là demo TSA token, không phải production TSA pháp lý.

**Backend đối chiếu sau UI:** `/api/timestamp/issue` và `/api/timestamp/verify` trả success.

---

## FE-13. Trust & Key Services — Timestamp mismatch phải fail

**Mục tiêu:** kiểm tra message imprint binding.

**Đầu vào:**
- Token tạo từ FE-12.
- Expected imprint sai: `bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb`

**Bước thực hiện:**
1. Giữ token từ FE-12.
2. Đổi expected imprint sang chuỗi `b...b` dài 64 hex.
3. Bấm verify.

**Kết quả mong đợi:**
- UI báo timestamp không hợp lệ hoặc `ok=false`.
- Lý do: imprint không khớp.
- Không được báo token valid toàn phần.

---

## FE-14. Trust & Key Services — Revocation status/CRL/OCSP debug

**Mục tiêu:** kiểm tra UI service thu hồi chứng thư.

**Đầu vào:** active certificate serial đang hiển thị trên UI.

**Bước thực hiện:**
1. Mở tab `Revocation` hoặc khu vực revocation trong `Trust & Key Services`.
2. Kiểm tra status của serial hiện tại.
3. Bấm lấy CRL nếu UI có nút.
4. Bấm OCSP demo nếu UI có nút.
5. Revoke certificate.
6. Kiểm tra lại status.

**Kết quả mong đợi:**
- Ban đầu status là good/active/not revoked.
- CRL/OCSP debug hiển thị dữ liệu hoặc trạng thái phản hồi.
- Sau revoke, status đổi thành revoked.
- Sau revoke, ký mới bằng cert đó phải bị chặn.

---

## FE-15. Remote signing UI — sai MFA bị reject

**Mục tiêu:** kiểm tra policy/MFA của remote signing.

**Đầu vào:**
- File: `inputs/03_invoice_unsigned.pdf`
- Purpose: `Remote signing wrong MFA FE-15`
- MFA: `123456`

**Bước thực hiện:**
1. Tạo signing request PDF và confirm intent trong UI.
2. Chuyển sang khu vực `Remote signing` nếu UI tách tab, hoặc dùng phần remote signing trong service console.
3. Nhập MFA `123456`.
4. Bấm remote sign PDF.

**Kết quả mong đợi:**
- UI hiển thị lỗi `Invalid demo MFA code`.
- Không tạo signed PDF.
- Audit nếu hiển thị sẽ có event rejected/denied.

---

## FE-16. Remote signing UI — đúng MFA ký PDF thành công

**Mục tiêu:** kiểm tra remote signing happy path.

**Đầu vào:**
- File: `inputs/03_invoice_unsigned.pdf`
- Purpose: `Remote signing PDF FE-16`
- MFA: `000000`

**Bước thực hiện:**
1. Tạo signing request với PDF-3.
2. Confirm intent.
3. Nhập MFA `000000` trong remote signing.
4. Bấm remote sign PDF.
5. Quan sát kết quả và download nếu có.

**Kết quả mong đợi:**
- UI báo ký thành công.
- Có `file_id`/download link hoặc metadata file.
- Verification accepted nếu pyHanko validate thành công.
- Remote signing policy hiển thị kiểu `confirmed_intent + demo_mfa + active_certificate + pdf_document`.
- Key custody vẫn là demo backend/remote service boundary; không được hiểu là HSM thật.

---

## FE-17. Blind Signature Mode — all-in-one demo thành công

**Mục tiêu:** kiểm tra chữ ký mù ở UI và phân biệt nó với ký PDF.

**Đầu vào:**
- Token/message: `privacy-token-demo-001-UI`

**Bước thực hiện:**
1. Mở `Blind Signature Mode`.
2. Nhập token/message.
3. Bấm run/demo/sign token tùy tên nút trên UI.
4. Quan sát các bước protocol architecture.

**Kết quả mong đợi:**
- UI hiển thị các pha: Prepare, Blind, BlindSign, Finalize, Verify token, Redeem/mark spent.
- Kết quả `blind_signature_valid=true` hoặc trạng thái verified.
- `redeemed=true`, `spent_status=spent` trong lần redeem đầu.
- Có ghi chú đây là privacy token signing, không phải PDF/PAdES document signing.
- Có cảnh báo production_ready=false hoặc chưa test-vector verified nếu UI show advanced.

---

## FE-18. Blind Signature Mode — empty token bị reject

**Mục tiêu:** kiểm tra validation cho input rỗng.

**Đầu vào:** token/message rỗng hoặc toàn khoảng trắng.

**Bước thực hiện:**
1. Mở `Blind Signature Mode`.
2. Xóa nội dung ô token/message.
3. Bấm run/demo.

**Kết quả mong đợi:**
- UI không được báo thành công.
- Hiển thị lỗi `message is required` hoặc validation tương đương.

---

## FE-19. Audit Trail UI — kiểm tra event sau thao tác

**Mục tiêu:** xác nhận hệ thống có ghi audit cho các thao tác chính.

**Đầu vào:** đã chạy ít nhất FE-03 hoặc FE-17.

**Bước thực hiện:**
1. Mở `Audit trail`.
2. Refresh/tải danh sách event.
3. Tìm các event gần nhất.

**Kết quả mong đợi:**
- Sau FE-03 có event kiểu `prepare_signing_request`, `confirm_signing_intent`, `sign_pdf_pades_blt`.
- Sau FE-17 có event kiểu `blind_signature_demo` hoặc blind token redeem.
- Event có actor, action, target, status, thời gian hoặc metadata tương ứng.

---

# PHẦN B — BACKEND/API TEST CASES SAU KHI FRONTEND PASS

Mục đích của backend test không phải thay thế frontend test, mà để đối chiếu chính xác khi UI báo lỗi hoặc cần chứng minh logic bảo mật.

## BE-01. Health
**Input:** none.  
**Steps:** `GET /api/health`.  
**Expected:** HTTP 200, `status=ok`.

## BE-02. Init/issue active certificate
**Input:** none.  
**Steps:**
1. `POST /api/certificates/init-demo-pki?force=true`
2. `POST /api/certificates/enroll-demo-backend-key?activate=true`
3. `GET /api/certificates/my-active`
**Expected:** active certificate, key_source `DEMO_BACKEND_KEY`.

## BE-03. Canonical payload signing
**Input:** `inputs/04_plain_text_for_canonical_payload.txt`, purpose `BE canonical`, digest `sha256`.  
**Steps:** prepare → confirm → sign-and-verify.  
**Expected:** `accepted=true`, signature algorithm RSA-PSS, timestamp valid, revocation valid.

## BE-04. PDF/PAdES signing
**Input:** `inputs/01_contract_basic_unsigned.pdf`, digest `sha256`.  
**Steps:** prepare → confirm → sign-pdf → download → verify-pdf.  
**Expected:** signed PDF produced, verification accepted, target profile PAdES-B-LT, legal_ready false.

## BE-05. Tamper PDF
**Input:** signed PDF from BE-04.  
**Steps:** run `scripts/tamper_pdf.py`, then verify tampered PDF.  
**Expected:** not accepted.

## BE-06. Digest policy
**Input:** PDF-1 and TXT-1.  
**Steps/Expected:**
- TXT + sha3-256 canonical: accepted.
- PDF + sha3-256 PAdES: HTTP 400.
- md5/sha1 prepare: HTTP 400.
- PDF + sha384/sha512: signing accepted if validation succeeds.

## BE-07. Timestamp
**Input:** IMPRINT.  
**Steps:** issue → verify same imprint → verify different imprint.  
**Expected:** same imprint ok=true; different imprint ok=false.

## BE-08. Revocation
**Input:** active SERIAL.  
**Steps:** status → revoke → status → prepare signing with revoked cert.  
**Expected:** status revoked; signing prepare rejected.

## BE-09. Remote signing
**Input:** confirmed PDF request, MFA `000000` and `123456`.  
**Expected:** `000000` accepted; `123456` rejected.

## BE-10. Blind signature
**Input:** `{ "message": "privacy-token-demo-001-BE" }`.  
**Steps:** `POST /api/blind-signature/run`.  
**Expected:** `blind_signature_valid=true`, `verified=true`, `production_ready=false`.

---

# PHẦN C — BẢNG GHI KẾT QUẢ THỦ CÔNG

| Test ID | Tester | Date | Input | Actual result | Expected matched? | Evidence screenshot/file | Note |
|---|---|---|---|---|---|---|---|
| FE-03 | | | PDF-1 | | Pass/Fail | | |
| FE-05 | | | tampered PDF | | Pass/Fail | | |
| FE-09 | | | PDF + SHA3-256 | | Pass/Fail | | |
| FE-12 | | | IMPRINT | | Pass/Fail | | |
| FE-16 | | | PDF-3 + MFA 000000 | | Pass/Fail | | |
| FE-17 | | | TOKEN | | Pass/Fail | | |
