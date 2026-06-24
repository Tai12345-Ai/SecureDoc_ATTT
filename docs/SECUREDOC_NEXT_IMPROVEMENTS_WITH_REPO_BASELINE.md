# SECUREDOC_NEXT_IMPROVEMENTS_WITH_REPO_BASELINE.md

## 1. Mục tiêu

Tài liệu này bổ sung traceability cho roadmap cải thiện SecureDoc:

```text
Phase nào dùng baseline từ repo nào?
Trích xuất lý thuyết/cơ chế/thuật toán gì?
Chuyển hóa vào SecureDoc Python/Web như thế nào?
File/module nào cần sửa?
Tiêu chí nghiệm thu là gì?
```

Mục tiêu là tránh việc nói chung chung “tham khảo DSS/pyHanko/EJBCA/SignServer”, mà phải chỉ rõ từng cải tiến lấy ý tưởng kỹ thuật từ đâu.

---

## 2. Repo baseline tổng hợp

| Repo / dự án | Vai trò baseline | Dùng cho phase |
|---|---|---|
| pyHanko | PDF/PAdES signing, validation, timestamp, X.509 validation | Phase 1, 3, 7, 10 |
| pyca/cryptography | Key generation, RSA-PSS/ECDSA/EdDSA, X.509 certificate, proof-of-possession | Phase 2, 5, 10 |
| PyCryptodome | Primitive crypto, blind RSA mức toán học | Phase 8, 10 |
| Cashu Nutshell | Blind token, wallet/mint, Chaumian e-cash, double-spend direction | Phase 8 |
| DSS | Digital Signature Service architecture, signing service, validation service, timestamp service, PAdES/XAdES/CAdES | Phase 1, 3, 4, 7, 9, 10 |
| EJBCA CE | CA/PKI, certificate lifecycle, enrollment, management, validation | Phase 2, 4, 9, 10 |
| SignServer CE | Signing service, policy-driven signing, key protection, audit workflow | Phase 5, 6, 9, 10 |
| DigiDoc4j | ASiC/XAdES container, timestamp, OCSP, LT/LTA direction | Phase 1, 3, 4, 7 |
| Apache PDFBox | PDF signature field, ByteRange, incremental update | Phase 1 |

---

# Phase 1 — Ký PDF/PAdES thật

## Mục tiêu thực tế của Phase 1

Hiện repo đã có `backend/app/services/pades_service.py`, nhưng mới là **adapter boundary**: kiểm tra `pyHanko` có sẵn và mô tả profile mục tiêu. Luồng User Signing hiện tại trong `routes_user_signing.py` và `signing_service.py` đang ký **canonical payload/hash** rồi trả validation report demo, chưa xuất ra file PDF đã ký với `/ByteRange` và signature field.

Phase 1 cần biến boundary này thành luồng PDF/PAdES tối thiểu có thể demo thật:

```text
Input PDF thật
→ tạo signing request gắn documentHash + certificateSerial + intent
→ xác nhận ý chí ký
→ pyHanko tạo signed PDF bằng incremental update
→ lưu signed PDF
→ cho user tải signed PDF
→ verify lại signed PDF và trả report dễ đọc
```

Không mở rộng ngay sang PAdES-LT/LTA, OCSP/CRL thật, HSM/KMS hoặc CA công cộng. Các phần đó để Phase 3, 4, 5 và 9.

## Repo baseline

### pyHanko

Trích xuất áp dụng trực tiếp:

```text
- PdfSigner để tạo chữ ký PDF thật.
- PdfSignatureMetadata để khai báo field name, lý do ký, location/contact nếu cần.
- IncrementalPdfFileWriter để không rewrite toàn bộ PDF.
- SimpleSigner hoặc signer adapter riêng cho demo key hiện tại.
- ValidationContext để validate chữ ký, certificate chain và trust roots.
- PdfSignatureStatus để chuyển kết quả verify thành report.
- PAdES B-B là mục tiêu đầu tiên; B-T/B-LT/B-LTA để các phase sau.
```

### DSS

Trích xuất ở mức kiến trúc:

```text
- Tách signing service và validation service.
- API ký trả artifact đã ký, không chỉ trả JSON kỹ thuật.
- Validation report là artifact riêng, có summary cho người dùng và details cho kỹ thuật.
- Signing flow phải có bước prepare → confirm intent → sign.
```

### Apache PDFBox

Trích xuất ở mức cơ chế PDF để giải thích trong báo cáo/Advanced details:

```text
- PDF signature field là vùng logical chứa chữ ký.
- ByteRange xác định các byte của PDF được đưa vào digest, loại trừ container chữ ký.
- Incremental update giúp thêm chữ ký mà không phá nội dung PDF gốc.
- Visual appearance là phần hiển thị, không thay thế kiểm tra mật mã.
```

## Thiết kế chuyển hóa vào SecureDoc

### Trạng thái hiện tại

```text
User upload file
→ prepare_request lưu document vào data/documents
→ confirm_intent đánh dấu confirmed
→ sign_and_verify ký canonical payload bằng RSA-PSS
→ verify hash/payload/certificate/timestamp demo
→ frontend hiển thị report
```

Điểm yếu của trạng thái hiện tại:

```text
- Không có signed PDF để tải về.
- Không có /ByteRange trong PDF.
- Không validate được PDF signature structure.
- `pades_service.py` chưa tích hợp PdfSigner/PdfValidator.
- Chưa có route verification riêng cho upload một PDF đã ký.
```

### Target Phase 1A: PAdES-B-B demo bằng pyHanko

```text
1. Chỉ nhận file PDF hợp lệ.
2. Dùng signing request hiện có để giữ confirm intent.
3. Dùng demo user certificate/private key hiện có làm signer.
4. Gọi pyHanko để ký PDF bằng incremental update.
5. Lưu signed PDF dưới data/signed_documents.
6. Trả signed_file_id + download_url + verification summary.
7. Frontend hiển thị nút Download signed PDF.
```

### Target Phase 1B: Verify signed PDF

```text
1. Cho phép upload signed PDF hoặc verify theo signed_file_id.
2. Dùng pyHanko đọc embedded signature.
3. Kiểm tra:
   - chữ ký mật mã hợp lệ;
   - document digest/ByteRange hợp lệ;
   - certificate chain demo tin cậy;
   - file bị sửa sau khi ký thì reject;
   - report phân biệt lỗi PDF structure, lỗi crypto, lỗi certificate.
4. Trả report thân thiện cho User Mode và details cho Advanced details.
```

## Module cần sửa/thêm

```text
backend/app/services/pades_service.py
  - thêm sign_pdf_pades_bb(...)
  - thêm verify_pdf_signature(...)
  - map pyHanko status sang SecureDoc verification report

backend/app/services/signing_service.py
  - giữ prepare/confirm hiện tại
  - thêm nhánh sign_pdf_request(request_id) hoặc delegate sang pades_service
  - lưu metadata signed_file_id, original_hash, signed_path

backend/app/api/routes_user_signing.py
  - thêm endpoint ký PDF thật sau confirm intent
  - thêm endpoint download signed PDF

backend/app/api/routes_verification.py
  - thêm router mới để verify PDF đã ký độc lập với User Signing flow

backend/app/main.py
  - include verification router

frontend/src/api/client.ts
  - thêm signPdf, downloadSignedPdf, verifyPdf

frontend/src/modes/UserSigningPage.tsx
  - chỉ cho Phase 1 nhận PDF hoặc cảnh báo rõ nếu file không phải PDF
  - hiển thị Download signed PDF sau khi ký thành công
  - hiển thị VerificationSummary thay vì raw JSON mặc định

frontend/src/components/DownloadSignedPdfButton.tsx
frontend/src/components/VerificationSummary.tsx
  - thêm component nhỏ, không trộn logic verify vào page chính
```

## Endpoint đề xuất

Giữ endpoint hiện tại cho demo ký payload, thêm endpoint PDF riêng để không phá API cũ:

```text
POST /api/user-signing/prepare
POST /api/user-signing/confirm
POST /api/user-signing/sign-pdf?request_id={request_id}
GET  /api/user-signing/signed-files/{file_id}
POST /api/verification/verify-pdf
POST /api/verification/verify-signed-file/{file_id}
```

Lý do không thay ngay `POST /api/user-signing/sign-and-verify`: endpoint này đang phục vụ demo canonical payload và test hiện có. Phase 1 nên thêm nhánh PDF trước, sau đó mới quyết định có deprecate flow cũ hay không.

## Data/storage đề xuất

```text
data/documents/
  req_<id>_<original_filename>.pdf

data/signed_documents/
  signed_<file_id>.pdf

metadata tạm thời trong memory hoặc JSON:
  file_id
  request_id
  original_document_hash
  signed_document_hash
  original_filename
  signed_path
  signer_certificate_serial
  pades_profile = PAdES-B-B
  created_at
```

Phase 6 sẽ thay metadata tạm bằng database. Phase 1 chỉ cần tránh hard-code path tuyệt đối và không trả filesystem path thật về frontend.

## Validation và xử lý lỗi bắt buộc

```text
- Reject file rỗng.
- Reject file không có header PDF `%PDF-`.
- Giới hạn size upload theo cấu hình, không để user upload tùy ý.
- Không dùng filename trực tiếp làm path nếu chưa sanitize.
- Nếu request chưa confirm intent thì không được ký.
- Nếu certificate_serial trong request không khớp active certificate thì reject.
- Nếu pyHanko không import được thì trả lỗi cấu hình rõ ràng, không silent fallback sang fake signing.
- Nếu verify fail thì report phải nói fail ở lớp nào: PDF structure, ByteRange/digest, crypto signature, certificate chain.
```

## Acceptance criteria

```text
- User upload file PDF và tạo signing request thành công.
- User không ký được nếu chưa confirm intent.
- Backend tạo file signed PDF thật có embedded signature.
- Signed PDF được tải về từ frontend bằng nút Download signed PDF.
- Verify signed PDF trả về summary: accepted/rejected, signer, certificate, signing time nếu có, integrity status.
- Sửa byte bất kỳ trong signed PDF sau khi ký thì verify reject.
- Upload non-PDF vào endpoint sign-pdf bị reject rõ ràng.
- User Mode không show JSON thô mặc định.
- Advanced details vẫn có ByteRange/PAdES/certificate/pyHanko status để thuyết trình kỹ thuật.
- Test service cover happy path, missing confirm, non-PDF, tampered signed PDF.
```

## Test cần thêm trong Phase 1

```text
backend/tests/test_pades_service.py
  - test_sign_pdf_creates_signed_pdf
  - test_sign_pdf_rejects_non_pdf
  - test_sign_pdf_requires_confirmed_request
  - test_verify_signed_pdf_accepts_original
  - test_verify_signed_pdf_rejects_tampered_file

frontend manual check
  - chọn PDF mẫu
  - prepare → confirm → sign-pdf
  - tải PDF đã ký
  - verify lại PDF đã ký
  - mở Advanced details
```

## Rủi ro và TODO sau Phase 1

```text
- PAdES-B-B chưa đủ legal readiness nếu thiếu trusted CA, TSA, revocation và key protection.
- Timestamp RFC3161 thật chuyển sang Phase 3.
- Revocation OCSP/CRL thật chuyển sang Phase 4.
- Browser local signing / remote signing an toàn hơn chuyển sang Phase 5.
- Persistence bền vững chuyển sang Phase 6.
- Security hardening upload/auth/rate-limit chuyển sang Phase 9.
```

---

# Phase 2 — Certificate Lifecycle / CA / X.509

## Mục tiêu thực tế của Phase 2

Hiện repo đã có `backend/app/services/pki_service.py` tạo được demo PKI:

```text
Root CA
→ Intermediate CA
→ Alice Demo Signer certificate
```

Code đã dùng `cryptography` để sinh RSA key, build X.509 certificate, thêm `BasicConstraints`, `KeyUsage`, `ExtendedKeyUsage`, và verify chain cơ bản. Tuy nhiên đây vẫn là **bootstrap demo**, chưa phải certificate lifecycle đúng nghĩa:

```text
- CA service đang tự sinh luôn user private key.
- Chưa có enrollment request.
- Chưa có proof-of-possession.
- Chưa có certificate state machine.
- Revoke hiện là in-memory set trong `revocation_service.py`.
- User Mode chỉ đọc "my-active", chưa phân biệt issued/active/revoked/expired/superseded.
```

Phase 2 cần biến PKI demo thành lifecycle tối thiểu theo hướng EJBCA: tách enrollment, issuance, active certificate, chain view và revoke/status. Mục tiêu chưa phải production CA, nhưng phải làm rõ ranh giới:

```text
Key generation ≠ Certificate issuance
User private key ≠ CA private key
User signing certificate ≠ CA certificate
Enrollment request ≠ Issued certificate
Revocation status ≠ Certificate file tồn tại
```

## Repo baseline

### EJBCA CE

Trích xuất áp dụng ở mức kiến trúc:

```text
- CA/PKI là subsystem riêng, không trộn vào user signing flow.
- Certificate lifecycle có trạng thái rõ: request/enroll, issue, active, revoke, expire, renew/supersede.
- Certificate profile quyết định CA cert hay end-entity signing cert.
- CA hierarchy tách Root CA và Issuing/Intermediate CA.
- Revoke/status là nghiệp vụ certificate management, không phải thao tác ký tài liệu.
- User thường không có quyền issue/revoke certificate.
```

### pyca/cryptography

Trích xuất áp dụng trực tiếp:

```text
- Generate hoặc load public/private key đúng thuật toán.
- Serialize public key để gửi enrollment.
- Verify proof-of-possession bằng public key trong enrollment.
- Build X.509 certificate từ public key đã được chứng minh sở hữu.
- Add BasicConstraints(ca=False) cho user certificate.
- Add KeyUsage(digital_signature=True, content_commitment=True) cho chứng thư ký tài liệu.
- Add SubjectKeyIdentifier và AuthorityKeyIdentifier để trace chain.
- Sign certificate bằng Intermediate CA private key.
- Parse/verify certificate và chain.
```

## Thiết kế chuyển hóa vào SecureDoc

### Trạng thái hiện tại

```text
POST /api/certificates/init-demo-pki
→ init_demo_pki(force)
→ sinh Root key/cert, Intermediate key/cert, Alice key/cert
→ lưu PEM dưới data/demo_pki

GET /api/certificates/my-active
→ trả Alice certificate view

POST /api/certificates/{serial}/revoke
→ đưa serial vào in-memory revoked set
```

Điểm yếu cần xử lý trong Phase 2:

```text
- CA bootstrap và user certificate issuance đang nằm chung `init_demo_pki`.
- User private key do backend/CA sinh ra, không phản ánh enrollment thực tế.
- Không có record enrollment để audit ai xin cấp, public key nào, proof nào.
- Không có certificate profile rõ ràng cho document signing.
- `ExtendedKeyUsageOID.CODE_SIGNING` chưa phù hợp để giải thích ký tài liệu/PDF.
- Revocation mất sau restart vì nằm trong memory.
- Status `active` trong certificate_view_dict là hard-code, chưa đọc lifecycle/revocation/expiry.
```

### Target Phase 2A: Lifecycle demo tối thiểu

```text
1. Giữ `init_demo_pki` chỉ để bootstrap Root/Intermediate CA và demo Alice ban đầu.
2. Thêm `certificate_lifecycle_service.py` quản lý enrollment và certificate records.
3. Enrollment nhận identity + public_key_pem + proof_of_possession.
4. Verify proof-of-possession trước khi issue.
5. Issue user signing certificate từ Intermediate CA.
6. Lưu record trạng thái certificate: pending → issued → active.
7. Revoke cập nhật lifecycle status, không chỉ thêm serial vào set.
8. `my-active` lấy certificate active từ lifecycle store.
```

### Target Phase 2B: Chain/status/report rõ ràng

```text
1. `GET /api/certificates/{serial}/status` trả:
   - lifecycle_status;
   - revocation_status;
   - validity time;
   - issuer;
   - profile;
   - warning nếu demo/local.
2. `GET /api/certificates/chain/{serial}` trả user → intermediate → root.
3. Verification report dùng status thật:
   - expired → reject;
   - revoked → reject hoặc policy tùy Phase 4;
   - unknown serial → reject;
   - chain invalid → reject.
4. Pipeline Demo có case enrollment → issue → use certificate → revoke.
```

## Certificate profile đề xuất

```text
profile_id = demo-document-signing-v1
subject = CN=<display_name>, emailAddress=<email>
issuer = SecureDoc Demo Intermediate CA
BasicConstraints = CA:FALSE
KeyUsage = digitalSignature, contentCommitment
ExtendedKeyUsage = bỏ qua trong demo hoặc ghi rõ "demo document signing"
validity = 365 ngày
serial = random x509 serial
signature_algorithm = sha256WithRSAEncryption cho cert issuer signature
document_signature_algorithm = RSA-PSS-SHA256 cho signing payload/PDF
```

Ghi chú kỹ thuật: certificate signature algorithm và document signature algorithm là hai việc khác nhau. Certificate có thể được CA ký bằng RSA/PKCS#1 v1.5 hoặc ECDSA, còn tài liệu/PDF có thể dùng RSA-PSS tùy signer và thư viện.

## Certificate states

```text
pending
issued
active
expired
revoked
superseded
rejected
```

Quy tắc tối thiểu:

```text
pending    = đã nhận enrollment nhưng chưa issue
issued     = CA đã cấp cert nhưng chưa chọn làm active
active     = cert đang được User Mode dùng để ký
expired    = now > not_valid_after
revoked    = bị thu hồi bởi CA/admin demo
superseded = đã có cert mới thay thế
rejected   = enrollment bị từ chối do proof/key/identity không hợp lệ
```

## Module cần sửa/thêm

```text
backend/app/services/pki_service.py
  - giữ CA bootstrap, load Root/Intermediate, build certificate
  - tách hàm issue_user_certificate_from_public_key(...)
  - certificate_view_dict đọc status từ lifecycle/revocation nếu có
  - không dùng `init_demo_pki` như endpoint cấp cert người dùng mới

backend/app/services/certificate_lifecycle_service.py
  - create_enrollment(...)
  - verify_proof_of_possession(...)
  - issue_enrollment(...)
  - activate_certificate(...)
  - revoke_certificate(...)
  - get_certificate_status(...)
  - get_active_certificate_for_user(...)

backend/app/services/proof_of_possession_service.py
  - có thể thêm ở Phase 2 hoặc Phase 5
  - Phase 2 tối thiểu verify signature trên challenge bằng public key

backend/app/api/routes_certificates.py
  - thêm enroll/issue/activate/chain endpoints
  - giữ my-active/status/revoke hiện có nhưng chuyển sang lifecycle service

backend/app/domain/schemas.py
  - thêm EnrollmentRequest, EnrollmentView, CertificateStatusView, CertificateChainView

backend/app/services/signing_service.py
  - khi prepare/sign phải kiểm tra certificate_serial active/good
  - không chỉ tin vào serial do frontend gửi

frontend/src/modes/UserSigningPage.tsx
  - chỉ hiển thị "My active certificate"
  - không có nút generate CA/certificate trong signing flow

frontend/src/modes/PipelineDemoPage.tsx
  - thêm bước enrollment → issue → active → revoke demo
```

## Endpoint đề xuất

Giữ các endpoint hiện có, bổ sung endpoint lifecycle rõ hơn:

```text
POST /api/certificates/init-demo-pki
GET  /api/certificates/demo-pki

POST /api/certificates/enroll
GET  /api/certificates/enrollments/{enrollment_id}
POST /api/certificates/enrollments/{enrollment_id}/issue-demo
POST /api/certificates/{serial}/activate

GET  /api/certificates/my-active
GET  /api/certificates/{serial}/status
GET  /api/certificates/chain/{serial}
POST /api/certificates/{serial}/revoke
```

Không nên để User Signing flow gọi `init-demo-pki(force=True)` như một cách "generate certificate". Bootstrap demo nên là thao tác admin/pipeline, còn người dùng cuối chỉ thấy chứng thư đang active.

## Data/storage đề xuất

Trước Phase 6 có thể dùng JSON store nhỏ, sau đó chuyển database:

```text
data/certificates/
  enrollments.json
  certificates.json
  cert_<serial>.pem
  public_key_<enrollment_id>.pem

Enrollment record:
  enrollment_id
  subject
  email
  public_key_fingerprint_sha256
  proof_challenge
  proof_signature
  status
  created_at
  decided_at

Certificate record:
  serial
  enrollment_id
  subject
  issuer
  profile_id
  pem_path
  status
  valid_from
  valid_to
  revoked_at
  superseded_by
```

Không lưu private key người dùng trong lifecycle store. Nếu demo vẫn cần backend signing key, phải ghi rõ đó là `Demo Backend Signing` và tách khỏi mô hình enrollment đúng.

## Validation và xử lý lỗi bắt buộc

```text
- Reject public key PEM parse lỗi.
- Reject key quá yếu hoặc thuật toán không hỗ trợ.
- Reject enrollment thiếu identity/email.
- Reject proof-of-possession sai challenge hoặc sai signature.
- Không issue nếu enrollment không ở trạng thái pending/approved.
- Không activate certificate expired/revoked/unknown.
- Không revoke serial không tồn tại mà không báo lỗi.
- Signing flow reject nếu certificate không active/good.
- Không endpoint nào trả CA private key hoặc user private key.
```

## Acceptance criteria

```text
- User Mode không có nút "generate certificate" lẫn trong signing flow.
- User chỉ thấy "My active certificate" và trạng thái active/good.
- Có enrollment request chứa public key + proof-of-possession.
- CA chỉ issue certificate sau khi proof-of-possession hợp lệ.
- Certificate record có lifecycle status rõ ràng.
- `my-active` không trả certificate revoked/expired.
- Revoke certificate xong signing/verification report phản ánh đúng.
- Pipeline Demo có enrollment → issue → activate → sign → revoke → status.
- README giải thích key generation khác certificate issuance.
- Không lưu private key người dùng plaintext trong lifecycle path mới.
```

## Test cần thêm trong Phase 2

```text
backend/tests/test_certificate_lifecycle.py
  - test_enroll_with_valid_proof_creates_pending_enrollment
  - test_enroll_rejects_invalid_public_key
  - test_issue_rejects_invalid_proof
  - test_issue_creates_x509_user_certificate
  - test_my_active_ignores_revoked_certificate
  - test_signing_rejects_revoked_certificate
  - test_chain_endpoint_returns_user_intermediate_root

manual check
  - init demo PKI
  - create enrollment
  - issue demo certificate
  - activate certificate
  - open User Mode and confirm active cert
  - revoke cert and verify status/report
```

## Rủi ro và TODO sau Phase 2

```text
- JSON/in-memory lifecycle store vẫn chưa bền vững bằng database; xử lý ở Phase 6.
- Proof-of-possession bằng challenge demo chưa thay thế WebCrypto non-extractable key; xử lý sâu ở Phase 5.
- Revocation vẫn chưa phải CRL/OCSP thật; xử lý ở Phase 4.
- Quyền admin/user, RBAC và audit bắt buộc cho issue/revoke; hardening ở Phase 9.
- Demo CA private keys đang nằm trong data/demo_pki; production phải dùng offline root và HSM/KMS.
```

---

# Phase 3 — Timestamp Service

## Repo baseline

### pyHanko

Trích xuất:

```text
- RFC3161 timestamp server support.
- PAdES B-T cần timestamp.
- LTV-enabled signatures cần timestamp + revocation information.
```

### DSS

Trích xuất:

```text
- Timestamp service là service riêng.
- Validation service phải kiểm tra timestamp token.
- Timestamp nằm trong validation report.
```

### DigiDoc4j

Trích xuất:

```text
- Signature profile T: chữ ký có timestamp.
- LT: timestamp + OCSP.
- LTA: archival timestamp.
```

## Chuyển hóa vào SecureDoc

Nâng từ:

```text
DEMO_TIMESTAMP_JSON
```

lên:

```text
Demo TSA có key riêng
→ TSA ký timestamp token
→ Verifier kiểm tra TSA signature
→ Sau đó mới nâng lên RFC3161 thật
```

## Module cần sửa/thêm

```text
backend/app/services/timestamp_service.py
backend/app/services/timestamp_validation_service.py
backend/app/api/routes_timestamp.py
frontend/src/components/TimestampStatus.tsx
```

## Endpoint đề xuất

```text
POST /api/timestamp/issue
POST /api/timestamp/verify
```

## Acceptance criteria

```text
- Timestamp không còn là JSON không ký.
- TSA dùng key riêng.
- Timestamp report có signing time.
- Verification report phân biệt:
  - signature valid
  - timestamp valid
  - timestamp source
  - revocation checked at signing time or verify time
```

---

# Phase 4 — Revocation Service / CRL / OCSP

## Repo baseline

### EJBCA

Trích xuất:

```text
- Certificate validation gồm trạng thái chứng thư.
- CA/PKI quản lý revoke.
- Revocation là một phần certificate lifecycle.
```

### DSS

Trích xuất:

```text
- Validation report phải kiểm tra certificate validity/revocation.
- Certificate validation service tách riêng.
```

### DigiDoc4j

Trích xuất:

```text
- LT profile dùng timestamp + OCSP.
- LTA dùng archival timestamp.
```

## Chuyển hóa vào SecureDoc

Policy cần có:

```text
Nếu có trusted timestamp:
    kiểm tra chứng thư có bị revoke tại thời điểm ký không.

Nếu không có trusted timestamp:
    kiểm tra chứng thư tại thời điểm verify,
    nhưng report phải cảnh báo không chứng minh chắc được signing time.
```

## Module cần sửa/thêm

```text
backend/app/services/revocation_service.py
backend/app/services/crl_service.py
backend/app/services/ocsp_demo_service.py
backend/app/api/routes_revocation.py
frontend/src/components/RevocationStatus.tsx
```

## Endpoint đề xuất

```text
GET  /api/revocation/crl
GET  /api/revocation/status/{serial}
POST /api/revocation/revoke/{serial}
```

## Acceptance criteria

```text
- Revoke certificate before signing → reject.
- Revoke certificate after signing + trusted timestamp → policy can still accept old signature.
- Revoke certificate after signing + no trusted timestamp → warning/reject depending policy.
- Pipeline Demo có case “revoke rồi verify lại”.
```

---

# Phase 5 — Key Custody / Proof-of-Possession / Remote Signing

## Repo baseline

### SignServer CE

Trích xuất:

```text
- Signing key cần được bảo vệ.
- Signing service có workflow/audit.
- Policy-driven signing.
- Không để key lộ ra frontend.
```

### pyca/cryptography

Trích xuất:

```text
- Proof-of-possession.
- Public key serialization.
- Signature verify.
```

## Chuyển hóa vào SecureDoc

Thêm 2 chế độ:

```text
Demo Backend Signing
Browser Local Signing
```

### Browser Local Signing

```text
Browser WebCrypto sinh key pair
Private key non-extractable
Public key gửi backend
Backend tạo challenge
Browser ký challenge
Backend verify proof-of-possession
CA issue certificate
Browser ký canonical payload
Backend verify signature
```

### Remote Signing / SignServer-like

```text
User xác thực MFA
Backend gửi signing request tới signing service
Signing service kiểm tra policy
Signing service ký bằng key được bảo vệ
Audit event được ghi
```

## Module cần sửa/thêm

```text
frontend/src/services/webcrypto.ts
frontend/src/modes/KeySetupPage.tsx
backend/app/api/routes_key_enrollment.py
backend/app/services/proof_of_possession_service.py
backend/app/services/remote_signing_service.py
```

## Endpoint đề xuất

```text
POST /api/key-enrollment/challenge
POST /api/key-enrollment/submit-public-key
POST /api/user-signing/submit-client-signature
POST /api/remote-signing/sign
```

## Acceptance criteria

```text
- User Mode không show private key PEM.
- Không paste private key.
- Không gửi private key về backend trong browser signing mode.
- Có proof-of-possession.
- Có audit cho signing request.
```

---

# Phase 6 — Database hóa Signing Workflow

## Repo baseline

### DSS

Trích xuất:

```text
- Signing/validation là service có request/response rõ ràng.
- Report cần lưu/trace được.
```

### SignServer

Trích xuất:

```text
- Signing workflow cần auditable.
- Signing operation cần có log.
```

## Chuyển hóa vào SecureDoc

Thay in-memory dict bằng database.

## Bảng đề xuất

```text
users
certificates
certificate_enrollments
documents
signing_requests
signed_packages
verification_reports
timestamps
revocations
audit_events
blind_tokens
blind_keysets
```

## Acceptance criteria

```text
- Restart backend không mất signing history.
- User xem lại lịch sử ký.
- Verifier có thể verify lại signed package cũ.
- Audit events lưu bền vững.
- Không lưu private key plaintext.
```

---

# Phase 7 — User UX giống hệ thống ký số thật

## Repo baseline

### DSS web demo

Trích xuất:

```text
- Có web demo cho signing/validation.
- Tách người dùng thao tác khỏi service xử lý kỹ thuật.
- Validation report là artifact riêng.
```

### pyHanko

Trích xuất:

```text
- User-facing operation: sign PDF, validate PDF.
- Advanced info chỉ cần cho kỹ thuật/diagnostics.
```

## Chuyển hóa vào SecureDoc

User Mode cần có:

```text
Dashboard
My certificates
Upload document
Review before signing
Confirm intent
Sign
Download signed PDF
Verification report
Signing history
```

## Không show mặc định

```text
Raw signed package
Raw certificate PEM
Private key PEM
Full canonical payload
Full audit JSON
```

Đưa các phần đó vào:

```text
Advanced technical details
```

## Acceptance criteria

```text
- User bình thường hiểu kết quả ký mà không cần đọc JSON.
- Có nút Download signed PDF.
- Có nút Verify another document.
- Có Signing history.
- Advanced details phục vụ thuyết trình ATTT.
```

---

# Phase 8 — Blind Signature nâng cao

## Repo baseline

### PyCryptodome

Trích xuất:

```text
- RSA primitive.
- Modular exponentiation.
- Hashing.
- Random blinding factor.
- Blind RSA demo.
```

### Cashu Nutshell

Trích xuất ở mức kiến trúc:

```text
- Wallet / Mint separation.
- Blind token.
- Keyset rotation.
- DLEQ proof direction.
- Spent-token/double-spend direction.
- Privacy token/e-cash application.
```

## Chuyển hóa vào SecureDoc

Không gộp chữ ký mù vào document signing. Tạo module riêng:

```text
Blind Wallet
Blind Signer / Mint
Verifier
Spent-token Registry
Keyset Rotation
```

## Flow đề xuất

```text
1. User tạo token.
2. User blind token.
3. Blind signer ký blinded token.
4. User unblind signature.
5. User redeem token.
6. Verifier kiểm tra signature.
7. Registry đánh dấu token đã dùng.
8. Nếu redeem lại token cũ → double-spend detected.
```

## Module cần sửa/thêm

```text
backend/app/services/blind_signature_service.py
backend/app/services/blind_wallet_service.py
backend/app/services/blind_mint_service.py
backend/app/services/spent_token_registry.py
backend/app/api/routes_blind_signature.py
frontend/src/modes/BlindSignaturePage.tsx
```

## Endpoint đề xuất

```text
POST /api/blind/wallet/create-token
POST /api/blind/wallet/blind-token
POST /api/blind/mint/sign-blinded-token
POST /api/blind/wallet/unblind
POST /api/blind/verifier/verify-token
POST /api/blind/verifier/redeem-token
```

## Acceptance criteria

```text
- Demo thể hiện unlinkability.
- Demo thể hiện double-spend detection.
- Blind signer key tách khỏi CA key, TSA key, user signing key.
- Không log blinding factor.
- Không log token gốc ở blind signer.
```

---

# Phase 9 — Security Hardening

## Repo baseline

### EJBCA

Trích xuất:

```text
- CA management phải tách khỏi user flow.
- Certificate issue/revoke phải có quyền riêng.
```

### SignServer

Trích xuất:

```text
- Signing workflow phải auditable.
- Signing operation phải có policy.
- Key protection là yêu cầu trung tâm.
```

### DSS

Trích xuất:

```text
- Validation phải có report rõ ràng.
- Service phải tách trách nhiệm.
```

## Cải thiện SecureDoc

Thêm:

```text
Auth thật
MFA/OTP thật
RBAC backend
Rate limiting
Upload validation
MIME sniffing
File size limit
Path traversal protection
HTTPS
Secrets không hardcode
Không commit private keys
Threat model
```

## Acceptance criteria

```text
- User thường không gọi được issue/revoke certificate.
- Không endpoint nào trả private key.
- Không bypass được confirm intent.
- Không upload path traversal.
- Có docs/THREAT_MODEL.md.
```

---

# Phase 10 — Test Cases

## Repo baseline

### DSS

Trích xuất:

```text
- Validation report phải kiểm tra nhiều lớp, không chỉ crypto signature.
```

### pyHanko

Trích xuất:

```text
- PDF validation phải kiểm tra integrity, certificate chain, incremental update/difference.
```

### EJBCA

Trích xuất:

```text
- Certificate validity và revocation là một phần validation.
```

### Cashu-inspired blind token

Trích xuất:

```text
- Redeem token cần chống double-spend.
```

## Unit tests

```text
Hash document
Canonical payload stable
RSA-PSS sign/verify
Certificate chain valid
Certificate expired
Certificate revoked
Timestamp verify
Blind signature verify
Double-spend detect
```

## Integration tests

```text
Full signing flow accepted
Tamper document after signing → reject
Wrong certificate serial → reject
Revoke certificate before signing → reject
Missing intent confirmation → reject
Replay nonce → reject
Blind token double spend → reject
```

## E2E tests

```text
User upload PDF
User sign
Download signed PDF
Verify signed PDF
Open Advanced details
Run Pipeline Demo
Run Blind Signature Demo
```

---

# 11. Traceability matrix

| Phase | Repo baseline | Cơ chế/lý thuyết trích xuất | SecureDoc module |
|---|---|---|---|
| Phase 1 | pyHanko, DSS, PDFBox | PAdES, PDF signing, validation service, ByteRange | `pades_service.py`, `routes_verification.py` |
| Phase 2 | EJBCA, pyca/cryptography | CA hierarchy, certificate lifecycle, X.509 | `pki_service.py`, `certificate_lifecycle_service.py` |
| Phase 3 | pyHanko, DSS, DigiDoc4j | Timestamp, B-T/LT/LTA, timestamp validation | `timestamp_service.py` |
| Phase 4 | EJBCA, DSS, DigiDoc4j | Revocation, OCSP/CRL, validation by signing time | `revocation_service.py` |
| Phase 5 | SignServer, pyca/cryptography | Key protection, proof-of-possession, remote signing | `key_enrollment`, `remote_signing_service.py` |
| Phase 6 | DSS, SignServer | Request/report persistence, auditable workflow | database models |
| Phase 7 | DSS, pyHanko | Web demo UX, validation report, PDF sign/verify UX | frontend modes/components |
| Phase 8 | PyCryptodome, Cashu Nutshell | Blind RSA, wallet/mint, double-spend detection | `blind_signature_service.py` |
| Phase 9 | EJBCA, SignServer, DSS | RBAC, policy, service separation, audit | security/auth modules |
| Phase 10 | DSS, pyHanko, EJBCA, Cashu | Multi-layer validation and negative tests | tests |

---

# 12. Kết luận

Bản v4 đã đủ để demo các thành phần chính của đề bài. Các phase tiếp theo cần phát triển theo hướng có traceability rõ ràng: mỗi cải tiến đều chỉ ra repo baseline, cơ chế được trích xuất, cách chuyển hóa sang Python/SecureDoc và tiêu chí nghiệm thu. Điều này giúp báo cáo có cơ sở kỹ thuật hơn, tránh cảm giác chỉ “tham khảo repo” chung chung.
