# SecureDoc Full Demo v4

Bản v4 thiết kế lại SecureDoc theo hướng **web demo chữ ký số đầy đủ cho học phần ATTT**, lấy baseline từ:

1. `pyHanko`  
   → Ký PDF/PAdES, verify, timestamp, X.509 validation.

2. `pyca/cryptography`  
   → Sinh khóa, RSA-PSS/ECDSA/EdDSA, certificate, proof-of-possession.

3. `PyCryptodome`  
   → Demo primitive và blind RSA mức toán học.

4. `Cashu Nutshell`  
   → Tham khảo kiến trúc chữ ký mù / privacy token / Chaumian e-cash.

5. `DSS`  
   → Reference kiến trúc tổng thể cho dịch vụ chữ ký số: signing service, validation service, timestamp service, PAdES/XAdES/CAdES service.

6. `EJBCA + SignServer`  
   → Reference cho CA/PKI/certificate lifecycle và signing service thực tế.

## Mục tiêu

Bản này không còn chỉ là giao diện tĩnh. Nó có backend và frontend ăn khớp theo các mode chính:

```text
1. Pipeline Demo Mode
   Dùng để dạy ATTT, show toàn bộ pipeline end-to-end.

2. User Signing Mode
   Mô phỏng web ký số thực tế cho người dùng cuối.
   User không phải nhìn JSON thô, private key PEM, certificate JSON, CA key.

3. Certificate Lifecycle Mode
   Demo enrollment, issue, activate, revoke, status và chain của X.509 certificate.

4. Blind Signature Mode
   Demo chữ ký mù riêng: blind → sign blinded → unblind → verify.

4. API demo mở rộng
   Timestamp service, revocation service, key enrollment và remote signing.
```

## Kiến trúc

```text
frontend/
├── Pipeline Demo
├── User Signing
├── Certificate Lifecycle
└── Blind Signature

backend/
├── PKI Service
├── Certificate Service
├── Signing Service
├── Verification Service
├── Timestamp Service
├── Revocation Service
├── Key Enrollment Service
├── Remote Signing Service
├── Audit Service
├── PAdES Adapter
└── Blind Signature Service
```

## Cách chạy không cần Docker

### Yêu cầu

```text
Python 3.11+
Node.js 18 hoặc 20+
npm
```

### 1. Chạy backend

```bash
cd securedoc_full_demo_v4
python -m venv .venv
```

Windows PowerShell:

```powershell
.\.venv\Scripts\activate
pip install -r requirements.txt
mkdir data
cd backend
$env:PYTHONPATH="."
uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```

Linux/macOS:

```bash
source .venv/bin/activate
pip install -r requirements.txt
mkdir -p data
cd backend
PYTHONPATH=. uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```

Backend docs:

```text
http://127.0.0.1:8000/docs
```

### 2. Chạy frontend

Mở terminal khác:

```bash
cd securedoc_full_demo_v4/frontend
npm install
npm run dev
```

Frontend:

```text
http://localhost:5173
```

## Demo flow chính

### User Signing Mode

```text
1. Load chứng thư đang active của user
2. Upload PDF
3. Prepare signing request
4. Confirm signing intent
5. Ký PDF/PAdES-B-B bằng pyHanko
6. Download signed PDF
7. Verify signed PDF
8. Show verification report bằng status badge
9. Advanced details chỉ mở khi cần
```

Flow chính của User Signing Mode là **Ký PDF/PAdES**. Flow “ký payload demo” chỉ là advanced demo để thuyết trình cơ chế canonical payload, nonce và RSA-PSS.

Signing history trong User Mode hiện là **in-memory demo**: backend restart sẽ mất history. Đây là giới hạn có chủ đích của Phase 1/2; Phase 6 sẽ DB hóa signing history, verification report và audit trail.

### Certificate Lifecycle Mode

```text
Root CA demo
→ Intermediate CA demo
→ Enrollment chứa public key + proof-of-possession
→ Issue User Signing Certificate
→ Activate certificate
→ Revoke/status/chain
```

Key generation khác certificate issuance:

```text
Key generation
  = sinh key pair cho user/device/signer.

Certificate issuance
  = CA kiểm tra identity + public key + proof-of-possession,
    rồi ký X.509 certificate bằng CA private key.
```

Demo hiện có bootstrap certificate để chạy nhanh flow ban đầu, đồng thời có lifecycle-issued certificate để minh họa enrollment/issue/activate/revoke. Production không nên để CA tự sinh private key người dùng.

Certificate lifecycle hiện lưu JSON trong `data/certificates`. Đây là storage demo cho Phase 2; production cần database, RBAC cho CA Officer/Admin, audit production và CRL/OCSP thật.

### Pipeline Demo Mode

```text
Init Demo PKI
→ Create Signing Key
→ Certificate Enrollment
→ Issue X.509 Certificate
→ Upload/Hash Document
→ Prepare Canonical Payload
→ Confirm Intent
→ Sign
→ Verify
→ Timestamp
→ Audit
```

### Timestamp / Revocation / Key Custody API

```text
POST /api/timestamp/issue
POST /api/timestamp/verify
GET  /api/revocation/crl
GET  /api/revocation/status/{serial}
POST /api/revocation/revoke/{serial}
POST /api/key-enrollment/challenge
POST /api/key-enrollment/submit-public-key
POST /api/user-signing/submit-client-signature
POST /api/remote-signing/sign
```

Timestamp hiện là signed demo TSA token bằng key riêng của TSA. Nó chưa phải RFC3161 TimeStampToken, nhưng không còn là JSON unsigned.

Revocation hiện có registry local ghi `revoked_at`; verification policy phân biệt:

```text
trusted timestamp → check revocation tại signing time
không có trusted timestamp → check revocation tại verify time
```

Key custody hiện có 2 hướng demo:

```text
Browser/local-key style: public key + proof-of-possession challenge
Remote signing style: backend giữ demo key, kiểm tra policy + demo MFA trước khi ký
```

Frontend có tab `Security Services` để chạy nhanh các demo Phase 3-5: issue/verify timestamp, check/revoke certificate serial, key enrollment, browser payload signing và remote signing.

### Blind Signature Mode

```text
Create token
→ Blind token
→ Blind signer signs blinded token
→ User unblinds signature
→ Verifier checks unblinded signature
→ Explain unlinkability
```

## Phase 1/2 status

```text
Phase 1:
- Đã ký và verify PDF/PAdES-B-B thật bằng pyHanko.
- Đã có Download signed PDF.
- Đã có Verify another signed PDF.
- Đã có test reject unsigned PDF và tampered PDF.

Phase 2:
- Đã có Root CA → Intermediate CA → User Signing Certificate.
- Đã có enrollment + proof-of-possession.
- Đã có issue/activate/revoke/status/chain.
- Đã có lifecycle_status, revocation_status và effective_status.
- Đã có certificate profile validation cho document signing certificate.
```

## Giới hạn bảo mật

Bản này là demo học thuật, chưa phải production:

- Chưa có HSM/KMS thật.
- Root CA demo chạy local, production phải offline.
- PAdES hiện là PAdES-B-B demo bằng pyHanko; chưa phải PAdES-B-T/B-LT/B-LTA.
- Timestamp là signed demo TSA token trong payload demo, chưa phải RFC3161 TSA thật.
- Revocation là local registry/unsigned demo CRL, chưa phải OCSP/CRL thật.
- Signing history hiện là in-memory; restart backend sẽ mất history.
- Certificate lifecycle hiện lưu JSON trong `data/certificates`; production cần DB, RBAC và audit production.
- PDF/PAdES verification dùng SecureDoc Demo Root CA local, chưa phải public trusted CA.
- Legal readiness luôn `false` trong demo.
- User private key trong demo có thể được backend mô phỏng như remote signing service; production nên dùng browser non-extractable key, smartcard, USB token, HSM/KMS hoặc remote signing đạt chuẩn.

## Vì sao không show JSON trong User Mode?

User Mode mô phỏng người dùng thật. Người dùng cuối chỉ cần thấy:

```text
Tài liệu đã được ký chưa?
Chữ ký có hợp lệ không?
Tài liệu có bị sửa không?
Chứng thư có tin cậy không?
Timestamp có hợp lệ không?
```

JSON kỹ thuật được đưa vào phần `Advanced technical details`, không hiển thị mặc định.
