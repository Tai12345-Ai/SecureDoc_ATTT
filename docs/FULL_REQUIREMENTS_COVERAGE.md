# Coverage theo yêu cầu đề bài

## Chữ ký số

Có:

- RSA-PSS-SHA256 signing.
- Public key verification.
- X.509 certificate binding.
- Verification report.

## Các cơ chế tạo chữ ký số

Có:

- Hash tài liệu bằng SHA-256.
- Canonical payload.
- Nonce.
- Signing purpose.
- Intent confirmation.
- Signature creation.
- Signature verification.

## Giao thức chữ ký số

Có flow:

```text
prepare → confirm intent → sign & verify → report
```

Có binding:

```text
requestId + documentHash + certificateSerial + signingPurpose + nonce
```

## Các dịch vụ chữ ký số

Có service boundary:

- PKI Service.
- Certificate Service.
- Signing Service.
- Verification Service.
- Timestamp Service.
- Revocation Service.
- Audit Service.
- PAdES Adapter.

## Chữ ký mù

Có module riêng:

```text
create token → blind → sign blinded → unblind → verify
```

## Ứng dụng

Có 3 web mode:

- User Signing Mode.
- Pipeline / ATTT Demo.
- Blind Signature Mode.

## Chưa production

- PAdES thật cần hoàn thiện adapter pyHanko.
- RFC3161 timestamp thật chưa bật.
- OCSP/CRL thật chưa bật.
- HSM/KMS chưa có.
- legalReady = false.
