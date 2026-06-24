# Next implementation steps

## Phase 1: Hoàn thiện PDF/PAdES thật

- Tích hợp pyHanko `PdfSigner`.
- Tạo signature field.
- Xuất signed PDF.
- Validate signed PDF.
- Hiển thị download signed PDF trong User Mode.

## Phase 2: RFC3161 timestamp thật

- Thêm TSA client.
- Verify TimeStampToken.
- Bind timestamp với document imprint.

## Phase 3: Revocation thật

- CRL parser.
- OCSP client.
- Check revocation at signing time nếu có trusted timestamp.

## Phase 4: User key chuẩn hơn

- Browser WebCrypto non-extractable key.
- Hoặc remote signing service style SignServer.
- Hoặc smartcard/USB token/HSM adapter.

## Phase 5: Blind token nâng cao

- Tách Wallet và Blind Signer/Mint.
- Thêm spent-token registry.
- Thêm double-spend detection.
- Thêm keyset rotation giống hướng Cashu.
