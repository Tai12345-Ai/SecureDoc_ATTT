# Baseline mapping

## 1. pyHanko

Use for:

- PDF/PAdES signing.
- Signature validation.
- RFC3161 timestamp integration.
- X.509 validation context.
- PAdES B-B/B-T/B-LT/B-LTA direction.

Current project:

```text
backend/app/services/pades_service.py
```

## 2. pyca/cryptography

Use for:

- RSA key generation.
- X.509 Root CA / Intermediate CA / User certificate.
- RSA-PSS signing and verification.
- Certificate chain verification demo.

Current project:

```text
backend/app/services/pki_service.py
backend/app/services/signing_service.py
```

## 3. PyCryptodome

Use for:

- Blind RSA arithmetic.
- Primitive crypto demo.

Current project:

```text
backend/app/services/blind_signature_service.py
```

## 4. Cashu Nutshell

Use as architecture reference:

- wallet/mint separation.
- privacy token.
- blind signature protocol.
- double-spend prevention direction.

Current project:

```text
Blind Signature Mode
```

## 5. DSS

Use as architecture reference:

- separate signing service.
- separate validation service.
- timestamp service.
- certificate validation.
- application-level signature formats.

Current project:

```text
Pipeline Mode
Signing Service
Verification Service
Timestamp Service
PAdES Adapter
```

## 6. EJBCA + SignServer

Use as architecture reference:

- CA lifecycle.
- certificate enrollment/issue/revoke.
- signing service and audit.
- key protection direction.

Current project:

```text
PKI Service
Certificate endpoints
Audit Service
Signing request protocol
```
