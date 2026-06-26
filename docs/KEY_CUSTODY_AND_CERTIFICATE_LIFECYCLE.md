# Key Custody and Certificate Lifecycle

SecureDoc separates certificate issuance from private-key custody. This demo has
three explicit modes.

## DEMO_BACKEND_KEY

- The backend generates and stores Alice's demo private key.
- This key is used only for educational PDF/PAdES and canonical payload signing.
- The matching certificate records have:
  - `key_source = DEMO_BACKEND_KEY`
  - `private_key_custody = BACKEND_DEMO_STORAGE`
  - `backend_has_private_key = true`
- This is not production-ready and is not a legal-readiness claim.

## CLIENT_SIDE_KEY

- The browser, user device, or external client generates the keypair.
- The private key stays outside the backend.
- The backend receives only the public key and a proof-of-possession signature.
- The CA issues an X.509 certificate for that submitted public key.
- The matching certificate records have:
  - `key_source = CLIENT_SIDE_KEY`
  - `private_key_custody = USER_BROWSER_OR_DEVICE`
  - `backend_has_private_key = false`
- Backend PDF/PAdES signing is rejected for this certificate mode because the
  backend does not have the private key. The canonical payload client-side
  signing demo can verify signatures with the certificate public key.

## REMOTE_HSM_KEY

- This is the future production-like model.
- The raw private key should live in an HSM, KMS, token, or qualified remote
  signing service.
- The backend orchestrates policy, intent, MFA, and verification, but should not
  see the raw private key.
- The matching certificate records should have:
  - `key_source = REMOTE_HSM_KEY`
  - `private_key_custody = REMOTE_HSM_OR_KMS`
  - `backend_has_private_key = false`

## Why the CA Should Not Hold User Private Keys

A CA's job is to validate identity, verify proof of possession, and issue a
certificate binding an identity to a public key. In a production signing system,
the user signing private key should be controlled by the user, a secure device,
or a dedicated remote signing/HSM service. If the CA/backend also holds user
private keys, compromise of the backend can enable forged user signatures and
break non-repudiation assumptions.

## Current Limitation

Full client-side PAdES signing is not implemented yet. It requires a PDF
pre-sign/finalize workflow with ByteRange calculation and a CMS signature
container. SecureDoc currently keeps this as future work and supports
client-side signing only for the canonical payload demo.
