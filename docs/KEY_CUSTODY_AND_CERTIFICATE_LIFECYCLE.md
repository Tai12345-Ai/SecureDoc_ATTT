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
- The proof-of-possession challenge is single-use, expires after 5 minutes, and
  locks after repeated failed proof attempts in the demo JSON store.
- Issuing the same enrollment again returns the existing certificate record
  instead of minting another certificate.
- The matching certificate records have:
  - `key_source = CLIENT_SIDE_KEY`
  - `private_key_custody = USER_BROWSER_OR_DEVICE`
  - `backend_has_private_key = false`
- Backend PDF/PAdES signing is rejected for this certificate mode because the
  backend does not have the private key.
- Client-side PDF/PAdES signing is supported through a demo pre-sign/finalize
  flow: the backend prepares the PDF ByteRange and CMS signed attributes, the
  browser or external client signs those exact attributes, and the backend
  verifies the raw signature with the certificate public key before finalizing
  the CMS/PDF container.
- The canonical payload client-side signing demo also verifies signatures with
  the certificate public key.

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

The client-side PAdES path is still demo-grade, not production/legal-ready. Its
pre-sign state is kept in backend memory for a short TTL and is single-use, so a
backend restart clears pending operations. Production would need authenticated
sessions, durable transaction state, rate limiting, audit hardening, HSM/token
or qualified remote-signing integration, trusted CA/TSA/OCSP/CRL operations, and
legal policy controls.
