const API_BASE = "http://127.0.0.1:8000/api";

async function jfetch(url: string, init?: RequestInit) {
  const res = await fetch(url, init);
  if (!res.ok) {
    const text = await res.text();
    throw new Error(text);
  }
  return res.json();
}

export function getPipelineSteps() {
  return jfetch(`${API_BASE}/pipeline/steps`);
}

export function getPipelineStepDetail(stepId: string) {
  return jfetch(`${API_BASE}/pipeline/steps/${stepId}`);
}

export function runFullPipeline() {
  return jfetch(`${API_BASE}/pipeline/run-full`, { method: "POST" });
}

export function getUserWorkspace() {
  return jfetch(`${API_BASE}/user-signing/workspace`);
}

export function prepareSigningRequest(file: File, purpose: string, certSerial: string) {
  const body = new FormData();
  body.append("file", file);
  body.append("signing_purpose", purpose);
  body.append("certificate_serial", certSerial);
  return jfetch(`${API_BASE}/user-signing/prepare`, {
    method: "POST",
    body
  });
}

export function confirmSigningIntent(requestId: string) {
  return jfetch(`${API_BASE}/user-signing/confirm?request_id=${encodeURIComponent(requestId)}`, {
    method: "POST"
  });
}

export function signAndVerify(requestId: string) {
  return jfetch(`${API_BASE}/user-signing/sign-and-verify?request_id=${encodeURIComponent(requestId)}`, {
    method: "POST"
  });
}

export function signPdf(requestId: string) {
  return jfetch(`${API_BASE}/user-signing/sign-pdf?request_id=${encodeURIComponent(requestId)}`, {
    method: "POST"
  });
}

export function submitClientSignature(requestId: string, signatureBase64: string) {
  return jfetch(`${API_BASE}/user-signing/submit-client-signature?request_id=${encodeURIComponent(requestId)}&signature_base64=${encodeURIComponent(signatureBase64)}`, {
    method: "POST"
  });
}

export function signedPdfUrl(fileId: string) {
  return `${API_BASE}/user-signing/signed-files/${encodeURIComponent(fileId)}`;
}

export function verifyPdf(file: File) {
  const body = new FormData();
  body.append("file", file);
  return jfetch(`${API_BASE}/verification/verify-pdf`, {
    method: "POST",
    body
  });
}

export function getMyActiveCertificate() {
  return jfetch(`${API_BASE}/certificates/my-active`);
}

export function enrollDemoBackendKey() {
  return jfetch(`${API_BASE}/certificates/enroll-demo-backend-key?activate=true`, {
    method: "POST"
  });
}

export function getCertificateStatus(serial: string) {
  return jfetch(`${API_BASE}/certificates/${encodeURIComponent(serial)}/status`);
}

export function getCertificateChain(serial: string) {
  return jfetch(`${API_BASE}/certificates/chain/${encodeURIComponent(serial)}`);
}

export function revokeCertificate(serial: string) {
  return jfetch(`${API_BASE}/certificates/${encodeURIComponent(serial)}/revoke`, {
    method: "POST"
  });
}

export function issueTimestamp(messageImprintSha256: string) {
  return jfetch(`${API_BASE}/timestamp/issue`, {
    method: "POST",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify({ message_imprint_sha256: messageImprintSha256 })
  });
}

export function verifyTimestamp(token: any, expectedImprintSha256: string) {
  return jfetch(`${API_BASE}/timestamp/verify`, {
    method: "POST",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify({ token, expected_imprint_sha256: expectedImprintSha256 })
  });
}

export function getDemoCrl() {
  return jfetch(`${API_BASE}/revocation/crl`);
}

export function getRevocationStatus(serial: string) {
  return jfetch(`${API_BASE}/revocation/status/${encodeURIComponent(serial)}`);
}

export function revokeSerial(serial: string, reason = "cessationOfOperation") {
  return jfetch(`${API_BASE}/revocation/revoke/${encodeURIComponent(serial)}?reason=${encodeURIComponent(reason)}`, {
    method: "POST"
  });
}

export function createKeyEnrollmentChallenge(displayName: string, email: string, publicKeyPem: string) {
  return jfetch(`${API_BASE}/key-enrollment/challenge`, {
    method: "POST",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify({ display_name: displayName, email, public_key_pem: publicKeyPem })
  });
}

export function submitKeyEnrollmentProof(challengeId: string, proofSignatureBase64: string, issueCertificate = true, activateCertificate = false) {
  return jfetch(`${API_BASE}/key-enrollment/submit-public-key`, {
    method: "POST",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify({
      challenge_id: challengeId,
      proof_signature_base64: proofSignatureBase64,
      issue_certificate: issueCertificate,
      activate_certificate: activateCertificate
    })
  });
}

export function remoteSign(requestId: string, mfaCode: string) {
  return jfetch(`${API_BASE}/remote-signing/sign`, {
    method: "POST",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify({ request_id: requestId, mfa_code: mfaCode })
  });
}

export function runBlindSignature(message: string) {
  return jfetch(`${API_BASE}/blind-signature/run`, {
    method: "POST",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify({ message })
  });
}
