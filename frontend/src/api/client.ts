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

export function signedPdfUrl(fileId: string) {
  return `${API_BASE}/user-signing/signed-files/${encodeURIComponent(fileId)}`;
}

export function getSigningHistory() {
  return jfetch(`${API_BASE}/user-signing/history`);
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

export function runBlindSignature(message: string) {
  return jfetch(`${API_BASE}/blind-signature/run`, {
    method: "POST",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify({ message })
  });
}
