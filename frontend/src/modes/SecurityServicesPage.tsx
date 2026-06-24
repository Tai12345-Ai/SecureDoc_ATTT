import React, { useState } from "react";
import {
  createKeyEnrollmentChallenge,
  getDemoCrl,
  getRevocationStatus,
  issueTimestamp,
  remoteSign,
  revokeSerial,
  submitClientSignature,
  submitKeyEnrollmentProof,
  verifyTimestamp,
} from "../api/client";
import { AdvancedDetails } from "../components/AdvancedDetails";

function arrayBufferToBase64(buffer: ArrayBuffer) {
  const bytes = new Uint8Array(buffer);
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

function pemFromSpki(spki: ArrayBuffer) {
  const base64 = arrayBufferToBase64(spki);
  const lines = base64.match(/.{1,64}/g)?.join("\n") || base64;
  return `-----BEGIN PUBLIC KEY-----\n${lines}\n-----END PUBLIC KEY-----\n`;
}

function sortForCanonicalJson(value: any): any {
  if (Array.isArray(value)) return value.map(sortForCanonicalJson);
  if (value && typeof value === "object") {
    return Object.keys(value)
      .sort()
      .reduce((acc: any, key) => {
        acc[key] = sortForCanonicalJson(value[key]);
        return acc;
      }, {});
  }
  return value;
}

function canonicalJson(value: any) {
  return JSON.stringify(sortForCanonicalJson(value));
}

export function SecurityServicesPage() {
  const [imprint, setImprint] = useState("a".repeat(64));
  const [timestampToken, setTimestampToken] = useState<any>(null);
  const [timestampVerify, setTimestampVerify] = useState<any>(null);
  const [serial, setSerial] = useState("");
  const [revocationResult, setRevocationResult] = useState<any>(null);
  const [keyPair, setKeyPair] = useState<CryptoKeyPair | null>(null);
  const [publicKeyPem, setPublicKeyPem] = useState("");
  const [challenge, setChallenge] = useState<any>(null);
  const [keyEnrollmentResult, setKeyEnrollmentResult] = useState<any>(null);
  const [clientRequestId, setClientRequestId] = useState("");
  const [clientPayloadJson, setClientPayloadJson] = useState("");
  const [clientSignatureResult, setClientSignatureResult] = useState<any>(null);
  const [remoteRequestId, setRemoteRequestId] = useState("");
  const [remoteResult, setRemoteResult] = useState<any>(null);
  const [busy, setBusy] = useState("");
  const [error, setError] = useState("");

  async function run(label: string, fn: () => Promise<void>) {
    setError("");
    setBusy(label);
    try {
      await fn();
    } catch (e: any) {
      setError(e.message || String(e));
    } finally {
      setBusy("");
    }
  }

  async function generateBrowserKey() {
    await run("keygen", async () => {
      const pair = await crypto.subtle.generateKey(
        {
          name: "RSA-PSS",
          modulusLength: 3072,
          publicExponent: new Uint8Array([1, 0, 1]),
          hash: "SHA-256",
        },
        false,
        ["sign", "verify"],
      ) as CryptoKeyPair;
      const spki = await crypto.subtle.exportKey("spki", pair.publicKey);
      setKeyPair(pair);
      setPublicKeyPem(pemFromSpki(spki));
    });
  }

  async function requestChallenge() {
    await run("challenge", async () => {
      setChallenge(await createKeyEnrollmentChallenge("Alice Browser Key", "alice@example.com", publicKeyPem));
    });
  }

  async function submitProof() {
    await run("submit-proof", async () => {
      if (!keyPair || !challenge) throw new Error("Generate key and request challenge first");
      const signature = await crypto.subtle.sign(
        { name: "RSA-PSS", saltLength: 32 },
        keyPair.privateKey,
        new TextEncoder().encode(challenge.challenge),
      );
      setKeyEnrollmentResult(await submitKeyEnrollmentProof(challenge.challenge_id, arrayBufferToBase64(signature), true, true));
    });
  }

  async function submitBrowserPayloadSignature() {
    await run("client-sign", async () => {
      if (!keyPair) throw new Error("Generate browser key first");
      if (!clientRequestId.trim()) throw new Error("requestId is required");
      if (!clientPayloadJson.trim()) throw new Error("Canonical payload JSON is required");
      const parsedPayload = JSON.parse(clientPayloadJson);
      const signature = await crypto.subtle.sign(
        { name: "RSA-PSS", saltLength: 32 },
        keyPair.privateKey,
        new TextEncoder().encode(canonicalJson(parsedPayload)),
      );
      setClientSignatureResult(await submitClientSignature(clientRequestId.trim(), arrayBufferToBase64(signature)));
    });
  }

  return (
    <section className="card">
      <div className="section-title">
        <div>
          <h2>Security Services</h2>
          <p>Demo Phase 3, 4, 5: signed TSA token, revocation policy, browser key enrollment and remote signing.</p>
        </div>
        <div className="mode-pill">Phase 3-5</div>
      </div>

      {error && <div className="error">{error}</div>}

      <div className="summary-card">
        <h3>Timestamp Service</h3>
        <label>Message imprint SHA-256</label>
        <input value={imprint} onChange={e => setImprint(e.target.value)} />
        <div className="actions">
          <button className="primary" onClick={() => run("timestamp", async () => setTimestampToken(await issueTimestamp(imprint)))} disabled={!!busy}>Issue signed timestamp</button>
          <button onClick={() => run("verify-ts", async () => setTimestampVerify(await verifyTimestamp(timestampToken, imprint)))} disabled={!timestampToken || !!busy}>Verify timestamp</button>
        </div>
        {timestampVerify && <p className={timestampVerify.ok ? "green" : "error"}>{timestampVerify.message}</p>}
        {timestampToken && <AdvancedDetails data={{ timestampToken, timestampVerify }} />}
      </div>

      <div className="summary-card">
        <h3>Revocation Service</h3>
        <label>Certificate serial</label>
        <input value={serial} onChange={e => setSerial(e.target.value)} placeholder="Paste certificate serial" />
        <div className="actions">
          <button onClick={() => run("rev-status", async () => setRevocationResult(await getRevocationStatus(serial)))} disabled={!serial || !!busy}>Check status</button>
          <button onClick={() => run("revoke", async () => setRevocationResult(await revokeSerial(serial)))} disabled={!serial || !!busy}>Revoke serial</button>
          <button onClick={() => run("crl", async () => setRevocationResult(await getDemoCrl()))} disabled={!!busy}>View demo CRL</button>
        </div>
        {revocationResult && <AdvancedDetails data={revocationResult} />}
      </div>

      <div className="summary-card">
        <h3>Browser Local Key Enrollment</h3>
        <p className="hint">The private key stays in this browser session. Backend receives only the public key and proof-of-possession signature.</p>
        <p className="hint">Submitting proof activates the browser-issued certificate for Alice. Return to User Signing and prepare a new request after this step.</p>
        <div className="actions">
          <button className="primary" onClick={generateBrowserKey} disabled={!!busy}>Generate browser key</button>
          <button onClick={requestChallenge} disabled={!publicKeyPem || !!busy}>Request challenge</button>
          <button onClick={submitProof} disabled={!challenge || !keyPair || !!busy}>Submit proof</button>
        </div>
        {keyEnrollmentResult && <AdvancedDetails data={keyEnrollmentResult} />}
      </div>

      <div className="summary-card">
        <h3>Browser Payload Signing</h3>
        <p className="hint">Prepare and confirm a request in User Signing, then paste its requestId and canonical payload JSON from Advanced details.</p>
        <label>Request ID</label>
        <input value={clientRequestId} onChange={e => setClientRequestId(e.target.value)} placeholder="req_..." />
        <label>Canonical payload JSON</label>
        <textarea value={clientPayloadJson} onChange={e => setClientPayloadJson(e.target.value)} rows={5} placeholder='{"certificateSerial":"...","documentHash":"..."}' />
        <div className="actions">
          <button onClick={submitBrowserPayloadSignature} disabled={!keyPair || !clientRequestId || !clientPayloadJson || !!busy}>Sign with browser key</button>
        </div>
        {clientSignatureResult && <AdvancedDetails data={clientSignatureResult} />}
      </div>

      <div className="summary-card">
        <h3>Remote Signing</h3>
        <p className="hint">Use a prepared and confirmed requestId from User Signing. Demo MFA code is <code>000000</code>. This mode requires the demo backend signing certificate to be active.</p>
        <label>Request ID</label>
        <input value={remoteRequestId} onChange={e => setRemoteRequestId(e.target.value)} placeholder="req_..." />
        <div className="actions">
          <button onClick={() => run("remote-sign", async () => setRemoteResult(await remoteSign(remoteRequestId, "000000")))} disabled={!remoteRequestId || !!busy}>Remote sign</button>
        </div>
        {remoteResult && <AdvancedDetails data={remoteResult} />}
      </div>
    </section>
  );
}
