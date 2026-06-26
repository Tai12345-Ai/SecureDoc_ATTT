import React, { useState } from "react";
import { runBlindSignature, getBlindSignerInfo } from "../api/client";
import { AdvancedDetails } from "../components/AdvancedDetails";

export function BlindSignaturePage() {
  const [message, setMessage] = useState("privacy-token-demo-001");
  const [result, setResult] = useState<any>(null);
  const [signerInfo, setSignerInfo] = useState<any>(null);
  const [busy, setBusy] = useState(false);

  async function run() {
    setBusy(true);
    try {
      setResult(await runBlindSignature(message));
    } finally {
      setBusy(false);
    }
  }

  async function loadSignerInfo() {
    try {
      setSignerInfo(await getBlindSignerInfo());
    } catch {}
  }

  return (
    <section className="card mode-page blind-page" aria-busy={busy}>
      <div className="section-title mode-header">
        <div>
          <h2>Blind Signature Mode</h2>
          <p>Blind signature is for anonymous/privacy token signing, not PDF/PAdES document signing.</p>
        </div>
        <div className="mode-outcome">
          <strong>Privacy job</strong>
          <span>Sign a token without linking it to the original message.</span>
        </div>
      </div>

      {/* Protocol view */}
      <div className="summary-card no-margin">
        <h3>Protocol architecture (RFC9474-RSABSSA)</h3>
        <p className="hint">In the real protocol, the server never sees the original token. Only the blinded message crosses the trust boundary.</p>
        <div className="blind-steps">
          <div className="blind-step"><span>1</span><div><h3>Client: Prepare</h3><p>Client creates a privacy token and applies PrepareRandomize.</p></div></div>
          <div className="blind-step"><span>2</span><div><h3>Client: Blind</h3><p>Client PSS-encodes the prepared message and blinds it with a random factor.</p></div></div>
          <div className="blind-step"><span>3</span><div><h3>Server: BlindSign</h3><p>Server signs only the blinded message using a dedicated blind-signature key. It never sees the original token.</p></div></div>
          <div className="blind-step"><span>4</span><div><h3>Client: Finalize</h3><p>Client unblinds the response and verifies the resulting RSA-PSS signature.</p></div></div>
          <div className="blind-step"><span>5</span><div><h3>Verifier: Verify &amp; Redeem</h3><p>Verifier checks the signature, then marks the token spent in a registry to prevent double-spend.</p></div></div>
        </div>
        <div className="badge-row" style={{marginTop: "12px"}}>
          <button type="button" onClick={loadSignerInfo}>Load signer info</button>
        </div>
        {signerInfo && (
          <div className="summary-grid" style={{marginTop: "12px"}}>
            <p><span>Key ID</span><strong>{signerInfo.key_id}</strong></p>
            <p><span>Algorithm</span><strong>{signerInfo.public_key_algorithm} {signerInfo.public_key_size}</strong></p>
            <p><span>Scheme</span><strong>{signerInfo.scheme}</strong></p>
            <p><span>Status</span><strong>{signerInfo.status}</strong></p>
            <p><span>Compliance</span><strong>{signerInfo.compliance_status}</strong></p>
            <p><span>Test vectors</span><strong>{String(signerInfo.rfc9474_test_vectors_passed)}</strong></p>
          </div>
        )}
      </div>

      {/* Educational demo */}
      <div className="form-card primary-task-card compact-task">
        <h3>Educational end-to-end demo</h3>
        <p className="hint">This demo runs the entire flow on the server for educational purposes. The server sees the original token — this is NOT the real privacy architecture.</p>
        <label htmlFor="blind-message">Token/message cần ký mù</label>
        <input id="blind-message" value={message} onChange={e => setMessage(e.target.value)} />
        <button className="primary" type="button" onClick={run}>{busy ? "Đang chạy..." : "Run educational end-to-end demo"}</button>
      </div>

      {result && (
        <div className={result.blind_signature_valid ? "final-card accepted" : "final-card rejected"} aria-live="polite">
          <h2>{result.title}</h2>
          <p>{result.message}</p>
          <p className="hint">{result.unlinkability_note}</p>

          <div className="summary-grid">
            <p><span>Target scheme</span><strong>{result.target_scheme}</strong></p>
            <p><span>Achieved scheme</span><strong>{result.achieved_scheme}</strong></p>
            <p><span>Valid</span><strong>{String(result.blind_signature_valid)}</strong></p>
            <p><span>Compliance</span><strong>{result.compliance_status}</strong></p>
            <p><span>Test vectors</span><strong>{String(result.rfc9474_test_vectors_passed)}</strong></p>
            <p><span>Production ready</span><strong>{String(result.production_ready)}</strong></p>
            <p><span>Key ID</span><strong>{result.key_id}</strong></p>
            <p><span>Spent status</span><strong>{result.spent_status}</strong></p>
          </div>

          <div className="blind-steps">
            {result.steps.map((s: any, idx: number) => (
              <div className="blind-step" key={s.name}>
                <span>{idx + 1}</span>
                <div>
                  <h3>{s.name}</h3>
                  <p>{s.explanation}</p>
                  <code>{typeof s.value === "string" && s.value.length > 48 ? s.value.slice(0, 48) + "…" : s.value}</code>
                </div>
              </div>
            ))}
          </div>

          {result.warnings?.length > 0 && (
            <details className="warning-box">
              <summary>Warnings</summary>
              <ul>{result.warnings.map((warning: string) => <li key={warning}>{warning}</li>)}</ul>
            </details>
          )}

          <AdvancedDetails data={result.advanced} />
        </div>
      )}
    </section>
  );
}
