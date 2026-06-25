import React, { useState } from "react";
import { runBlindSignature } from "../api/client";
import { AdvancedDetails } from "../components/AdvancedDetails";

export function BlindSignaturePage() {
  const [message, setMessage] = useState("privacy-token-demo-001");
  const [result, setResult] = useState<any>(null);
  const [busy, setBusy] = useState(false);

  async function run() {
    setBusy(true);
    try {
      setResult(await runBlindSignature(message));
    } finally {
      setBusy(false);
    }
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

      <div className="form-card primary-task-card compact-task">
        <label htmlFor="blind-message">Token/message cần ký mù</label>
        <input id="blind-message" value={message} onChange={e => setMessage(e.target.value)} />
        <button className="primary" type="button" onClick={run}>{busy ? "Đang chạy..." : "Run blind signature flow"}</button>
      </div>

      {result && (
        <div className={result.blind_signature_valid ? "final-card accepted" : "final-card rejected"} aria-live="polite">
          <h2>{result.title}</h2>
          <p>{result.message}</p>
          <p className="hint">{result.unlinkability_note}</p>

          <div className="summary-grid">
            <p><span>Target scheme</span><strong>{result.target_scheme}</strong></p>
            <p><span>Achieved scheme</span><strong>{result.achieved_scheme}</strong></p>
            <p><span>Scheme complete</span><strong>{String(result.scheme_complete)}</strong></p>
            <p><span>Valid</span><strong>{String(result.blind_signature_valid)}</strong></p>
            <p><span>Production ready</span><strong>{String(result.production_ready)}</strong></p>
            <p><span>Key ID</span><strong>{result.key_id}</strong></p>
            <p><span>Spent status</span><strong>{result.spent_status}</strong></p>
            <p><span>Token hash</span><strong>{result.token_hash}</strong></p>
          </div>

          <div className="blind-steps">
            {result.steps.map((s: any, idx: number) => (
              <div className="blind-step" key={s.name}>
                <span>{idx + 1}</span>
                <div>
                  <h3>{s.name}</h3>
                  <p>{s.explanation}</p>
                  <code>{s.value}</code>
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
