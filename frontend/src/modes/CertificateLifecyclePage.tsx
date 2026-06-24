import React, { useEffect, useState } from "react";
import {
  enrollDemoBackendKey,
  getCertificateChain,
  getCertificateStatus,
  getMyActiveCertificate,
  revokeCertificate,
} from "../api/client";
import { AdvancedDetails } from "../components/AdvancedDetails";

export function CertificateLifecyclePage() {
  const [active, setActive] = useState<any>(null);
  const [status, setStatus] = useState<any>(null);
  const [chain, setChain] = useState<any>(null);
  const [lastAction, setLastAction] = useState<any>(null);
  const [busy, setBusy] = useState("");
  const [error, setError] = useState("");

  async function refresh(serial?: string) {
    const cert = serial ? active : await getMyActiveCertificate();
    const activeCert = serial ? { ...active, serial } : cert;
    setActive(activeCert);
    if (activeCert?.serial) {
      setStatus(await getCertificateStatus(activeCert.serial));
      setChain(await getCertificateChain(activeCert.serial));
    }
  }

  useEffect(() => {
    refresh().catch(e => setError(e.message || String(e)));
  }, []);

  async function issueDemo() {
    setError("");
    setBusy("issue");
    try {
      const issued = await enrollDemoBackendKey();
      setLastAction(issued);
      await refresh(issued.serial);
    } catch (e: any) {
      setError(e.message || String(e));
    } finally {
      setBusy("");
    }
  }

  async function revokeActive() {
    if (!active?.serial) return;
    setError("");
    setBusy("revoke");
    try {
      const revoked = await revokeCertificate(active.serial);
      setLastAction(revoked);
      setStatus(revoked);
    } catch (e: any) {
      setError(e.message || String(e));
    } finally {
      setBusy("");
    }
  }

  return (
    <section className="card mode-page certificate-page" aria-busy={!!busy}>
      <div className="section-title mode-header">
        <div>
          <h2>Certificate Lifecycle</h2>
          <p>Demo Phase 2: enrollment, issue, active certificate, chain, status và revoke.</p>
        </div>
        <div className="mode-outcome">
          <strong>Lifecycle job</strong>
          <span>Issue, inspect, chain, and revoke certificates.</span>
        </div>
      </div>

      {error && <div className="error" role="alert">{error}</div>}

      <div className="actions mode-command-bar">
        <button className="primary" type="button" onClick={issueDemo} disabled={!!busy}>{busy === "issue" ? "Đang issue..." : "Enroll + Issue demo cert"}</button>
        <button type="button" onClick={revokeActive} disabled={!active || !!busy}>{busy === "revoke" ? "Đang revoke..." : "Revoke active cert"}</button>
      </div>

      <div className="summary-card priority-card">
        <h3>My active certificate</h3>
        {active ? (
          <div className="summary-grid">
            <p><span>Serial</span><strong>{active.serial}</strong></p>
            <p><span>Subject</span><strong>{active.subject}</strong></p>
            <p><span>Issuer</span><strong>{active.issuer}</strong></p>
            <p><span>Status</span><strong className={active.status === "active" ? "green" : ""}>{status?.lifecycle_status || active.status}</strong></p>
          </div>
        ) : <p>Đang tải certificate...</p>}
      </div>

      {status && (
        <div className="summary-card">
          <h3>Certificate status</h3>
          <div className="summary-grid">
            <p><span>Lifecycle</span><strong>{status.lifecycle_status}</strong></p>
            <p><span>Revocation</span><strong>{status.revocation_status}</strong></p>
            <p><span>Effective</span><strong>{status.effective_status}</strong></p>
            <p><span>Profile</span><strong>{status.profile_id}</strong></p>
            <p><span>Key source</span><strong>{status.key_source}</strong></p>
            <p><span>Origin</span><strong>{status.certificate_origin}</strong></p>
            <p><span>X.509 profile</span><strong>{status.profile_validation?.valid ? "valid" : "invalid"}</strong></p>
          </div>
          <p className="hint">{status.warning}</p>
          {status.profile_validation?.checks && (
            <div className="checks">
              {status.profile_validation.checks.map((check: any) => (
                <div className={check.ok ? "check-card ok" : "check-card bad"} key={check.key}>
                  <div className="check-icon" aria-hidden="true">{check.ok ? "✓" : "!"}</div>
                  <div>
                    <strong>{check.label}</strong>
                    <p>{check.message}</p>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {chain && (
        <div className="summary-card">
          <h3>Certificate chain</h3>
          <div className="artifact-overview">
            {chain.chain.map((cert: any, index: number) => (
              <div key={`${cert.serial}-${index}`}>
                <strong>{index === 0 ? "User cert" : index === 1 ? "Intermediate CA" : "Root CA"}</strong>
                <p>{cert.subject}</p>
              </div>
            ))}
          </div>
        </div>
      )}

      {lastAction && <AdvancedDetails data={lastAction} />}
    </section>
  );
}
