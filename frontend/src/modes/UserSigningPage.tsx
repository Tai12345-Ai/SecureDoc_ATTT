import React, { useEffect, useState } from "react";
import { getUserWorkspace, prepareSigningRequest, confirmSigningIntent, signAndVerify, signPdf, verifyPdf, getSigningHistory, remoteSignPdf } from "../api/client";
import { CheckCard } from "../components/CheckCard";
import { AdvancedDetails } from "../components/AdvancedDetails";
import { DownloadSignedPdfButton } from "../components/DownloadSignedPdfButton";
import { VerificationSummary } from "../components/VerificationSummary";

const DIGEST_OPTIONS = [
  { value: "sha256", label: "SHA-256", note: "recommended" },
  { value: "sha384", label: "SHA-384", note: "" },
  { value: "sha512", label: "SHA-512", note: "" },
  { value: "sha3_256", label: "SHA3-256", note: "experimental" },
  { value: "sha3_384", label: "SHA3-384", note: "experimental" },
  { value: "sha3_512", label: "SHA3-512", note: "experimental" },
];

export function UserSigningPage() {
  const [workspace, setWorkspace] = useState<any>(null);
  const [file, setFile] = useState<File | null>(null);
  const [purpose, setPurpose] = useState("Ký xác nhận tài liệu demo");
  const [digestAlgorithm, setDigestAlgorithm] = useState("sha256");
  const [prepared, setPrepared] = useState<any>(null);
  const [confirmed, setConfirmed] = useState<any>(null);
  const [result, setResult] = useState<any>(null);
  const [pdfResult, setPdfResult] = useState<any>(null);
  const [verifyFile, setVerifyFile] = useState<File | null>(null);
  const [verifyReport, setVerifyReport] = useState<any>(null);
  const [history, setHistory] = useState<any[]>([]);
  const [busy, setBusy] = useState("");
  const [error, setError] = useState("");
  const [mfaCode, setMfaCode] = useState("000000");
  const [remotePdfResult, setRemotePdfResult] = useState<any>(null);

  useEffect(() => {
    getUserWorkspace().then(setWorkspace).catch(e => setError(String(e)));
    refreshHistory();
  }, []);

  const cert = workspace?.certificate;
  const isExperimental = digestAlgorithm.startsWith("sha3_");
  const keySource = cert?.key_source || "UNKNOWN_KEY_SOURCE";
  const isDemoBackendKey = keySource === "DEMO_BACKEND_KEY";
  const backendPadesBlocked = cert && !isDemoBackendKey;

  async function refreshHistory() {
    try {
      const data = await getSigningHistory();
      setHistory(data.items || []);
    } catch {
      setHistory([]);
    }
  }

  async function doPrepare() {
    if (!file || !cert) {
      setError("Bạn cần chọn tài liệu trước.");
      return;
    }
    setError("");
    setBusy("prepare");
    setPrepared(null);
    setConfirmed(null);
    setResult(null);
    setPdfResult(null);
    setRemotePdfResult(null);
    try {
      setPrepared(await prepareSigningRequest(file, purpose, cert.serial, digestAlgorithm));
    } catch (e: any) {
      setError(e.message || String(e));
    } finally {
      setBusy("");
    }
  }

  async function doConfirm() {
    if (!prepared) return;
    setError("");
    setBusy("confirm");
    try {
      setConfirmed(await confirmSigningIntent(prepared.request_id));
    } catch (e: any) {
      setError(e.message || String(e));
    } finally {
      setBusy("");
    }
  }

  async function doSign() {
    if (!prepared || !confirmed) return;
    setError("");
    setBusy("sign");
    try {
      setResult(await signAndVerify(prepared.request_id));
    } catch (e: any) {
      setError(e.message || String(e));
    } finally {
      setBusy("");
    }
  }

  async function doSignPdf() {
    if (!prepared || !confirmed) return;
    if (!file?.name.toLowerCase().endsWith(".pdf")) {
      setError("Luồng ký PDF PAdES-B-LT chỉ nhận file PDF.");
      return;
    }
    setError("");
    setBusy("sign-pdf");
    try {
      setPdfResult(await signPdf(prepared.request_id));
      await refreshHistory();
    } catch (e: any) {
      setError(e.message || String(e));
    } finally {
      setBusy("");
    }
  }

  async function doRemoteSignPdf() {
    if (!prepared || !confirmed) return;
    if (!file?.name.toLowerCase().endsWith(".pdf")) {
      setError("Remote PDF signing requires a PDF file.");
      return;
    }
    setError("");
    setBusy("remote-sign-pdf");
    try {
      setRemotePdfResult(await remoteSignPdf(prepared.request_id, mfaCode));
      await refreshHistory();
    } catch (e: any) {
      setError(e.message || String(e));
    } finally {
      setBusy("");
    }
  }

  async function doVerifyPdf() {
    if (!verifyFile) return;
    setError("");
    setBusy("verify-pdf");
    try {
      setVerifyReport(await verifyPdf(verifyFile));
    } catch (e: any) {
      setError(e.message || String(e));
    } finally {
      setBusy("");
    }
  }

  return (
    <section className="card mode-page signing-page" aria-busy={!!busy}>
      <div className="section-title mode-header">
        <div>
          <h2>User Signing Mode</h2>
          <p>Giao diện mô phỏng người dùng thật: chọn tài liệu, xác nhận ý chí ký, ký và xem kết quả xác minh.</p>
        </div>
        <div className="mode-outcome">
          <strong>Primary job</strong>
          <span>Prepare, approve, sign, and verify one PDF.</span>
        </div>
      </div>

      {error && <div className="error" role="alert">{error}</div>}

      <div className="user-grid">
        <aside className="sidebar-card identity-panel">
          <h3>Người ký</h3>
          <span className="demo-badge">Demo user</span>
          <p><strong>{workspace?.user?.name || "Alice Demo Signer"}</strong></p>
          <p>{workspace?.user?.email || "alice@example.com"}</p>

          <h3>Chứng thư đang dùng</h3>
          {cert ? (
            <div className="cert-box">
              <p><span>Signer</span><strong>{cert.subject?.split(",")[0]?.replace("CN=","") || cert.subject}</strong></p>
              <p><span>Email</span><strong>{cert.subject?.match(/emailAddress=([^,]+)/)?.[1] || "alice@example.com"}</strong></p>
              <p><span>Serial</span><strong>{cert.serial ? cert.serial.slice(0, 24) + "…" : ""}</strong></p>
              <p><span>Status</span><strong className="green">{cert.status}</strong></p>
              <p><span>Public key</span><strong>{cert.public_key_algorithm} {cert.public_key_size}</strong></p>
              <p><span>Document signature</span><strong>{cert.document_signature_algorithm}</strong></p>
              <p><span>Digest</span><strong>{cert.digest_algorithm}</strong></p>
              <p><span>Key source</span><strong>{keySource}</strong></p>
              <p><span>Private key custody</span><strong>{cert.private_key_custody || "unknown"}</strong></p>
              <p><span>Backend has private key</span><strong>{String(cert.backend_has_private_key ?? false)}</strong></p>
              <p><span>Target profile</span><strong>PAdES-B-LT</strong></p>
              {backendPadesBlocked && (
                <p className="hint" style={{color: "#b45309"}}>
                  Backend PAdES signing is disabled for this certificate. Use browser/external client signing for canonical payloads.
                </p>
              )}
              <details className="advanced-demo">
                <summary>Certificate details</summary>
                <div className="cert-box" style={{marginTop: "8px"}}>
                  <p><span>Subject</span><strong>{cert.subject}</strong></p>
                  <p><span>Issuer</span><strong>{cert.issuer}</strong></p>
                  <p><span>Certificate signature</span><strong>{cert.certificate_signature_algorithm}</strong></p>
                  <p><span>Profile</span><strong>{cert.certificate_profile}</strong></p>
                  <p><span>Standards</span><strong>{cert.standards?.join(", ")}</strong></p>
                </div>
              </details>
            </div>
          ) : <p>Đang tải chứng thư...</p>}
        </aside>

        <div className="main-flow signing-flow">
          <div className="progress">
            <div className={file ? "done" : ""}>1. Chọn tài liệu</div>
            <div className={prepared ? "done" : ""}>2. Tạo yêu cầu ký</div>
            <div className={confirmed ? "done" : ""}>3. Xác nhận ý chí ký</div>
            <div className={pdfResult || result ? "done" : ""}>4. Ký & xác minh</div>
          </div>

          <div className="form-card primary-task-card">
            <label htmlFor="signing-file">Tài liệu cần ký</label>
            <input id="signing-file" type="file" accept="application/pdf,.pdf" onChange={e => setFile(e.target.files?.[0] || null)} />

            <label htmlFor="signing-purpose">Mục đích ký</label>
            <input id="signing-purpose" value={purpose} onChange={e => setPurpose(e.target.value)} />

            <label htmlFor="digest-algorithm">Digest algorithm</label>
            <select
              id="digest-algorithm"
              value={digestAlgorithm}
              onChange={e => setDigestAlgorithm(e.target.value)}
            >
              {DIGEST_OPTIONS.map(opt => (
                <option key={opt.value} value={opt.value}>
                  {opt.label}{opt.note ? ` (${opt.note})` : ""}
                </option>
              ))}
            </select>
            {isExperimental && (
              <p className="hint" style={{color: "#e67e22", marginTop: "4px"}}>
                ⚠ SHA-3 is experimental and not enabled for PAdES/PDF signing. Use SHA-256/SHA-384/SHA-512 for PAdES.
              </p>
            )}
            {!isExperimental && digestAlgorithm === "sha256" && (
              <p className="hint" style={{marginTop: "4px"}}>
                SHA-256 is recommended for maximum PDF/PAdES validator compatibility.
              </p>
            )}

            <div className="actions">
              <button type="button" onClick={doPrepare} disabled={!file || !!busy}>{busy === "prepare" ? "Đang tạo..." : "Tạo yêu cầu ký"}</button>
              <button type="button" onClick={doConfirm} disabled={!prepared || !!busy}>{busy === "confirm" ? "Đang xác nhận..." : "Xác nhận OTP/TOTP"}</button>
              <button className="primary" type="button" onClick={doSignPdf} disabled={!confirmed || !!busy || isExperimental || !!backendPadesBlocked}>{busy === "sign-pdf" ? "Đang ký PDF..." : "Ký PDF PAdES-B-LT"}</button>
            </div>
            {backendPadesBlocked && (
              <p className="hint" style={{color: "#b45309"}}>
                Client-side key certificates cannot be used with backend PAdES signing yet. They can be used in the canonical payload client-side signing demo.
              </p>
            )}
            <details className="advanced-demo">
              <summary>Advanced demo: ký canonical payload</summary>
              <p className="hint">Flow chính của User Mode là ký PDF/PAdES. Nút này chỉ phục vụ thuyết trình cơ chế hash, nonce và canonical JSON.</p>
              <p className="hint">Client-side key certificates cannot be used with backend PAdES signing yet. They can be used in the canonical payload client-side signing demo.</p>
              <button type="button" onClick={doSign} disabled={!confirmed || !!busy || !!backendPadesBlocked}>{busy === "sign" ? "Đang ký..." : "Ký payload demo"}</button>
            </details>
            <details className="advanced-demo">
              <summary>Advanced demo: Remote sign PDF</summary>
              <p className="hint">Remote signing uses a demo backend key with MFA check. Production requires HSM/KMS/qualified remote signing service.</p>
              <label htmlFor="mfa-code">MFA code (demo: 000000)</label>
              <input id="mfa-code" value={mfaCode} onChange={e => setMfaCode(e.target.value)} placeholder="000000" style={{maxWidth: "160px"}} />
              <button type="button" onClick={doRemoteSignPdf} disabled={!confirmed || !!busy || isExperimental || !!backendPadesBlocked}>{busy === "remote-sign-pdf" ? "Đang ký..." : "Remote sign PDF demo"}</button>
            </details>
          </div>

          {prepared && (
            <div className="summary-card">
              <h3>Yêu cầu ký đã được tạo</h3>
              <div className="summary-grid">
                <p><span>Mã yêu cầu</span><strong>{prepared.request_id}</strong></p>
                <p><span>Tài liệu</span><strong>{prepared.document_name}</strong></p>
                <p><span>Hash</span><strong>{prepared.document_hash.slice(0, 24)}...</strong></p>
                <p><span>Hash algorithm</span><strong>{prepared.hash_algorithm}</strong></p>
                <p><span>Chứng thư</span><strong>{prepared.certificate_serial}</strong></p>
              </div>
              {prepared.advanced?.digest_policy?.is_experimental && (
                <p className="hint" style={{color: "#e67e22"}}>
                  ⚠ {prepared.advanced.digest_policy.experimental_warning}
                </p>
              )}
              <p className="hint">Hệ thống đã tạo payload chuẩn hóa và nonce để chống sửa ngữ cảnh ký.</p>
              <AdvancedDetails data={prepared.advanced} />
            </div>
          )}

          {confirmed && (
            <div className="summary-card good">
              <h3>Ý chí ký đã được xác nhận</h3>
              <p>{confirmed.message}</p>
            </div>
          )}

          {pdfResult && (
            <div className="summary-card good">
              <h3>PDF đã được ký</h3>
              <p>Target profile: <strong>{pdfResult.metadata?.target_profile || "PAdES-B-LT"}</strong>; achieved profile: <strong>{pdfResult.metadata?.achieved_profile}</strong></p>
              <p>Signed file ID: <code>{pdfResult.file_id}</code></p>
              <DownloadSignedPdfButton fileId={pdfResult.file_id} />
              <VerificationSummary report={pdfResult.verification} title="Signed PDF verification" />
              <AdvancedDetails data={pdfResult.advanced} />
            </div>
          )}

          {remotePdfResult && (
            <div className="summary-card good">
              <h3>PDF đã được ký qua Remote Signing</h3>
              <p>Remote signing policy: <strong>{remotePdfResult.remote_signing?.policy}</strong></p>
              <p>Key custody: <strong>{remotePdfResult.remote_signing?.keyCustody}</strong></p>
              {remotePdfResult.file_id && <DownloadSignedPdfButton fileId={remotePdfResult.file_id} />}
              {remotePdfResult.verification && <VerificationSummary report={remotePdfResult.verification} title="Remote signed PDF verification" />}
              <AdvancedDetails data={remotePdfResult} />
            </div>
          )}

          {result && (
            <div className={result.status === "accepted" ? "final-card accepted" : "final-card rejected"} aria-live="polite">
              <h2>{result.title}</h2>
              <p>{result.message}</p>

              <div className="checks">
                {result.checks.map((check: any) => <CheckCard key={check.key} check={check} />)}
              </div>

              <div className="legal-box">
                <strong>Legal readiness: {String(result.legal_ready)}</strong>
                <p>Demo chưa coi là sẵn sàng pháp lý vì chưa dùng CA công cộng, HSM/KMS, OCSP/CRL thật, RFC3161 TSA thật và PAdES-LTV đầy đủ.</p>
              </div>

              {result.warnings?.length > 0 && (
                <div className="warning-box">
                  <strong>Cảnh báo demo</strong>
                  <ul>{result.warnings.map((w: string) => <li key={w}>{w}</li>)}</ul>
                </div>
              )}

              <AdvancedDetails data={result.advanced} />
            </div>
          )}

          <div className="summary-card">
            <h3>Verify another signed PDF</h3>
            <p className="hint">Dùng để kiểm tra một PDF đã ký độc lập với signing request hiện tại.</p>
            <div className="actions">
              <label className="sr-only" htmlFor="verify-file">Signed PDF to verify</label>
              <input id="verify-file" type="file" accept="application/pdf,.pdf" onChange={e => setVerifyFile(e.target.files?.[0] || null)} />
              <button type="button" onClick={doVerifyPdf} disabled={!verifyFile || !!busy}>{busy === "verify-pdf" ? "Đang verify..." : "Verify PDF"}</button>
            </div>
            {verifyReport && <VerificationSummary report={verifyReport} title="Uploaded PDF verification" />}
          </div>

          <div className="summary-card">
            <h3>Signing history</h3>
            <p className="hint">Phase 1/2 demo: lịch sử ký hiện lưu trong memory của backend. Restart backend sẽ mất history; Phase 6 mới DB hóa.</p>
            {history.length > 0 ? (
              <div className="history-list">
                {history.map(item => (
                  <div className="history-item" key={item.file_id}>
                    <div>
                      <strong>{item.original_filename}</strong>
                      <p>{item.target_profile || "PAdES-B-LT"} → {item.achieved_profile || item.pades_profile} · {new Date(item.created_at).toLocaleString()}</p>
                      <code>{item.file_id}</code>
                    </div>
                    <DownloadSignedPdfButton fileId={item.file_id} />
                  </div>
                ))}
              </div>
            ) : <p className="hint">Chưa có signed PDF nào trong phiên backend hiện tại.</p>}
          </div>
        </div>
      </div>
    </section>
  );
}
