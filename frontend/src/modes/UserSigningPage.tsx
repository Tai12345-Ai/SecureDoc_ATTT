import React, { useEffect, useState } from "react";
import { getUserWorkspace, prepareSigningRequest, confirmSigningIntent, signAndVerify, signPdf, verifyPdf, getSigningHistory } from "../api/client";
import { CheckCard } from "../components/CheckCard";
import { AdvancedDetails } from "../components/AdvancedDetails";
import { DownloadSignedPdfButton } from "../components/DownloadSignedPdfButton";
import { VerificationSummary } from "../components/VerificationSummary";

export function UserSigningPage() {
  const [workspace, setWorkspace] = useState<any>(null);
  const [file, setFile] = useState<File | null>(null);
  const [purpose, setPurpose] = useState("Ký xác nhận tài liệu demo");
  const [prepared, setPrepared] = useState<any>(null);
  const [confirmed, setConfirmed] = useState<any>(null);
  const [result, setResult] = useState<any>(null);
  const [pdfResult, setPdfResult] = useState<any>(null);
  const [verifyFile, setVerifyFile] = useState<File | null>(null);
  const [verifyReport, setVerifyReport] = useState<any>(null);
  const [history, setHistory] = useState<any[]>([]);
  const [busy, setBusy] = useState("");
  const [error, setError] = useState("");

  useEffect(() => {
    getUserWorkspace().then(setWorkspace).catch(e => setError(String(e)));
    refreshHistory();
  }, []);

  const cert = workspace?.certificate;

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
    try {
      setPrepared(await prepareSigningRequest(file, purpose, cert.serial));
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
      setError("Phase 1 ký PAdES chỉ nhận file PDF.");
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
    <section className="card">
      <div className="section-title">
        <div>
          <h2>User Signing Mode</h2>
          <p>Giao diện mô phỏng người dùng thật: chọn tài liệu, xác nhận ý chí ký, ký và xem kết quả xác minh.</p>
        </div>
        <div className="mode-pill">Production-like UX</div>
      </div>

      {error && <div className="error">{error}</div>}

      <div className="user-grid">
        <aside className="sidebar-card">
          <h3>Người ký</h3>
          <p><strong>{workspace?.user?.name || "Alice Demo Signer"}</strong></p>
          <p>{workspace?.user?.email || "alice@example.com"}</p>

          <h3>Chứng thư đang dùng</h3>
          {cert ? (
            <div className="cert-box">
              <p><span>Serial</span><strong>{cert.serial}</strong></p>
              <p><span>Subject</span><strong>{cert.subject}</strong></p>
              <p><span>Issuer</span><strong>{cert.issuer}</strong></p>
              <p><span>Status</span><strong className="green">{cert.status}</strong></p>
              <p><span>Algorithm</span><strong>{cert.algorithm}</strong></p>
            </div>
          ) : <p>Đang tải chứng thư...</p>}
        </aside>

        <div className="main-flow">
          <div className="progress">
            <div className={file ? "done" : ""}>1. Chọn tài liệu</div>
            <div className={prepared ? "done" : ""}>2. Tạo yêu cầu ký</div>
            <div className={confirmed ? "done" : ""}>3. Xác nhận ý chí ký</div>
            <div className={pdfResult || result ? "done" : ""}>4. Ký & xác minh</div>
          </div>

          <div className="form-card">
            <label>Tài liệu cần ký</label>
            <input type="file" accept="application/pdf,.pdf" onChange={e => setFile(e.target.files?.[0] || null)} />

            <label>Mục đích ký</label>
            <input value={purpose} onChange={e => setPurpose(e.target.value)} />

            <div className="actions">
              <button onClick={doPrepare} disabled={!file || !!busy}>{busy === "prepare" ? "Đang tạo..." : "Tạo yêu cầu ký"}</button>
              <button onClick={doConfirm} disabled={!prepared || !!busy}>{busy === "confirm" ? "Đang xác nhận..." : "Xác nhận OTP/TOTP"}</button>
              <button className="primary" onClick={doSignPdf} disabled={!confirmed || !!busy}>{busy === "sign-pdf" ? "Đang ký PDF..." : "Ký PDF/PAdES"}</button>
            </div>
            <details className="advanced-demo">
              <summary>Advanced demo: ký canonical payload</summary>
              <p className="hint">Flow chính của User Mode là ký PDF/PAdES. Nút này chỉ phục vụ thuyết trình cơ chế hash, nonce và canonical JSON.</p>
              <button onClick={doSign} disabled={!confirmed || !!busy}>{busy === "sign" ? "Đang ký..." : "Ký payload demo"}</button>
            </details>
          </div>

          {prepared && (
            <div className="summary-card">
              <h3>Yêu cầu ký đã được tạo</h3>
              <div className="summary-grid">
                <p><span>Mã yêu cầu</span><strong>{prepared.request_id}</strong></p>
                <p><span>Tài liệu</span><strong>{prepared.document_name}</strong></p>
                <p><span>Hash</span><strong>{prepared.document_hash.slice(0, 24)}...</strong></p>
                <p><span>Chứng thư</span><strong>{prepared.certificate_serial}</strong></p>
              </div>
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
              <h3>PDF đã được ký PAdES-B-B</h3>
              <p>Signed file ID: <code>{pdfResult.file_id}</code></p>
              <DownloadSignedPdfButton fileId={pdfResult.file_id} />
              <VerificationSummary report={pdfResult.verification} title="Signed PDF verification" />
              <AdvancedDetails data={pdfResult.advanced} />
            </div>
          )}

          {result && (
            <div className={result.status === "accepted" ? "final-card accepted" : "final-card rejected"}>
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
              <input type="file" accept="application/pdf,.pdf" onChange={e => setVerifyFile(e.target.files?.[0] || null)} />
              <button onClick={doVerifyPdf} disabled={!verifyFile || !!busy}>{busy === "verify-pdf" ? "Đang verify..." : "Verify PDF"}</button>
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
                      <p>{item.pades_profile} · {new Date(item.created_at).toLocaleString()}</p>
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
