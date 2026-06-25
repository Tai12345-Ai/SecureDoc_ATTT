import React from "react";
import { CheckCard } from "./CheckCard";
import { AdvancedDetails } from "./AdvancedDetails";

type Props = {
  report: any;
  title?: string;
};

export function VerificationSummary({ report, title = "PDF verification report" }: Props) {
  if (!report) return null;
  const details = report.advanced || {};
  const passed = report.checks?.filter((check: any) => check.ok).length || 0;
  const total = report.checks?.length || 0;
  const timestamp = details.timestamp_status || {};
  const revocation = details.revocation_evidence_status || {};

  return (
    <div className={report.accepted ? "final-card accepted" : "final-card rejected"} aria-live="polite">
      <div className="section-title compact">
        <div>
          <h2>{title}</h2>
          <p>{report.message}</p>
        </div>
        <div className={report.accepted ? "status-pill ok" : "status-pill bad"} aria-label={`Verification status: ${report.accepted ? "Accepted" : "Not accepted"}`}>
          {report.accepted ? "Accepted" : "Not accepted"}
        </div>
      </div>

      <div className="summary-grid">
        <p><span>Kết quả</span><strong>{report.accepted ? "Chữ ký hợp lệ" : "Không hợp lệ"}</strong></p>
        <p><span>Target profile</span><strong>{details.target_profile || "PAdES-B-LT"}</strong></p>
        <p><span>Achieved profile</span><strong>{details.achieved_profile || details.pades_profile || "Không xác định"}</strong></p>
        {details.missing_requirements?.length > 0 && (
          <p><span>Missing for target</span><strong>{details.missing_requirements.join(", ")}</strong></p>
        )}
        <p><span>Checks passed</span><strong>{passed}/{total}</strong></p>
        <p><span>Digest</span><strong>{details.digest_algorithm || "SHA-256"}</strong></p>
        <p><span>Signature algorithm</span><strong>{details.signature_algorithm || "RSA-PSS"}</strong></p>
        <p><span>Timestamp</span><strong>{timestamp.state || "missing"}</strong></p>
        <p><span>Revocation evidence</span><strong>{revocation.state || "missing"}</strong></p>
        <p><span>Certificate chain</span><strong>{details.certificate_chain_status || "Không xác định"}</strong></p>
      </div>

      <div className="checks">
        {report.checks?.map((check: any) => <CheckCard key={check.key} check={check} />)}
      </div>

      <div className="badge-row">
        <span className="small-badge">Legal readiness: {String(report.legal_ready)}</span>
      </div>

      {report.warnings?.length > 0 && (
        <details className="warning-box">
          <summary>Cảnh báo demo</summary>
          <ul>{report.warnings.map((warning: string) => <li key={warning}>{warning}</li>)}</ul>
        </details>
      )}

      <AdvancedDetails data={report.advanced} />
    </div>
  );
}
