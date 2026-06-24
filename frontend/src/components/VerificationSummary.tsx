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

  return (
    <div className={report.accepted ? "final-card accepted" : "final-card rejected"}>
      <div className="section-title compact">
        <div>
          <h2>{title}</h2>
          <p>{report.message}</p>
        </div>
        <div className={report.accepted ? "status-pill ok" : "status-pill bad"}>
          {report.accepted ? "Accepted" : "Not accepted"}
        </div>
      </div>

      <div className="summary-grid">
        <p><span>Kết quả</span><strong>{report.accepted ? "Chữ ký hợp lệ" : "Không hợp lệ"}</strong></p>
        <p><span>Profile</span><strong>{details.pades_profile || "PAdES-B-B demo"}</strong></p>
        <p><span>Checks passed</span><strong>{passed}/{total}</strong></p>
        <p><span>Người ký</span><strong>{details.signer_subject || "Không xác định"}</strong></p>
        <p><span>Serial chứng thư</span><strong>{details.signer_serial || "Không xác định"}</strong></p>
        <p><span>Issuer</span><strong>{details.signer_issuer || "Không xác định"}</strong></p>
        <p><span>Signature field</span><strong>{details.signature_field || "Không có"}</strong></p>
        <p><span>Số chữ ký</span><strong>{details.signature_count ?? 0}</strong></p>
        <p><span>Coverage</span><strong>{details.coverage || "Không xác định"}</strong></p>
        <p><span>Digest</span><strong>{details.digest_algorithm || "SHA-256"}</strong></p>
      </div>

      <div className="checks">
        {report.checks?.map((check: any) => <CheckCard key={check.key} check={check} />)}
      </div>

      <div className="legal-box">
        <strong>Legal readiness: {String(report.legal_ready)}</strong>
        <p>Phase 1 mới đạt PAdES-B-B demo. Timestamp RFC3161, revocation OCSP/CRL và key custody thật thuộc các phase sau.</p>
      </div>

      {report.warnings?.length > 0 && (
        <div className="warning-box">
          <strong>Cảnh báo demo</strong>
          <ul>{report.warnings.map((warning: string) => <li key={warning}>{warning}</li>)}</ul>
        </div>
      )}

      <AdvancedDetails data={report.advanced} />
    </div>
  );
}
