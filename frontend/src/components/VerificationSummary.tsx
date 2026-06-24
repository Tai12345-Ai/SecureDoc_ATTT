import React from "react";
import { CheckCard } from "./CheckCard";
import { AdvancedDetails } from "./AdvancedDetails";

type Props = {
  report: any;
  title?: string;
};

export function VerificationSummary({ report, title = "PDF verification report" }: Props) {
  if (!report) return null;

  return (
    <div className={report.accepted ? "final-card accepted" : "final-card rejected"}>
      <h2>{title}</h2>
      <p>{report.message}</p>

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
