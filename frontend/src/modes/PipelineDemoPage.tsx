import React, { useEffect, useState } from "react";
import { getPipelineSteps, getPipelineStepDetail, runFullPipeline } from "../api/client";
import { CheckCard } from "../components/CheckCard";
import { AdvancedDetails } from "../components/AdvancedDetails";

const actors = [
  {
    name: "CA / PKI",
    role: "Cấp và quản lý chứng thư số",
    boundary: "Root CA → Intermediate CA → User Signing Certificate",
  },
  {
    name: "User / Signer",
    role: "Upload PDF, xác nhận ý chí ký và tạo chữ ký",
    boundary: "User Signing Mode",
  },
  {
    name: "Verifier",
    role: "Kiểm tra chữ ký, tài liệu và chứng thư",
    boundary: "Verification Service",
  },
  {
    name: "Trust Services",
    role: "Timestamp, revocation, audit, key custody",
    boundary: "Security Services / Trust & Key Services",
  },
];

const timeline = [
  {
    phase: "CA setup",
    title: "Init CA hierarchy",
    actor: "CA / PKI",
    what: "Khởi tạo Root CA và Intermediate CA demo.",
    artifact: "root_ca_cert.pem, intermediate_ca_cert.pem",
    baseline: "EJBCA / pyca-cryptography",
  },
  {
    phase: "Certificate lifecycle",
    title: "Enroll user public key",
    actor: "User + CA",
    what: "User gửi public key và proof-of-possession để chứng minh đang sở hữu private key.",
    artifact: "enrollment request, challenge, PoP signature",
    baseline: "EJBCA / WebCrypto / pyca-cryptography",
  },
  {
    phase: "Certificate lifecycle",
    title: "Issue X.509 certificate",
    actor: "CA Officer",
    what: "Intermediate CA ký và cấp User Signing Certificate.",
    artifact: "user_signing_cert.pem",
    baseline: "EJBCA / X.509",
  },
  {
    phase: "User signing",
    title: "Upload and hash PDF",
    actor: "User / Signing Service",
    what: "User chọn PDF; backend tính SHA-256 để ràng buộc chữ ký với nội dung tài liệu.",
    artifact: "documentHash",
    baseline: "Digital signature with hash",
  },
  {
    phase: "Signing protocol",
    title: "Prepare signing request",
    actor: "Signing Service",
    what: "Tạo requestId, nonce, certificateSerial, signingPurpose và canonical payload.",
    artifact: "signingRequest, canonicalPayload",
    baseline: "DSS-style signing protocol",
  },
  {
    phase: "Signing protocol",
    title: "Confirm signing intent",
    actor: "User",
    what: "User xác nhận ý chí ký trước khi private key hoặc signing service tạo chữ ký.",
    artifact: "confirmedIntent audit event",
    baseline: "SignServer-style policy check",
  },
  {
    phase: "PAdES signing",
    title: "Sign PDF/PAdES-B-LT",
    actor: "Signer / PAdES Service",
    what: "pyHanko tạo PDF signature với target PAdES-B-LT; B-B/B-T chỉ là bước nội bộ.",
    artifact: "signed.pdf",
    baseline: "pyHanko",
  },
  {
    phase: "Verification",
    title: "Verify PDF signature",
    actor: "Verifier",
    what: "Kiểm tra chữ ký mật mã, tính toàn vẹn tài liệu, certificate chain và profile.",
    artifact: "verificationReport",
    baseline: "DSS validation / pyHanko validation",
  },
  {
    phase: "Trust services",
    title: "Issue timestamp token",
    actor: "Timestamp Service",
    what: "Ký message imprint bằng TSA key riêng để mô phỏng bằng chứng thời điểm.",
    artifact: "signed TSA token demo",
    baseline: "DSS timestamp / pyHanko RFC3161 direction",
  },
  {
    phase: "Trust services",
    title: "Check revocation status",
    actor: "Revocation Service",
    what: "Kiểm tra certificate serial còn good hay đã revoked; xem demo CRL.",
    artifact: "revocationStatus, demoCRL",
    baseline: "EJBCA / DSS validation",
  },
  {
    phase: "Audit",
    title: "Write audit event",
    actor: "Audit Service",
    what: "Ghi lại sự kiện prepare, confirm, sign, verify để phục vụ truy vết và chống chối bỏ ở mức demo.",
    artifact: "auditEvent hash chain",
    baseline: "SignServer / DSS audit direction",
  },
];

export function PipelineDemoPage() {
  const [steps, setSteps] = useState<any[]>([]);
  const [selected, setSelected] = useState<any>(null);
  const [selectedTimeline, setSelectedTimeline] = useState<any>(timeline[0]);
  const [full, setFull] = useState<any>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    getPipelineSteps().then(async data => {
      setSteps(data);
      if (data[0]) setSelected(await getPipelineStepDetail(data[0].id));
    });
  }, []);

  async function clickStep(id: string) {
    setSelected(await getPipelineStepDetail(id));
  }

  async function run() {
    setBusy(true);
    try {
      setFull(await runFullPipeline());
    } finally {
      setBusy(false);
    }
  }

  const verificationChecks = full?.result?.checks || [];

  return (
    <section className="card mode-page pipeline-page" aria-busy={busy}>
      <div className="section-title mode-header">
        <div>
          <h2>End-to-End Pipeline / ATTT Demo</h2>
          <p>Trang này không phải user flow chính. Đây là timeline thuyết trình để nối CA, user signing, verification và trust services thành một pipeline chữ ký số hoàn chỉnh.</p>
        </div>
        <div className="mode-outcome action-outcome">
          <strong>Demo run</strong>
          <span>Execute the full CA to verification path.</span>
          <button className="primary" type="button" onClick={run}>{busy ? "Đang chạy..." : "Run full pipeline"}</button>
        </div>
      </div>

      <div className="role-grid actor-grid">
        {actors.map(actor => (
          <div className="role-card" key={actor.name}>
            <strong>{actor.name}</strong>
            <p>{actor.role}</p>
            <code>{actor.boundary}</code>
          </div>
        ))}
      </div>

      <div className="pipeline-guide narrative-grid">
        <div className="summary-card no-margin narrative-card">
          <h3>Pipeline end-to-end thực sự</h3>
          <p className="hint">CA cấp chứng thư → user ký PDF → verifier kiểm tra → trust services bổ sung timestamp/revocation/audit. Nút Run full pipeline chạy nhanh một mẫu tự động; timeline dưới đây giải thích từng artifact.</p>
          <div className="timeline-list">
            {timeline.map((item, index) => (
              <button
                key={`${item.phase}-${item.title}`}
                className={selectedTimeline?.title === item.title ? "timeline-step active" : "timeline-step"}
                type="button"
                aria-pressed={selectedTimeline?.title === item.title}
                onClick={() => setSelectedTimeline(item)}
              >
                <span>{index + 1}</span>
                <div>
                  <strong>{item.title}</strong>
                  <p>{item.actor} · {item.phase}</p>
                </div>
              </button>
            ))}
          </div>
        </div>

        <aside className="thinking-panel">
          <h3>Selected timeline step</h3>
          {selectedTimeline && (
            <>
              <h4>{selectedTimeline.title}</h4>
              <p><strong>Actor:</strong> {selectedTimeline.actor}</p>
              <p><strong>Việc xảy ra:</strong> {selectedTimeline.what}</p>
              <p><strong>Artifact:</strong> <code>{selectedTimeline.artifact}</code></p>
              <p><strong>Baseline:</strong> {selectedTimeline.baseline}</p>
            </>
          )}
        </aside>
      </div>

      <div className="pipeline-layout mt-18 mapping-grid">
        <div className="step-list">
          <h3>Mapping với đề tài ATTT</h3>
          {steps.map((s, i) => (
            <button className="step-button" key={s.id} type="button" onClick={() => clickStep(s.id)}>
              <span>{i + 1}</span>
              <div>
                <strong>{s.title}</strong>
                <p>{s.user_explanation}</p>
              </div>
            </button>
          ))}
        </div>

        <aside className="thinking-panel">
          <h3>Explain Panel</h3>
          {selected ? (
            <>
              <h4>{selected.step.title}</h4>
              <p><strong>User thấy:</strong> {selected.thinking_panel.what_user_sees}</p>
              <p><strong>Hệ thống làm ngầm:</strong> {selected.thinking_panel.what_system_does}</p>
              <p><strong>Service:</strong> {selected.thinking_panel.service_boundary}</p>
              <div className="artifact-tags">
                {selected.thinking_panel.artifacts.map((a: string) => <span key={a}>{a}</span>)}
              </div>
            </>
          ) : <p>Chọn một bước.</p>}
        </aside>
      </div>

      {full && (
        <div className="final-card accepted" aria-live="polite">
          <h2>{full.title}</h2>
          <p>{full.summary}</p>

          <h3>Verification checks</h3>
          <div className="checks">
            {verificationChecks.map((c: any) => <CheckCard key={c.key} check={c} />)}
          </div>

          <div className="artifact-overview">
            <div><strong>PKI</strong><p>{full.pki?.chain?.join(" → ")}</p></div>
            <div><strong>Certificate</strong><p>{full.pki?.user_certificate?.subject}</p></div>
            <div><strong>Request</strong><p>{full.prepared?.request_id}</p></div>
            <div><strong>PAdES</strong><p>{full.padesAdapter?.status}</p></div>
          </div>

          <AdvancedDetails data={full} />
        </div>
      )}
    </section>
  );
}
