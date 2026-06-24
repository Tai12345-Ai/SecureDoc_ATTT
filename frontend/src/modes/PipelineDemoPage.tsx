import React, { useEffect, useState } from "react";
import { getPipelineSteps, getPipelineStepDetail, runFullPipeline } from "../api/client";
import { CheckCard } from "../components/CheckCard";
import { AdvancedDetails } from "../components/AdvancedDetails";

export function PipelineDemoPage() {
  const [steps, setSteps] = useState<any[]>([]);
  const [selected, setSelected] = useState<any>(null);
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

  return (
    <section className="card">
      <div className="section-title">
        <div>
          <h2>Pipeline / ATTT Demo</h2>
          <p>Chế độ này phác họa full pipeline end-to-end và gắn từng bước với kiến thức ATTT.</p>
        </div>
        <button className="primary" onClick={run}>{busy ? "Đang chạy..." : "Run full pipeline"}</button>
      </div>

      <div className="pipeline-layout">
        <div className="step-list">
          {steps.map((s, i) => (
            <button className="step-button" key={s.id} onClick={() => clickStep(s.id)}>
              <span>{i + 1}</span>
              <div>
                <strong>{s.title}</strong>
                <p>{s.user_explanation}</p>
              </div>
            </button>
          ))}
        </div>

        <aside className="thinking-panel">
          <h3>Thinking / Explain Panel</h3>
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
        <div className="final-card accepted">
          <h2>{full.title}</h2>
          <p>{full.summary}</p>

          <h3>Verification checks</h3>
          <div className="checks">
            {full.result.checks.map((c: any) => <CheckCard key={c.key} check={c} />)}
          </div>

          <div className="artifact-overview">
            <div><strong>PKI</strong><p>{full.pki.chain.join(" → ")}</p></div>
            <div><strong>Certificate</strong><p>{full.pki.user_certificate.subject}</p></div>
            <div><strong>Request</strong><p>{full.prepared.request_id}</p></div>
            <div><strong>PAdES Adapter</strong><p>{full.padesAdapter.status}</p></div>
          </div>

          <AdvancedDetails data={full} />
        </div>
      )}
    </section>
  );
}
