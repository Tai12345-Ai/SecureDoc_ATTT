import React from "react";

export function CheckCard({ check }: { check: any }) {
  return (
    <div className={check.ok ? "check-card ok" : "check-card bad"}>
      <div className="check-icon" aria-hidden="true">{check.ok ? "✓" : "×"}</div>
      <div>
        <strong>{check.label}</strong>
        <p>{check.message}</p>
      </div>
    </div>
  );
}
