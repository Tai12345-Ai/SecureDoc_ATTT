import React from "react";

export function AdvancedDetails({ data }: { data: any }) {
  if (!data) return null;
  return (
    <details className="advanced">
      <summary>Advanced technical details</summary>
      <pre>{JSON.stringify(data, null, 2)}</pre>
    </details>
  );
}
