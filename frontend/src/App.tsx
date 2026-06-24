import React, { useState } from "react";
import { createRoot } from "react-dom/client";
import { PipelineDemoPage } from "./modes/PipelineDemoPage";
import { UserSigningPage } from "./modes/UserSigningPage";
import { BlindSignaturePage } from "./modes/BlindSignaturePage";
import { CertificateLifecyclePage } from "./modes/CertificateLifecyclePage";
import { SecurityServicesPage } from "./modes/SecurityServicesPage";
import "./styles/main.css";

type Mode = "pipeline" | "user" | "certificates" | "security" | "blind";

function App() {
  const [mode, setMode] = useState<Mode>("user");

  return (
    <main className="app">
      <header className="hero">
        <div>
          <h1>SecureDoc ATTT — Digital Signature Demo</h1>
          <p>Educational prototype mô phỏng hệ thống chữ ký số end-to-end: CA/PKI, X.509, PDF/PAdES, verification, trust services, remote signing và chữ ký mù.</p>
        </div>
      </header>

      <nav className="tabs">
        <button className={mode === "user" ? "active" : ""} onClick={() => setMode("user")}>User Signing</button>
        <button className={mode === "certificates" ? "active" : ""} onClick={() => setMode("certificates")}>CA / Certificate Lifecycle</button>
        <button className={mode === "security" ? "active" : ""} onClick={() => setMode("security")}>Trust & Key Services</button>
        <button className={mode === "pipeline" ? "active" : ""} onClick={() => setMode("pipeline")}>End-to-End Pipeline</button>
        <button className={mode === "blind" ? "active" : ""} onClick={() => setMode("blind")}>Blind Signature</button>
      </nav>

      {mode === "user" && <UserSigningPage />}
      {mode === "certificates" && <CertificateLifecyclePage />}
      {mode === "security" && <SecurityServicesPage />}
      {mode === "pipeline" && <PipelineDemoPage />}
      {mode === "blind" && <BlindSignaturePage />}
    </main>
  );
}

createRoot(document.getElementById("root")!).render(<App />);
