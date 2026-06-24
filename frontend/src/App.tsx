import React, { useState } from "react";
import { createRoot } from "react-dom/client";
import { PipelineDemoPage } from "./modes/PipelineDemoPage";
import { UserSigningPage } from "./modes/UserSigningPage";
import { BlindSignaturePage } from "./modes/BlindSignaturePage";
import { CertificateLifecyclePage } from "./modes/CertificateLifecyclePage";
import "./styles/main.css";

type Mode = "pipeline" | "user" | "certificates" | "blind";

function App() {
  const [mode, setMode] = useState<Mode>("user");

  return (
    <main className="app">
      <header className="hero">
        <div>
          <h1>SecureDoc Full Demo v4</h1>
          <p>End-to-end digital signature web demo: PKI, X.509, signing protocol, services, blind signature, application.</p>
        </div>
      </header>

      <nav className="tabs">
        <button className={mode === "user" ? "active" : ""} onClick={() => setMode("user")}>User Signing</button>
        <button className={mode === "certificates" ? "active" : ""} onClick={() => setMode("certificates")}>Certificate Lifecycle</button>
        <button className={mode === "pipeline" ? "active" : ""} onClick={() => setMode("pipeline")}>Pipeline / ATTT Demo</button>
        <button className={mode === "blind" ? "active" : ""} onClick={() => setMode("blind")}>Blind Signature</button>
      </nav>

      {mode === "user" && <UserSigningPage />}
      {mode === "certificates" && <CertificateLifecyclePage />}
      {mode === "pipeline" && <PipelineDemoPage />}
      {mode === "blind" && <BlindSignaturePage />}
    </main>
  );
}

createRoot(document.getElementById("root")!).render(<App />);
