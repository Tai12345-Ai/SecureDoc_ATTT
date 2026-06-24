import React, { useRef, useState } from "react";
import { createRoot } from "react-dom/client";
import gsap from "gsap";
import { useGSAP } from "@gsap/react";
import { ScrollTrigger } from "gsap/ScrollTrigger";
import { PipelineDemoPage } from "./modes/PipelineDemoPage";
import { UserSigningPage } from "./modes/UserSigningPage";
import { BlindSignaturePage } from "./modes/BlindSignaturePage";
import { CertificateLifecyclePage } from "./modes/CertificateLifecyclePage";
import { SecurityServicesPage } from "./modes/SecurityServicesPage";
import "./styles/main.css";

gsap.registerPlugin(useGSAP, ScrollTrigger);

type Mode = "pipeline" | "user" | "certificates" | "security" | "blind";

const modes: { id: Mode; label: string }[] = [
  { id: "user", label: "User Signing" },
  { id: "certificates", label: "CA Lifecycle" },
  { id: "security", label: "Trust Services" },
  { id: "pipeline", label: "Pipeline" },
  { id: "blind", label: "Blind Signature" },
];

function App() {
  const [mode, setMode] = useState<Mode>("user");
  const shellRef = useRef<HTMLDivElement | null>(null);

  useGSAP(() => {
    if (window.matchMedia("(prefers-reduced-motion: reduce)").matches) return;

    gsap.from(".top-nav", {
      y: -18,
      opacity: 0,
      duration: 0.65,
      ease: "power3.out",
    });

    gsap.from(".hero-copy > *, .hero-visual", {
      y: 36,
      opacity: 0,
      duration: 0.9,
      stagger: 0.1,
      ease: "power3.out",
    });

    gsap.fromTo(
      ".document-preview",
      { scale: 0.92 },
      {
        scale: 1,
        duration: 1.2,
        ease: "power2.out",
        scrollTrigger: {
          trigger: ".hero",
          start: "top 75%",
          end: "bottom 35%",
          scrub: true,
        },
      },
    );

    gsap.from(".action-footer", {
      y: 48,
      opacity: 0,
      scale: 0.98,
      duration: 0.8,
      ease: "power3.out",
      scrollTrigger: {
        trigger: ".action-footer",
        start: "top 86%",
      },
    });
  }, { scope: shellRef });

  useGSAP(() => {
    if (window.matchMedia("(prefers-reduced-motion: reduce)").matches) return;

    gsap.utils.toArray<HTMLElement>(".mode-page").forEach(surface => {
      gsap.from(surface, {
        y: 48,
        opacity: 0,
        scale: 0.98,
        duration: 0.8,
        ease: "power3.out",
        scrollTrigger: {
          trigger: surface,
          start: "top 86%",
        },
      });
    });
  }, { scope: shellRef, dependencies: [mode], revertOnUpdate: true });

  return (
    <main className="app">
      <div className="app-shell" ref={shellRef}>
        <nav className="top-nav" aria-label="SecureDoc modes">
          <button className="brand-lockup" type="button" onClick={() => setMode("user")} aria-label="Go to User Signing">
            <span className="brand-mark">SD</span>
            <span>
              <strong>SecureDoc ATTT</strong>
              <small>Digital trust lab</small>
            </span>
          </button>

          <div className="tabs" role="group" aria-label="Select demo mode">
            {modes.map(item => (
              <button
                key={item.id}
                className={mode === item.id ? "active" : ""}
                type="button"
                aria-pressed={mode === item.id}
                aria-label={`${item.label}${mode === item.id ? ", current mode" : ""}`}
                onClick={() => setMode(item.id)}
              >
                {item.label}
              </button>
            ))}
          </div>
        </nav>

        <header className="hero">
          <div className="hero-copy">
            <h1>
              SecureDoc ATTT digital signature <span className="hero-inline-media" aria-hidden="true"></span> workspace
            </h1>
            <p>
              An end-to-end signing and verification demo for PDF/PAdES, CA/PKI, X.509 certificates, trust services, remote signing, and blind signatures.
            </p>
            <div className="hero-actions">
              <button className="primary" type="button" onClick={() => setMode("user")}>
                Start signing flow
              </button>
              <button className="secondary" type="button" onClick={() => setMode("pipeline")}>
                View full pipeline
              </button>
            </div>
          </div>

          <div className="hero-visual" aria-hidden="true">
            <div className="document-preview">
              <div className="document-preview-top">
                <span>PDF/PAdES</span>
                <strong>Verified</strong>
              </div>
              <div className="document-lines">
                <span></span>
                <span></span>
                <span></span>
              </div>
              <div className="signature-strip">
                <div>
                  <span>Signer</span>
                  <strong>Alice Demo Signer</strong>
                </div>
                <div>
                  <span>Digest</span>
                  <strong>SHA-256</strong>
                </div>
              </div>
              <div className="trust-stack">
                <span>CA chain</span>
                <span>Timestamp</span>
                <span>Revocation</span>
              </div>
            </div>
          </div>
        </header>

        <div className="mode-stage">
          {mode === "user" && <UserSigningPage />}
          {mode === "certificates" && <CertificateLifecyclePage />}
          {mode === "security" && <SecurityServicesPage />}
          {mode === "pipeline" && <PipelineDemoPage />}
          {mode === "blind" && <BlindSignaturePage />}
        </div>

        <section className="trust-marquee" aria-label="SecureDoc trust capabilities">
          <div className="marquee-track">
            <span>PDF/PAdES</span>
            <span>X.509</span>
            <span>CA chain</span>
            <span>Timestamp</span>
            <span>Revocation</span>
            <span>Remote signing</span>
            <span>Blind signature</span>
            <span>Audit trail</span>
          </div>
        </section>

        <footer className="action-footer">
          <div>
            <h2>Validate the trust path before the signature leaves the workspace.</h2>
            <p>Use the signing flow for document work, or run the pipeline view when you need to explain every CA, verifier, and trust-service boundary.</p>
          </div>
          <div className="footer-actions">
            <button className="primary" type="button" onClick={() => setMode("user")}>
              Open signing mode
            </button>
            <button type="button" onClick={() => setMode("security")}>
              Inspect services
            </button>
          </div>
        </footer>
      </div>
    </main>
  );
}

createRoot(document.getElementById("root")!).render(<App />);
