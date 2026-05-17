"use client";
import { useState } from "react";

export default function SettingsPage() {
  const [backendUrl, setBackendUrl] = useState("http://localhost:7860");
  const [model, setModel] = useState("claude-opus-4-7");
  const [slitherEnabled, setSlitherEnabled] = useState(true);
  const [mythrilEnabled, setMythrilEnabled] = useState(false);
  const [aiThreshold, setAiThreshold] = useState("0.75");
  const [alertEmail, setAlertEmail] = useState("lindahmed1011@gmail.com");
  const [slackWebhook, setSlackWebhook] = useState("");
  const [saved, setSaved] = useState(false);

  const save = () => {
    setSaved(true);
    setTimeout(() => setSaved(false), 2000);
  };

  return (
    <div className="p-6 space-y-6 max-w-4xl">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="font-headline-md text-headline-md text-on-surface">Settings</h1>
          <p className="font-body-sm text-body-sm text-on-surface-variant mt-1">
            Configure backend, models, detectors, and alerts
          </p>
        </div>
        <button
          onClick={save}
          className="flex items-center gap-2 px-6 py-2 rounded font-label-caps text-label-caps transition-all active:scale-95"
          style={{ backgroundColor: saved ? "#4cd7f6" : "#adc6ff", color: saved ? "#003544" : "#002e6a", fontSize: "11px" }}
        >
          <span className="material-symbols-outlined" style={{ fontSize: "16px" }}>
            {saved ? "check" : "save"}
          </span>
          {saved ? "SAVED" : "SAVE CHANGES"}
        </button>
      </div>

      {/* Backend */}
      <section
        className="p-5 rounded-lg space-y-4"
        style={{ backgroundColor: "#141b2b", border: "1px solid #424754" }}
      >
        <h2 className="font-headline-sm text-headline-sm text-on-surface">Backend Connection</h2>

        <div>
          <label className="font-label-caps text-label-caps text-on-surface-variant block mb-1" style={{ fontSize: "10px" }}>
            FASTAPI / GRADIO URL
          </label>
          <input
            value={backendUrl}
            onChange={(e) => setBackendUrl(e.target.value)}
            className="w-full rounded px-3 py-2 font-code-sm text-code-sm text-on-surface outline-none transition-colors"
            style={{ backgroundColor: "#191f2f", border: "1px solid #424754" }}
          />
          <p className="font-body-sm text-body-sm text-on-surface-variant mt-1">
            The ChainSentinel backend serving /assistant, /audit, and /upload endpoints.
          </p>
        </div>

        <div className="flex items-center gap-3 p-3 rounded" style={{ backgroundColor: "#0c1322", border: "1px solid #2e3545" }}>
          <div className="w-2 h-2 rounded-full animate-pulse" style={{ backgroundColor: "#4cd7f6" }} />
          <span className="font-label-caps" style={{ fontSize: "10px", color: "#4cd7f6" }}>BACKEND REACHABLE</span>
          <span className="font-code-sm text-on-surface-variant ml-auto" style={{ fontSize: "11px" }}>latency: 12ms</span>
        </div>
      </section>

      {/* AI Model */}
      <section
        className="p-5 rounded-lg space-y-4"
        style={{ backgroundColor: "#141b2b", border: "1px solid #424754" }}
      >
        <h2 className="font-headline-sm text-headline-sm text-on-surface">AI Model Configuration</h2>

        <div>
          <label className="font-label-caps text-label-caps text-on-surface-variant block mb-1" style={{ fontSize: "10px" }}>
            CLAUDE MODEL
          </label>
          <select
            value={model}
            onChange={(e) => setModel(e.target.value)}
            className="w-full rounded px-3 py-2 font-code-sm text-code-sm text-on-surface outline-none"
            style={{ backgroundColor: "#191f2f", border: "1px solid #424754" }}
          >
            <option value="claude-opus-4-7">claude-opus-4-7 (Recommended)</option>
            <option value="claude-sonnet-4-6">claude-sonnet-4-6 (Faster)</option>
            <option value="claude-haiku-4-5-20251001">claude-haiku-4-5 (Lightweight)</option>
          </select>
        </div>

        <div>
          <label className="font-label-caps text-label-caps text-on-surface-variant block mb-1" style={{ fontSize: "10px" }}>
            ANOMALY SCORE THRESHOLD
          </label>
          <div className="flex items-center gap-3">
            <input
              type="range"
              min="0"
              max="1"
              step="0.01"
              value={aiThreshold}
              onChange={(e) => setAiThreshold(e.target.value)}
              className="flex-1"
            />
            <span className="font-code-sm text-code-sm w-12 text-right" style={{ color: "#4cd7f6" }}>
              {parseFloat(aiThreshold).toFixed(2)}
            </span>
          </div>
          <p className="font-body-sm text-body-sm text-on-surface-variant mt-1">
            Scores above this value are flagged as anomalous. Lower = more sensitive.
          </p>
        </div>
      </section>

      {/* Static Analysis Tools */}
      <section
        className="p-5 rounded-lg space-y-4"
        style={{ backgroundColor: "#141b2b", border: "1px solid #424754" }}
      >
        <h2 className="font-headline-sm text-headline-sm text-on-surface">Static Analysis Tools</h2>

        {[
          { label: "Slither",  desc: "Solidity static analyzer — fast and reliable.",                       value: slitherEnabled,  set: setSlitherEnabled  },
          { label: "Mythril",  desc: "EVM bytecode symbolic execution — deeper but slower.",                value: mythrilEnabled,  set: setMythrilEnabled  },
        ].map(({ label, desc, value, set }) => (
          <div key={label} className="flex items-center justify-between py-3" style={{ borderBottom: "1px solid #2e3545" }}>
            <div>
              <p className="font-label-caps text-on-surface">{label}</p>
              <p className="font-body-sm text-body-sm text-on-surface-variant mt-0.5">{desc}</p>
            </div>
            <button
              onClick={() => set(!value)}
              className="relative w-12 h-6 rounded-full transition-colors shrink-0"
              style={{ backgroundColor: value ? "#4cd7f6" : "#2e3545" }}
            >
              <div
                className="absolute top-1 w-4 h-4 rounded-full transition-transform"
                style={{
                  backgroundColor: value ? "#003544" : "#8c909f",
                  transform: value ? "translateX(26px)" : "translateX(4px)",
                }}
              />
            </button>
          </div>
        ))}
      </section>

      {/* Alert Channels */}
      <section
        className="p-5 rounded-lg space-y-4"
        style={{ backgroundColor: "#141b2b", border: "1px solid #424754" }}
      >
        <h2 className="font-headline-sm text-headline-sm text-on-surface">Alert Channels</h2>

        <div>
          <label className="font-label-caps text-label-caps text-on-surface-variant block mb-1" style={{ fontSize: "10px" }}>
            EMAIL (CRITICAL ALERTS)
          </label>
          <input
            value={alertEmail}
            onChange={(e) => setAlertEmail(e.target.value)}
            className="w-full rounded px-3 py-2 font-code-sm text-code-sm text-on-surface outline-none"
            style={{ backgroundColor: "#191f2f", border: "1px solid #424754" }}
          />
        </div>

        <div>
          <label className="font-label-caps text-label-caps text-on-surface-variant block mb-1" style={{ fontSize: "10px" }}>
            SLACK WEBHOOK URL
          </label>
          <input
            value={slackWebhook}
            onChange={(e) => setSlackWebhook(e.target.value)}
            placeholder="https://hooks.slack.com/services/…"
            className="w-full rounded px-3 py-2 font-code-sm text-code-sm text-on-surface outline-none"
            style={{ backgroundColor: "#191f2f", border: "1px solid #424754" }}
          />
        </div>
      </section>

      {/* Workspace */}
      <section
        className="p-5 rounded-lg space-y-4"
        style={{ backgroundColor: "#141b2b", border: "1px solid #424754" }}
      >
        <h2 className="font-headline-sm text-headline-sm text-on-surface">Workspace Preferences</h2>

        <div className="grid grid-cols-2 gap-4">
          {[
            { label: "Max File Size",      value: "50 MB"    },
            { label: "Auto-run Analysis",  value: "Disabled" },
            { label: "Report Language",    value: "English"  },
            { label: "Timezone",           value: "UTC"      },
          ].map(({ label, value }) => (
            <div key={label} className="flex justify-between py-2" style={{ borderBottom: "1px solid #2e3545" }}>
              <span className="font-label-caps text-label-caps text-on-surface-variant">{label}</span>
              <span className="font-code-sm text-code-sm text-on-surface">{value}</span>
            </div>
          ))}
        </div>
      </section>

      {/* Danger zone */}
      <section
        className="p-5 rounded-lg"
        style={{ backgroundColor: "rgba(147,0,10,0.08)", border: "1px solid rgba(255,180,171,0.2)" }}
      >
        <h2 className="font-headline-sm text-headline-sm mb-3" style={{ color: "#ffb4ab" }}>Danger Zone</h2>
        <div className="flex items-center justify-between">
          <div>
            <p className="font-label-caps text-on-surface" style={{ fontSize: "11px" }}>Clear Audit History</p>
            <p className="font-body-sm text-body-sm text-on-surface-variant mt-0.5">
              Permanently delete all audit sessions and reports. Cannot be undone.
            </p>
          </div>
          <button
            className="px-4 py-2 rounded font-label-caps text-label-caps transition-colors"
            style={{ border: "1px solid rgba(255,180,171,0.4)", color: "#ffb4ab", fontSize: "11px" }}
          >
            CLEAR ALL
          </button>
        </div>
      </section>
    </div>
  );
}
