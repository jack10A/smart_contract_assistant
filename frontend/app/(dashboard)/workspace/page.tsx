"use client";
import { useState } from "react";

const workspaceFiles = {
  Solidity: [
    { name: "hybrid_vulnerable_test.sol", size: "24 KB", lines: 876, indexed: true, risk: "HIGH",   lastAnalyzed: "17:45 today" },
    { name: "SafeMath.sol",               size: "4 KB",  lines: 120, indexed: true, risk: "LOW",    lastAnalyzed: "17:45 today" },
    { name: "VaultStrategy.sol",          size: "18 KB", lines: 631, indexed: true, risk: "MEDIUM", lastAnalyzed: "15:30 today" },
    { name: "GovernanceToken.sol",        size: "12 KB", lines: 440, indexed: false, risk: null,    lastAnalyzed: "—" },
  ],
  Documents: [
    { name: "audit_report_2026.pdf",      size: "2.1 MB", lines: null, indexed: true, risk: null, lastAnalyzed: "12:00 today" },
    { name: "protocol_spec.docx",         size: "840 KB", lines: null, indexed: true, risk: null, lastAnalyzed: "Yesterday" },
  ],
  CSV: [
    { name: "transaction_dataset.csv",   size: "1.4 MB", lines: 12400, indexed: true, risk: "MEDIUM", lastAnalyzed: "16:10 today" },
    { name: "anomaly_report.csv",        size: "210 KB", lines: 1800,  indexed: false, risk: null,    lastAnalyzed: "—" },
  ],
  JSON: [
    { name: "sample_trace.json",         size: "380 KB", lines: null, indexed: true,  risk: "HIGH",  lastAnalyzed: "17:00 today" },
    { name: "abi_vault.json",            size: "18 KB",  lines: null, indexed: true,  risk: null,    lastAnalyzed: "14:00 today" },
  ],
  Images: [
    { name: "alibaba_test.jpg",          size: "340 KB", lines: null, indexed: true, risk: "CRITICAL", lastAnalyzed: "16:55 today" },
    { name: "wallet_screenshot.png",     size: "210 KB", lines: null, indexed: false, risk: null,      lastAnalyzed: "—" },
  ],
  Other: [
    { name: "notes.txt",                 size: "2 KB",  lines: 44, indexed: true, risk: null, lastAnalyzed: "Yesterday" },
  ],
};

const riskColors: Record<string, { bg: string; text: string }> = {
  CRITICAL: { bg: "#93000a",              text: "#ffb4ab" },
  HIGH:     { bg: "rgba(223,116,18,0.2)", text: "#ffb786" },
  MEDIUM:   { bg: "rgba(76,215,246,0.1)", text: "#4cd7f6" },
  LOW:      { bg: "rgba(173,198,255,0.1)",text: "#adc6ff" },
};

const typeIcons: Record<string, string> = {
  Solidity: "description",
  Documents: "article",
  CSV: "table_rows",
  JSON: "data_object",
  Images: "image",
  Other: "folder",
};

export default function WorkspacePage() {
  const [dragging, setDragging] = useState(false);
  const [activeFile, setActiveFile] = useState("hybrid_vulnerable_test.sol");
  const [uploadProgress, setUploadProgress] = useState<number | null>(null);

  const simulateUpload = () => {
    setUploadProgress(0);
    const interval = setInterval(() => {
      setUploadProgress((p) => {
        if (p === null || p >= 100) { clearInterval(interval); setUploadProgress(null); return null; }
        return p + 10;
      });
    }, 200);
  };

  return (
    <div className="p-6 max-w-screen-xl mx-auto space-y-6">
      <div className="grid grid-cols-12 gap-4">
        {/* Upload Panel */}
        <div className="col-span-12 lg:col-span-4 space-y-4">
          <section
            className="p-4 rounded-lg"
            style={{ backgroundColor: "#141b2b", border: "1px solid #424754" }}
          >
            <h2 className="font-label-caps text-label-caps text-on-surface-variant mb-4 flex items-center gap-2">
              <span className="material-symbols-outlined text-sm">cloud_upload</span>
              UPLOAD FILES
            </h2>

            {/* Drop zone */}
            <div
              onDragOver={(e) => { e.preventDefault(); setDragging(true); }}
              onDragLeave={() => setDragging(false)}
              onDrop={(e) => { e.preventDefault(); setDragging(false); simulateUpload(); }}
              className="rounded-lg p-8 flex flex-col items-center justify-center text-on-surface-variant cursor-pointer transition-colors mb-4"
              style={{
                border: `2px dashed ${dragging ? "#adc6ff" : "#424754"}`,
                backgroundColor: dragging ? "rgba(173,198,255,0.05)" : "transparent",
              }}
            >
              <span className="material-symbols-outlined text-4xl mb-2" style={{ fontSize: "40px" }}>upload_file</span>
              <p className="font-body-sm text-body-sm text-center">Drop files here or</p>
              <button
                onClick={simulateUpload}
                className="mt-2 px-4 py-1.5 rounded font-label-caps text-label-caps transition-all active:scale-95"
                style={{ backgroundColor: "#191f2f", border: "1px solid #424754", color: "#adc6ff" }}
              >
                Browse Files
              </button>
              <p style={{ fontSize: "10px", color: "#8c909f", marginTop: "8px" }}>
                .sol .pdf .docx .csv .json .png .jpg
              </p>
            </div>

            {/* Upload progress */}
            {uploadProgress !== null && (
              <div className="mb-4 space-y-2">
                <div className="flex justify-between font-label-caps text-label-caps text-on-surface-variant">
                  <span>Uploading…</span>
                  <span>{uploadProgress}%</span>
                </div>
                <div className="h-1.5 rounded-full overflow-hidden" style={{ backgroundColor: "#2e3545" }}>
                  <div
                    className="h-full rounded-full transition-all duration-200"
                    style={{ width: `${uploadProgress}%`, backgroundColor: "#4cd7f6" }}
                  />
                </div>
              </div>
            )}

            {/* File type legend */}
            <div className="grid grid-cols-3 gap-2">
              {["Solidity", "CSV", "JSON", "Images", "Documents", "Other"].map((t) => (
                <div
                  key={t}
                  className="flex items-center gap-1 px-2 py-1 rounded"
                  style={{ backgroundColor: "#191f2f" }}
                >
                  <span className="material-symbols-outlined" style={{ fontSize: "12px", color: "#c2c6d6" }}>{typeIcons[t]}</span>
                  <span style={{ fontSize: "10px", color: "#c2c6d6", fontFamily: "Inter" }}>{t}</span>
                </div>
              ))}
            </div>
          </section>

          {/* Active file summary */}
          <div
            className="p-4 rounded-lg"
            style={{ backgroundColor: "#141b2b", border: "1px solid #424754" }}
          >
            <h3 className="font-label-caps text-label-caps text-on-surface-variant mb-3">ACTIVE FILE SUMMARY</h3>
            <div className="space-y-2">
              <div className="flex justify-between">
                <span className="font-label-caps text-label-caps text-on-surface-variant" style={{ fontSize: "10px" }}>FILE</span>
                <span className="font-code-sm text-code-sm" style={{ color: "#adc6ff" }}>{activeFile}</span>
              </div>
              <div className="flex justify-between">
                <span className="font-label-caps text-label-caps text-on-surface-variant" style={{ fontSize: "10px" }}>TYPE</span>
                <span className="font-code-sm text-code-sm text-on-surface">SOLIDITY</span>
              </div>
              <div className="flex justify-between">
                <span className="font-label-caps text-label-caps text-on-surface-variant" style={{ fontSize: "10px" }}>SIZE</span>
                <span className="font-code-sm text-code-sm text-on-surface">24 KB</span>
              </div>
              <div className="flex justify-between">
                <span className="font-label-caps text-label-caps text-on-surface-variant" style={{ fontSize: "10px" }}>LINES</span>
                <span className="font-code-sm text-code-sm text-on-surface">876</span>
              </div>
              <div className="flex justify-between">
                <span className="font-label-caps text-label-caps text-on-surface-variant" style={{ fontSize: "10px" }}>INDEXED</span>
                <span className="font-code-sm text-code-sm" style={{ color: "#4cd7f6" }}>YES</span>
              </div>
              <div className="flex justify-between">
                <span className="font-label-caps text-label-caps text-on-surface-variant" style={{ fontSize: "10px" }}>LAST SCAN</span>
                <span className="font-code-sm text-code-sm text-on-surface">17:45 today</span>
              </div>
              <div className="flex justify-between">
                <span className="font-label-caps text-label-caps text-on-surface-variant" style={{ fontSize: "10px" }}>RISK</span>
                <span
                  className="font-label-caps text-label-caps px-2 py-0.5 rounded"
                  style={{ backgroundColor: riskColors.HIGH.bg, color: riskColors.HIGH.text, fontSize: "9px" }}
                >
                  HIGH
                </span>
              </div>
            </div>
            <div className="mt-4 grid grid-cols-2 gap-2">
              <button
                className="py-1.5 rounded font-label-caps text-label-caps text-on-surface transition-colors hover:bg-surface-container-highest"
                style={{ border: "1px solid #424754" }}
              >
                View Audit
              </button>
              <button
                className="py-1.5 rounded font-label-caps text-label-caps transition-all active:scale-95"
                style={{ backgroundColor: "#adc6ff", color: "#002e6a" }}
              >
                Re-analyze
              </button>
            </div>
          </div>
        </div>

        {/* File Browser */}
        <div className="col-span-12 lg:col-span-8 space-y-3">
          <div className="flex items-center justify-between">
            <h2 className="font-headline-sm text-headline-sm text-on-surface">Workspace Files</h2>
            <div className="flex gap-2">
              <input
                className="px-3 py-1.5 rounded font-body-sm text-body-sm outline-none text-on-surface placeholder:text-on-surface-variant"
                style={{ backgroundColor: "#070e1d", border: "1px solid #424754", width: "200px" }}
                placeholder="Search files…"
              />
              <button
                className="px-3 py-1.5 rounded font-label-caps text-label-caps text-on-surface-variant transition-colors hover:bg-surface-container-highest"
                style={{ border: "1px solid #424754" }}
              >
                Sort
              </button>
            </div>
          </div>

          {Object.entries(workspaceFiles).map(([type, files]) => (
            <div
              key={type}
              className="rounded-lg overflow-hidden"
              style={{ border: "1px solid #424754" }}
            >
              {/* Section header */}
              <div
                className="flex items-center justify-between px-4 py-2"
                style={{ backgroundColor: "#191f2f" }}
              >
                <div className="flex items-center gap-2">
                  <span className="material-symbols-outlined" style={{ fontSize: "16px", color: "#8c909f" }}>{typeIcons[type]}</span>
                  <span className="font-label-caps text-label-caps text-on-surface">{type}</span>
                  <span
                    className="px-2 py-0.5 rounded-full font-label-caps"
                    style={{ fontSize: "10px", backgroundColor: "#2e3545", color: "#c2c6d6" }}
                  >
                    {files.length}
                  </span>
                </div>
              </div>

              {/* File rows */}
              {files.map((file) => (
                <div
                  key={file.name}
                  onClick={() => setActiveFile(file.name)}
                  className="flex items-center justify-between px-4 py-3 cursor-pointer transition-colors hover:bg-surface-container-high"
                  style={{
                    backgroundColor: file.name === activeFile ? "#232a3a" : "#141b2b",
                    borderTop: "1px solid #424754",
                    borderLeft: file.name === activeFile ? "3px solid #adc6ff" : "3px solid transparent",
                  }}
                >
                  <div className="flex items-center gap-3 min-w-0">
                    <span className="material-symbols-outlined" style={{ fontSize: "16px", color: "#adc6ff" }}>{typeIcons[type]}</span>
                    <span className="font-code-sm text-code-sm text-on-surface truncate">{file.name}</span>
                    {file.risk && (
                      <span
                        className="font-label-caps px-1.5 py-0.5 rounded shrink-0"
                        style={{
                          fontSize: "9px",
                          backgroundColor: riskColors[file.risk]?.bg,
                          color: riskColors[file.risk]?.text,
                        }}
                      >
                        {file.risk}
                      </span>
                    )}
                  </div>
                  <div className="flex items-center gap-4 shrink-0">
                    <span className="font-code-sm text-code-sm text-on-surface-variant hidden sm:block">{file.size}</span>
                    {file.lines && (
                      <span className="font-code-sm text-code-sm text-on-surface-variant hidden md:block">{file.lines} lines</span>
                    )}
                    <span
                      className="font-label-caps px-1.5 py-0.5 rounded"
                      style={{
                        fontSize: "9px",
                        backgroundColor: file.indexed ? "rgba(76,215,246,0.1)" : "#2e3545",
                        color: file.indexed ? "#4cd7f6" : "#8c909f",
                      }}
                    >
                      {file.indexed ? "INDEXED" : "PENDING"}
                    </span>
                    <span className="font-code-sm text-code-sm text-on-surface-variant hidden lg:block">{file.lastAnalyzed}</span>
                    <button
                      className="p-1 rounded text-on-surface-variant hover:text-on-surface transition-colors"
                      onClick={(e) => e.stopPropagation()}
                    >
                      <span className="material-symbols-outlined" style={{ fontSize: "16px" }}>more_vert</span>
                    </button>
                  </div>
                </div>
              ))}
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
