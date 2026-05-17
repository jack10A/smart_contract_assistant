"use client";
import { useRef, useState } from "react";
import { uploadFile, runAudit, exportReport } from "../lib/api";
import { useSession } from "../context/SessionContext";

const BASE = process.env.NEXT_PUBLIC_BACKEND_URL ?? "http://localhost:7860";

function buildAuditReplayText(session: ReturnType<typeof useSession>) {
  const audit = session.auditResult;
  if (!audit) return "";
  const label = audit.prediction?.label ?? "Security Finding";
  const lower = `${label} ${audit.audit_text} ${audit.line_map}`.toLowerCase();
  const title = lower.includes("reentrancy")
    ? "Reentrancy Drain Path"
    : lower.includes("delegatecall")
      ? "Delegatecall Takeover Path"
      : lower.includes("overflow") || lower.includes("underflow")
        ? "Arithmetic Corruption Path"
        : lower.includes("timestamp")
          ? "Timestamp Manipulation Path"
          : "Manual Review Path";
  const evidence = [...audit.line_map.matchAll(/\*\*Line\s+(\d+):\s+([^*]+)\*\*/g)]
    .slice(0, 8)
    .map((match) => `- ${audit.filename}:${match[1]} ${match[2].trim()}`)
    .join("\n");

  return [
    `### ${title}`,
    "",
    `- File: \`${audit.filename}\``,
    `- Prediction: **${label}**`,
    `- Confidence: **${Math.round((audit.prediction?.confidence ?? 0) * 100)}%**`,
    "",
    "#### Evidence",
    evidence || "- No line evidence was parsed.",
  ].join("\n");
}

interface TopHeaderProps {
  activeFile?: string;
  scanStatus?: "idle" | "scanning" | "complete" | "error";
  lastScan?: string;
}

export default function TopHeader({
  activeFile = "hybrid_vulnerable_test.sol",
  scanStatus: initialStatus = "complete",
  lastScan = "May 16, 2026 17:45",
}: TopHeaderProps) {
  const session = useSession();
  const [scanStatus, setScanStatus] = useState(initialStatus);
  const [uploadStatus, setUploadStatus] = useState<string | null>(null);
  const [exporting, setExporting] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);
  const displayedFile = session.selectedFile || activeFile;

  const statusColors: Record<string, string> = {
    idle:     "#c2c6d6",
    scanning: "#4cd7f6",
    complete: "#4cd7f6",
    error:    "#ffb4ab",
  };
  const statusLabels: Record<string, string> = {
    idle:     "IDLE",
    scanning: "SCANNING…",
    complete: "COMPLETE",
    error:    "ERROR",
  };

  return (
    <header
      className="flex justify-between items-center w-full px-6 h-16 shrink-0"
      style={{ backgroundColor: "#191f2f", borderBottom: "1px solid #424754" }}
    >
      {/* Left */}
      <div className="flex items-center gap-6">
        <span className="font-headline-sm text-headline-sm font-bold tracking-tight" style={{ color: "#adc6ff" }}>
          ChainSentinel AI
        </span>

        {/* Active file pill */}
        <div
          className="hidden lg:flex items-center gap-2 px-3 py-1.5 rounded"
          style={{ backgroundColor: "#070e1d", border: "1px solid #424754" }}
        >
          <span className="material-symbols-outlined" style={{ fontSize: "14px", color: "#c2c6d6" }}>description</span>
          <span className="font-code-sm text-code-sm" style={{ color: "#adc6ff" }}>{displayedFile}</span>
        </div>

        {/* Scan status */}
        <div className="hidden xl:flex items-center gap-2">
          <span
            className="inline-block w-2 h-2 rounded-full"
            style={{
              backgroundColor: statusColors[scanStatus],
              boxShadow: scanStatus === "scanning" ? `0 0 6px ${statusColors[scanStatus]}` : undefined,
            }}
          />
          <span className="font-label-caps text-label-caps" style={{ color: statusColors[scanStatus] }}>
            {statusLabels[scanStatus]}
          </span>
          <span style={{ fontSize: "10px", color: "#8c909f" }}>{uploadStatus ?? lastScan}</span>
        </div>
      </div>

      {/* Right */}
      <div className="flex items-center gap-3">
        {/* Upload */}
        <input
          ref={fileInputRef}
          type="file"
          className="hidden"
          accept=".sol,.json,.csv,.png,.jpg,.jpeg"
          onChange={async (e) => {
            const file = e.target.files?.[0];
            if (!file) return;
            setScanStatus("scanning");
            setUploadStatus(`Uploading ${file.name}...`);
            try {
              const uploaded = await uploadFile(file);
              session.setSelectedFile(uploaded.filename);
              session.setAuditResult(null);
              session.setFixResult(null);
              setUploadStatus(`Uploaded ${uploaded.filename}`);
              setScanStatus("idle");
            } catch (error) {
              setUploadStatus(error instanceof Error ? error.message : "Upload failed");
              setScanStatus("error");
            }
            e.target.value = "";
          }}
        />
        <button
          onClick={() => fileInputRef.current?.click()}
          className="flex items-center gap-2 px-3 py-1.5 rounded transition-colors hover:bg-surface-container-highest text-on-surface-variant"
          style={{ border: "1px solid #424754" }}
        >
          <span className="material-symbols-outlined" style={{ fontSize: "16px" }}>upload_file</span>
          <span className="font-label-caps text-label-caps">Upload</span>
        </button>

        {/* Notifications */}
        <button
          className="relative p-2 rounded transition-colors text-on-surface-variant hover:bg-surface-container-highest"
        >
          <span className="material-symbols-outlined" style={{ fontSize: "20px" }}>notifications</span>
          <span
            className="absolute top-1.5 right-1.5 w-2 h-2 rounded-full"
            style={{ backgroundColor: "#ffb4ab" }}
          />
        </button>

        {/* Divider */}
        <div className="h-6 w-px" style={{ backgroundColor: "#424754" }} />

        {/* Export */}
        <button
          onClick={async () => {
            setExporting(true);
            setUploadStatus("Generating report...");
            try {
              const existingReplay = session.investigateResult?.agents?.attack_replay_agent?.output ?? "";
              const result = await exportReport({
                selected_file: session.auditResult?.filename ?? session.selectedFile ?? displayedFile,
                risk_text: session.auditResult?.risk_text ?? "",
                audit_text: session.auditResult?.audit_text ?? "",
                fix_text: [session.fixResult?.fix_explanation, session.fixResult?.reaudit].filter(Boolean).join("\n\n---\n\n"),
                line_map_text: session.auditResult?.line_map ?? "",
                patch_diff_text: session.fixResult?.diff_markdown ?? "",
                csv_text: session.csvResult?.analysis_text ?? "",
                csv_explanation: session.csvResult?.explanation ?? "",
                trace_text: session.traceResult?.trace_text ?? "",
                image_text: session.imageResult?.image_text ?? "",
                investigation_summary: session.investigateResult?.summary ?? "",
                attack_replay_text: existingReplay || buildAuditReplayText(session),
              });
              window.location.href = `${BASE}${result.download_url}`;
              setUploadStatus(`Exported ${result.filename}`);
            } catch (error) {
              setUploadStatus(error instanceof Error ? error.message : "Report export failed");
            } finally {
              setExporting(false);
            }
          }}
          disabled={exporting}
          className="px-4 py-1.5 rounded font-label-caps text-label-caps transition-colors text-on-surface hover:bg-surface-container-highest"
          style={{ border: "1px solid #424754" }}
        >
          {exporting ? "Exporting..." : "Export Report"}
        </button>

        {/* Run Analysis */}
        <button
          onClick={async () => {
            setScanStatus("scanning");
            try {
              const result = await runAudit(displayedFile);
              session.setSelectedFile(result.filename);
              session.setAuditResult(result);
              setScanStatus("complete");
              setUploadStatus(`Audited ${result.filename}`);
            } catch (error) {
              setUploadStatus(error instanceof Error ? error.message : "Audit failed");
              setScanStatus("error");
            }
          }}
          disabled={scanStatus === "scanning"}
          className="px-4 py-1.5 rounded font-label-caps text-label-caps font-bold transition-all active:scale-95 duration-100"
          style={{ backgroundColor: scanStatus === "scanning" ? "#2e3545" : "#adc6ff", color: scanStatus === "scanning" ? "#8c909f" : "#002e6a" }}
        >
          {scanStatus === "scanning" ? "Scanning…" : "Run Analysis"}
        </button>

        {/* User avatar */}
        <div
          className="w-8 h-8 rounded-full flex items-center justify-center ml-1 cursor-pointer"
          style={{ backgroundColor: "#2e3545", border: "1px solid #424754" }}
        >
          <span className="material-symbols-outlined" style={{ fontSize: "16px", color: "#c2c6d6" }}>person</span>
        </div>
      </div>
    </header>
  );
}
