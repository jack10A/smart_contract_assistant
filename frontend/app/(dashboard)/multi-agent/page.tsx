"use client";
import { useState } from "react";
import type { ReactNode } from "react";
import { runInvestigation, listFiles, type AgentOut } from "../../lib/api";
import { useSession } from "../../context/SessionContext";

const AGENT_META: Record<string, { icon: string; color: string; role: string }> = {
  coordinator:          { icon: "manage_accounts", color: "#adc6ff", role: "Orchestrator" },
  document_indexer:     { icon: "folder_open",     color: "#4cd7f6", role: "Indexer" },
  solidity_auditor:     { icon: "bug_report",      color: "#ffb4ab", role: "Static + ML" },
  csv_anomaly_agent:    { icon: "table_chart",     color: "#4cd7f6", role: "Anomaly" },
  trace_analysis_agent: { icon: "route",           color: "#4cd7f6", role: "Trace" },
  image_security_agent: { icon: "image_search",    color: "#ffb4ab", role: "Phishing" },
  correlation_agent:    { icon: "hub",             color: "#ffb786", role: "Cross-modal" },
  attack_replay_agent:  { icon: "replay",          color: "#ffb786", role: "Exploit Sim" },
  remediation_agent:    { icon: "healing",         color: "#adc6ff", role: "LLM Fix" },
  report_writer:        { icon: "description",     color: "#4cd7f6", role: "PDF Export" },
};

const PIPELINE_STEPS = [
  { label: "File Ingestion",     icon: "upload_file" },
  { label: "Static Analysis",    icon: "code_blocks" },
  { label: "AI Classification",  icon: "psychology" },
  { label: "Cross-Modal Fusion", icon: "hub" },
  { label: "Report Generation",  icon: "description" },
];

const BASE = process.env.NEXT_PUBLIC_BACKEND_URL ?? "http://localhost:7860";

function reportDownloadUrl(reportPath: string) {
  const filename = reportPath.split(/[/\\]/).pop();
  return filename ? `${BASE}/api/download/report/${encodeURIComponent(filename)}` : "#";
}

const fileTypeLabel = (filename: string) => {
  const lower = filename.toLowerCase();
  if (lower.endsWith(".sol")) return "Solidity";
  if (lower.endsWith(".csv")) return "CSV";
  if (lower.endsWith(".json") && lower.includes("abi")) return "ABI";
  if (lower.endsWith(".json")) return "Trace / JSON";
  if (lower.endsWith(".png") || lower.endsWith(".jpg") || lower.endsWith(".jpeg") || lower.endsWith(".webp")) return "Images";
  if (lower.endsWith(".pdf") || lower.endsWith(".doc") || lower.endsWith(".docx") || lower.endsWith(".txt")) return "Documents";
  return "Other";
};

const isGeneratedArtifact = (filename: string) => {
  const lower = filename.toLowerCase();
  return lower === "audit_history.json" || lower.includes("_anomaly_report") || lower.includes("_fixed") || lower.endsWith(".sol.txt");
};

const groupOrder = ["Solidity", "CSV", "Trace / JSON", "ABI", "Images", "Documents", "Other"];

function statusColor(s: string) {
  const l = (s || "").toLowerCase();
  if (l.includes("done") || l.includes("success") || l.includes("complet")) return "#4cd7f6";
  if (l.includes("run") || l.includes("progress") || l.includes("active"))  return "#ffb786";
  if (l.includes("error") || l.includes("fail"))                            return "#ffb4ab";
  return "#8c909f";
}

function MarkdownText({ text, maxHeight }: { text: string; maxHeight?: string }) {
  const lines = text.split("\n");
  const blocks: ReactNode[] = [];
  const inline = (value: string) => value.split(/(`[^`]+`|\*\*[^*]+\*\*)/g).filter(Boolean).map((part, index) => {
    if (part.startsWith("`") && part.endsWith("`")) {
      return <code key={index} className="px-1 py-0.5 rounded" style={{ backgroundColor: "#070e1d", color: "#adc6ff" }}>{part.slice(1, -1)}</code>;
    }
    if (part.startsWith("**") && part.endsWith("**")) {
      return <strong key={index} style={{ color: "#f5f7ff" }}>{part.slice(2, -2)}</strong>;
    }
    return <span key={index}>{part}</span>;
  });

  for (let i = 0; i < lines.length; i += 1) {
    const line = lines[i].trim();
    if (!line || line === "---") continue;

    if (line.startsWith("```")) {
      const codeLines: string[] = [];
      i += 1;
      while (i < lines.length && !lines[i].trim().startsWith("```")) {
        codeLines.push(lines[i]);
        i += 1;
      }
      blocks.push(
        <pre key={`code-${i}`} className="overflow-auto rounded p-3" style={{ backgroundColor: "#03060b", border: "1px solid #2e3545", color: "#dce2f7", fontSize: "12px", lineHeight: 1.7 }}>
          {codeLines.join("\n")}
        </pre>
      );
      continue;
    }

    if (line.startsWith("|") && i + 1 < lines.length && lines[i + 1].includes("---")) {
      const tableLines = [line];
      i += 2;
      while (i < lines.length && lines[i].trim().startsWith("|")) {
        tableLines.push(lines[i].trim());
        i += 1;
      }
      i -= 1;
      const rows = tableLines.map((row) => row.split("|").slice(1, -1).map((cell) => cell.trim()));
      const [headers, ...bodyRows] = rows;
      blocks.push(
        <div key={`table-${i}`} className="overflow-x-auto rounded-lg my-4" style={{ border: "1px solid #2e3545" }}>
          <table className="w-full border-collapse" style={{ minWidth: "720px" }}>
            <thead style={{ backgroundColor: "#191f2f" }}>
              <tr>
                {headers.map((header, index) => (
                  <th key={index} className="text-left px-3 py-2 font-label-caps" style={{ color: "#adc6ff", fontSize: "10px", borderBottom: "1px solid #2e3545" }}>
                    {inline(header)}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {bodyRows.map((row, rowIndex) => (
                <tr key={rowIndex} style={{ borderTop: rowIndex ? "1px solid #20283a" : undefined }}>
                  {row.map((cell, cellIndex) => (
                    <td key={cellIndex} className="align-top px-3 py-2" style={{ color: "#dce2f7", fontSize: "12px", lineHeight: 1.6 }}>
                      {inline(cell)}
                    </td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      );
      continue;
    }

    if (/^\d+\.\s+/.test(line)) {
      const items = [line.replace(/^\d+\.\s+/, "")];
      while (i + 1 < lines.length && /^\d+\.\s+/.test(lines[i + 1].trim())) {
        i += 1;
        items.push(lines[i].trim().replace(/^\d+\.\s+/, ""));
      }
      blocks.push(
        <ol key={`ol-${i}`} className="space-y-1.5 my-3 pl-5 list-decimal">
          {items.map((item, index) => <li key={index} style={{ color: "#c2c6d6", fontSize: "13px", lineHeight: 1.65 }}>{inline(item)}</li>)}
        </ol>
      );
      continue;
    }

    if (line.startsWith("- ") || line.startsWith("*   ")) {
      const marker = line.startsWith("*   ") ? "*   " : "- ";
      const items = [line.slice(marker.length)];
      while (i + 1 < lines.length && (lines[i + 1].trim().startsWith("- ") || lines[i + 1].trim().startsWith("*   "))) {
        i += 1;
        const next = lines[i].trim();
        items.push(next.startsWith("*   ") ? next.slice(4) : next.slice(2));
      }
      blocks.push(
        <ul key={`list-${i}`} className="space-y-1.5 my-3">
          {items.map((item, index) => (
            <li key={index} className="flex gap-2" style={{ color: "#c2c6d6", fontSize: "13px", lineHeight: 1.65 }}>
              <span style={{ color: "#4cd7f6" }}>-</span>
              <span>{inline(item)}</span>
            </li>
          ))}
        </ul>
      );
      continue;
    }

    if (line.startsWith("> ")) {
      blocks.push(<blockquote key={`q-${i}`} className="my-3 rounded px-3 py-2" style={{ backgroundColor: "rgba(76,215,246,0.06)", borderLeft: "3px solid #4cd7f6", color: "#dce2f7", fontSize: "13px" }}>{inline(line.slice(2))}</blockquote>);
      continue;
    }

    if (line.startsWith("## ")) {
      blocks.push(<h3 key={`h2-${i}`} className="font-headline-sm mt-6 mb-3" style={{ color: "#f5f7ff", fontSize: "18px" }}>{inline(line.slice(3))}</h3>);
      continue;
    }
    if (line.startsWith("### ")) {
      blocks.push(<h4 key={`h3-${i}`} className="font-headline-sm mt-5 mb-3" style={{ color: "#adc6ff", fontSize: "16px" }}>{inline(line.slice(4))}</h4>);
      continue;
    }
    if (line.startsWith("#### ")) {
      blocks.push(<h5 key={`h4-${i}`} className="font-label-caps mt-4 mb-2" style={{ color: "#8fb3ff", fontSize: "11px" }}>{inline(line.slice(5))}</h5>);
      continue;
    }

    blocks.push(<p key={`p-${i}`} className="my-2" style={{ color: "#dce2f7", fontSize: "13px", lineHeight: 1.7 }}>{inline(line)}</p>);
  }

  return <div className="overflow-auto pr-1" style={{ maxHeight }}>{blocks}</div>;
}

export default function MultiAgentPage() {
  const session = useSession();
  const [files, setFiles]               = useState<string[]>([]);
  const [selectedFiles, setSelectedFiles] = useState<string[]>([]);
  const [filesLoaded, setFilesLoaded]   = useState(false);
  const [running, setRunning]           = useState(false);
  const [error, setError]               = useState<string | null>(null);
  const [selectedAgent, setSelectedAgent] = useState<string | null>(null);
  const [step, setStep]                 = useState(0);
  const [fileQuery, setFileQuery]       = useState("");
  const [showGenerated, setShowGenerated] = useState(false);

  const result = session.investigateResult;

  const loadFiles = async () => {
    if (filesLoaded) return;
    try { const { files: f } = await listFiles(); setFiles(f); setFilesLoaded(true); }
    catch { setFiles([]); }
  };

  const toggleFile = (f: string) =>
    setSelectedFiles(prev => prev.includes(f) ? prev.filter(x => x !== f) : [...prev, f]);

  const visibleFiles = files.filter((file) => {
    if (!showGenerated && isGeneratedArtifact(file)) return false;
    return file.toLowerCase().includes(fileQuery.trim().toLowerCase());
  });
  const groupedFiles = groupOrder
    .map((group) => ({ group, files: visibleFiles.filter((file) => fileTypeLabel(file) === group) }))
    .filter((item) => item.files.length > 0);

  const handleRun = async () => {
    setRunning(true); setError(null); session.setInvestigateResult(null); setStep(0);
    const stepTimer = setInterval(() => setStep(s => s < 4 ? s + 1 : s), 4000);
    try {
      const filesToRun = selectedFiles.length > 0 ? selectedFiles : visibleFiles;
      const res = await runInvestigation(filesToRun.length > 0 ? filesToRun : undefined);
      session.setInvestigateResult(res); setStep(4);
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : "Investigation failed");
    } finally {
      clearInterval(stepTimer); setRunning(false);
    }
  };

  const agents    = result?.agents ?? {};
  const agentKeys = Object.keys(agents);
  const detail: AgentOut | undefined = selectedAgent ? agents[selectedAgent] : undefined;

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-start justify-between gap-4 flex-wrap">
        <div>
          <h1 className="font-headline-md text-headline-md text-on-surface">Multi-Agent Investigation</h1>
          <p className="font-body-sm text-body-sm text-on-surface-variant mt-1">10 specialist agents orchestrated across Solidity, CSV, JSON trace, and image files</p>
        </div>
        <button onClick={handleRun} disabled={running}
          className="px-6 py-2 rounded font-label-caps font-bold transition-all active:scale-95"
          style={{ backgroundColor: running ? "#2e3545" : "#adc6ff", color: running ? "#424754" : "#002e6a" }}>
          {running ? "INVESTIGATING..." : "START INVESTIGATION"}
        </button>
      </div>

      {/* File selector */}
      <div className="p-4 rounded-lg" style={{ backgroundColor: "#141b2b", border: "1px solid #424754" }}>
        <div className="flex items-start justify-between gap-3 mb-4 flex-wrap">
          <div>
            <h3 className="font-label-caps text-label-caps text-on-surface-variant">FILES TO INCLUDE {selectedFiles.length > 0 && `(${selectedFiles.length} selected)`}</h3>
            <p className="font-label-caps text-on-surface-variant mt-1" style={{ fontSize: "9px" }}>Leave unselected to investigate all visible workspace files.</p>
          </div>
          <div className="flex items-center gap-2 flex-wrap">
            <input
              value={fileQuery}
              onChange={(e) => setFileQuery(e.target.value)}
              placeholder="Search files"
              className="rounded px-3 py-2 font-code-sm text-on-surface outline-none"
              style={{ backgroundColor: "#191f2f", border: "1px solid #424754", minWidth: "180px", fontSize: "12px" }}
            />
            <button
              onClick={() => setShowGenerated((value) => !value)}
              className="font-label-caps px-3 py-2 rounded transition-colors"
              style={{ fontSize: "10px", border: "1px solid #424754", color: showGenerated ? "#adc6ff" : "#8c909f", backgroundColor: showGenerated ? "rgba(173,198,255,0.12)" : "#191f2f" }}
            >
              {showGenerated ? "HIDE GENERATED" : "SHOW GENERATED"}
            </button>
            <button onClick={loadFiles} className="font-label-caps px-3 py-2 rounded transition-colors" style={{ fontSize: "10px", color: "#4cd7f6", border: "1px solid #424754" }}>REFRESH</button>
          </div>
        </div>
        {!filesLoaded ? (
          <button onClick={loadFiles} className="font-body-sm text-body-sm text-on-surface-variant hover:underline">Click to load workspace files...</button>
        ) : files.length === 0 ? (
          <p className="font-body-sm text-body-sm text-on-surface-variant">No files in workspace. Upload files first.</p>
        ) : groupedFiles.length === 0 ? (
          <p className="font-body-sm text-body-sm text-on-surface-variant">No files match the current search and filter.</p>
        ) : (
          <div className="space-y-4">
            {groupedFiles.map(({ group, files: groupFiles }) => (
              <div key={group}>
                <div className="flex items-center gap-2 mb-2">
                  <span className="font-label-caps" style={{ fontSize: "10px", color: "#adc6ff" }}>{group}</span>
                  <span className="font-label-caps text-on-surface-variant" style={{ fontSize: "9px" }}>{groupFiles.length}</span>
                </div>
                <div className="flex flex-wrap gap-2">
                  {groupFiles.map(f => {
                    const sel = selectedFiles.includes(f);
                    const generated = isGeneratedArtifact(f);
                    return (
                      <button key={f} onClick={() => toggleFile(f)} className="font-code-sm px-3 py-1 rounded transition-colors"
                        style={{ backgroundColor: sel ? "rgba(173,198,255,0.15)" : "#191f2f", border: sel ? "1px solid rgba(173,198,255,0.4)" : "1px solid #424754", color: sel ? "#adc6ff" : generated ? "#6f7482" : "#c2c6d6", fontSize: "11px" }}>
                        {f}
                      </button>
                    );
                  })}
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Pipeline */}
      <div className="p-5 rounded-lg" style={{ backgroundColor: "#141b2b", border: "1px solid #424754" }}>
        <h3 className="font-headline-sm text-headline-sm text-on-surface mb-5">Investigation Pipeline</h3>
        <div className="flex items-center">
          {PIPELINE_STEPS.map((s, i) => {
            const done   = result ? true : i < step;
            const active = running && i === step;
            const color  = done ? "#4cd7f6" : active ? "#ffb786" : "#424754";
            return (
              <div key={s.label} className="flex items-center flex-1">
                <div className="flex flex-col items-center flex-1">
                  <div className="w-10 h-10 rounded-full flex items-center justify-center mb-2 relative"
                    style={{ backgroundColor: done ? "rgba(76,215,246,0.15)" : active ? "rgba(255,183,134,0.15)" : "#2e3545", border: `2px solid ${color}` }}>
                    <span className="material-symbols-outlined" style={{ fontSize: "18px", color }}>{s.icon}</span>
                    {active && <div className="absolute inset-0 rounded-full animate-ping" style={{ backgroundColor: "rgba(255,183,134,0.2)" }} />}
                  </div>
                  <span className="font-label-caps text-center" style={{ fontSize: "9px", color }}>{s.label}</span>
                </div>
                {i < PIPELINE_STEPS.length - 1 && <div className="h-px" style={{ width: "32px", backgroundColor: done ? "#4cd7f6" : "#2e3545", marginBottom: "24px", flexShrink: 0 }} />}
              </div>
            );
          })}
        </div>
      </div>

      {error && <div className="p-4 rounded-lg" style={{ backgroundColor: "rgba(255,180,171,0.08)", border: "1px solid rgba(255,180,171,0.3)", color: "#ffb4ab" }}><p className="font-body-sm">{error}</p></div>}

      {running && (
        <div className="p-6 rounded-lg text-center space-y-3" style={{ backgroundColor: "#141b2b", border: "1px solid #424754" }}>
          <div className="flex justify-center gap-2">{[0,1,2].map(i => <div key={i} className="w-2 h-2 rounded-full animate-bounce" style={{ backgroundColor: "#4cd7f6", animationDelay: `${i*150}ms` }} />)}</div>
          <p className="font-body-sm text-body-sm text-on-surface-variant">{PIPELINE_STEPS[Math.min(step, 4)]?.label} in progress... This may take a few minutes.</p>
        </div>
      )}

      {result && (
        <div className="grid grid-cols-12 gap-4">
          <div className="col-span-12 lg:col-span-8 space-y-4">
            <div className="grid grid-cols-2 md:grid-cols-3 xl:grid-cols-5 gap-3">
              {(agentKeys.length > 0 ? agentKeys : Object.keys(AGENT_META)).map(key => {
                const meta  = AGENT_META[key] ?? { icon: "smart_toy", color: "#8c909f", role: "" };
                const agent = agents[key];
                const sc    = statusColor(agent?.status ?? "done");
                return (
                  <button key={key} onClick={() => setSelectedAgent(selectedAgent === key ? null : key)}
                    className="p-3 rounded-lg text-left transition-all"
                    style={{ backgroundColor: selectedAgent === key ? "#232a3a" : "#141b2b", border: `1px solid ${selectedAgent === key ? meta.color + "60" : "#424754"}` }}>
                    <div className="flex items-center justify-between mb-2">
                      <span className="material-symbols-outlined" style={{ fontSize: "18px", color: meta.color }}>{meta.icon}</span>
                      <div className="w-2 h-2 rounded-full" style={{ backgroundColor: sc, boxShadow: `0 0 4px ${sc}` }} />
                    </div>
                    <p className="font-label-caps text-on-surface" style={{ fontSize: "10px" }}>{key.replace(/_/g, " ").toUpperCase().slice(0, 16)}</p>
                    <p className="font-body-sm text-on-surface-variant mt-0.5" style={{ fontSize: "10px" }}>{meta.role}</p>
                    {agent?.status && <p className="font-label-caps mt-1" style={{ fontSize: "9px", color: sc }}>{agent.status.toUpperCase().slice(0, 20)}</p>}
                  </button>
                );
              })}
            </div>

            {result.summary && (
              <div className="p-5 rounded-lg" style={{ backgroundColor: "#141b2b", border: "1px solid #424754" }}>
                <h3 className="font-headline-sm text-on-surface mb-4">Investigation Summary</h3>
                <MarkdownText text={result.summary} />
              </div>
            )}

            {result.findings && result.findings.length > 0 && (
              <div className="p-5 rounded-lg" style={{ backgroundColor: "#141b2b", border: "1px solid #424754" }}>
                <h3 className="font-headline-sm text-on-surface mb-4">Findings ({result.findings.length})</h3>
                <div className="space-y-2">
                  {result.findings.map((f: unknown, i) => {
                    const finding = f as Record<string, unknown>;
                    const sev = (finding.severity as string) ?? "";
                    const fc  = sev.toLowerCase().includes("critical") ? "#ffb4ab" : sev.toLowerCase().includes("high") ? "#ffb786" : "#4cd7f6";
                    return (
                      <div key={i} className="p-3 rounded" style={{ backgroundColor: "#191f2f", border: "1px solid #2e3545" }}>
                        <div className="flex items-center gap-2 mb-1">
                          <span className="font-label-caps px-1.5 py-0.5 rounded" style={{ fontSize: "9px", color: fc, backgroundColor: fc + "15" }}>{sev}</span>
                          <span className="font-label-caps text-on-surface" style={{ fontSize: "10px" }}>{finding.title as string ?? finding.id as string ?? `Finding ${i + 1}`}</span>
                        </div>
                        {finding.recommendation != null && <p className="font-body-sm text-body-sm text-on-surface-variant">{String(finding.recommendation)}</p>}
                      </div>
                    );
                  })}
                </div>
              </div>
            )}
          </div>

          <div className="col-span-12 lg:col-span-4 space-y-4">
            {detail && (
              <div className="p-5 rounded-lg" style={{ backgroundColor: "#141b2b", border: "1px solid #424754" }}>
                <div className="flex items-center gap-3 mb-4">
                  <div className="w-10 h-10 rounded-full flex items-center justify-center" style={{ backgroundColor: `${(AGENT_META[selectedAgent!]?.color ?? "#8c909f")}20` }}>
                    <span className="material-symbols-outlined" style={{ fontSize: "20px", color: AGENT_META[selectedAgent!]?.color ?? "#8c909f" }}>{AGENT_META[selectedAgent!]?.icon ?? "smart_toy"}</span>
                  </div>
                  <div>
                    <p className="font-headline-sm text-on-surface">{detail.name}</p>
                    <p className="font-label-caps" style={{ fontSize: "10px", color: statusColor(detail.status) }}>{detail.status}</p>
                  </div>
                </div>
                {detail.output && (
                  <MarkdownText text={`${detail.output.slice(0, 2000)}${detail.output.length > 2000 ? "..." : ""}`} maxHeight="360px" />
                )}
              </div>
            )}

            <div className="p-5 rounded-lg" style={{ backgroundColor: "#141b2b", border: "1px solid #424754" }}>
              <h3 className="font-headline-sm text-on-surface mb-4">Generated Report</h3>
              {result.report_path ? (
                <div className="flex flex-col gap-2">
                  <p className="font-code-sm text-on-surface-variant" style={{ fontSize: "11px" }}>{result.report_path.split(/[/\\]/).pop()}</p>
                  <a href={reportDownloadUrl(result.report_path)} download
                    className="flex items-center justify-center gap-2 py-2 rounded font-label-caps"
                    style={{ backgroundColor: "#adc6ff", color: "#002e6a", fontSize: "10px" }}>
                    <span className="material-symbols-outlined" style={{ fontSize: "14px" }}>download</span>
                    DOWNLOAD PDF REPORT
                  </a>
                </div>
              ) : (
                <p className="font-body-sm text-body-sm text-on-surface-variant">Report will appear here after investigation completes.</p>
              )}
            </div>
          </div>
        </div>
      )}

      {!result && !running && !error && (
        <div className="flex flex-col items-center gap-4 py-16">
          <span className="material-symbols-outlined" style={{ fontSize: "56px", color: "#2e3545" }}>hub</span>
          <p className="font-body-sm text-body-sm text-on-surface-variant text-center max-w-md">
            Click <strong className="text-on-surface">START INVESTIGATION</strong> to launch all 10 specialist agents across your workspace files.
          </p>
        </div>
      )}
    </div>
  );
}
