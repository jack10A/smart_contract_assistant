"use client";
import { useState } from "react";
import type { ReactNode } from "react";
import { correlateCSVWithContract, runCSVAnomaly, listFiles } from "../../lib/api";
import { useSession } from "../../context/SessionContext";

const BASE = process.env.NEXT_PUBLIC_BACKEND_URL ?? "http://localhost:7860";

function workspaceAssetUrl(path: string) {
  const normalized = path.replaceAll("\\", "/");
  if (/^https?:\/\//i.test(normalized)) return normalized;
  const workspaceRelative = normalized.includes("workspace_uploads/")
    ? normalized.split("workspace_uploads/", 2)[1]
    : normalized.replace(/^\/?uploads\//, "");
  return `${BASE}/uploads/${workspaceRelative.replace(/^\/+/, "").split("/").map(encodeURIComponent).join("/")}`;
}

function MarkdownText({ text }: { text: string }) {
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
          <table className="w-full border-collapse" style={{ minWidth: "760px" }}>
            <thead style={{ backgroundColor: "#191f2f" }}>
              <tr>{headers.map((header, index) => <th key={index} className="text-left px-3 py-2 font-label-caps" style={{ color: "#adc6ff", fontSize: "10px", borderBottom: "1px solid #2e3545" }}>{inline(header)}</th>)}</tr>
            </thead>
            <tbody>
              {bodyRows.map((row, rowIndex) => (
                <tr key={rowIndex} style={{ borderTop: rowIndex ? "1px solid #20283a" : undefined }}>
                  {row.map((cell, cellIndex) => <td key={cellIndex} className="align-top px-3 py-2" style={{ color: "#dce2f7", fontSize: "12px", lineHeight: 1.6 }}>{inline(cell)}</td>)}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      );
      continue;
    }

    if (line.startsWith("### ")) {
      blocks.push(<h4 key={`h-${i}`} className="font-headline-sm mt-5 mb-3" style={{ color: "#adc6ff", fontSize: "16px" }}>{inline(line.slice(4))}</h4>);
      continue;
    }

    if (line.startsWith("- ")) {
      const items = [line.slice(2)];
      while (i + 1 < lines.length && lines[i + 1].trim().startsWith("- ")) {
        i += 1;
        items.push(lines[i].trim().slice(2));
      }
      blocks.push(
        <ul key={`list-${i}`} className="space-y-1.5 my-3">
          {items.map((item, index) => (
            <li key={index} style={{ color: "#c2c6d6", fontSize: "13px", lineHeight: 1.65, paddingLeft: "14px", position: "relative" }}>
              <span style={{ color: "#4cd7f6", position: "absolute", left: 0 }}>-</span>
              <span style={{ display: "inline" }}>{inline(item)}</span>
            </li>
          ))}
        </ul>
      );
      continue;
    }

    blocks.push(<p key={`p-${i}`} className="my-2" style={{ color: "#dce2f7", fontSize: "13px", lineHeight: 1.7 }}>{inline(line)}</p>);
  }

  return <div>{blocks}</div>;
}

export default function CSVAnomalyPage() {
  const session = useSession();
  const [fileList, setFileList]       = useState<string[]>([]);
  const [filesLoaded, setFilesLoaded] = useState(false);
  const [selected, setSelected]       = useState(session.csvFile || "");
  const [running, setRunning]         = useState(false);
  const [error, setError]             = useState<string | null>(null);
  const [tab, setTab]                 = useState<"analysis" | "explanation">("analysis");
  const [rowNumber, setRowNumber]     = useState("");
  const [correlating, setCorrelating] = useState(false);
  const [correlationError, setCorrelationError] = useState<string | null>(null);
  const [correlationText, setCorrelationText] = useState("");

  const result = session.csvResult;

  const loadFiles = async () => {
    if (filesLoaded) return;
    try { const { files } = await listFiles(); setFileList(files.filter(f => f.toLowerCase().endsWith(".csv"))); setFilesLoaded(true); }
    catch { setFileList([]); }
  };

  const handleRun = async () => {
    if (!selected) return;
    setRunning(true); setError(null); session.setCSVResult(selected, null);
    try { const r = await runCSVAnomaly(selected); session.setCSVResult(selected, r); }
    catch (e: unknown) { setError(e instanceof Error ? e.message : "Analysis failed"); }
    finally { setRunning(false); }
  };

  const handleCorrelate = async () => {
    if (!result || !session.auditResult) return;
    setCorrelating(true);
    setCorrelationError(null);
    setCorrelationText("");
    try {
      const response = await correlateCSVWithContract(
        session.auditResult.filename,
        session.auditResult.audit_text,
        session.auditResult.line_map,
        result.analysis_text,
        rowNumber
      );
      setCorrelationText(response.correlation_text);
    } catch (e: unknown) {
      setCorrelationError(e instanceof Error ? e.message : "Correlation failed");
    } finally {
      setCorrelating(false);
    }
  };

  const riskColor = result
    ? result.risk_level.toLowerCase().includes("high") || result.risk_level.toLowerCase().includes("critical") ? "#ffb4ab"
    : result.risk_level.toLowerCase().includes("medium") ? "#ffb786" : "#4cd7f6"
    : "#8c909f";

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-start justify-between gap-4 flex-wrap">
        <div>
          <h1 className="font-headline-md text-headline-md text-on-surface">CSV Anomaly Detection</h1>
          <p className="font-body-sm text-body-sm text-on-surface-variant mt-1">Autoencoder (PyTorch) + Isolation Forest consensus · LLM explanation</p>
        </div>
        <div className="flex items-center gap-3">
          <select value={selected} onFocus={loadFiles} onChange={e => setSelected(e.target.value)}
            className="rounded px-3 py-2 font-code-sm text-on-surface outline-none"
            style={{ backgroundColor: "#191f2f", border: "1px solid #424754", minWidth: "220px", fontSize: "12px" }}>
            <option value="">Select a .csv file…</option>
            {fileList.map(f => <option key={f} value={f}>{f}</option>)}
          </select>
          <button onClick={handleRun} disabled={!selected || running}
            className="px-6 py-2 rounded font-label-caps font-bold transition-all active:scale-95"
            style={{ backgroundColor: !selected || running ? "#2e3545" : "#adc6ff", color: !selected || running ? "#424754" : "#002e6a" }}>
            {running ? "ANALYSING…" : "RUN ANALYSIS"}
          </button>
        </div>
      </div>

      {error && <div className="p-4 rounded-lg font-body-sm" style={{ backgroundColor: "rgba(255,180,171,0.08)", border: "1px solid rgba(255,180,171,0.3)", color: "#ffb4ab" }}>{error}</div>}

      {running && (
        <div className="p-8 rounded-lg flex flex-col items-center gap-3" style={{ backgroundColor: "#141b2b", border: "1px solid #424754" }}>
          <div className="flex gap-2">{[0,1,2].map(i => <div key={i} className="w-2 h-2 rounded-full animate-bounce" style={{ backgroundColor: "#4cd7f6", animationDelay: `${i*150}ms` }} />)}</div>
          <p className="font-body-sm text-on-surface-variant">Training autoencoder + running Isolation Forest on {selected}…</p>
        </div>
      )}

      {result && (
        <div className="space-y-4">
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            {[
              { label: "Risk Score",      value: `${result.risk_score}/100`,   color: riskColor },
              { label: "Risk Level",      value: result.risk_level,            color: riskColor },
              { label: "Anomalies Found", value: String(result.anomaly_count), color: result.anomaly_count > 0 ? "#ffb4ab" : "#4cd7f6" },
              { label: "File",            value: session.csvFile,              color: "#c2c6d6" },
            ].map(({ label, value, color }) => (
              <div key={label} className="p-4 rounded-lg" style={{ backgroundColor: "#191f2f", border: "1px solid #424754" }}>
                <p className="font-label-caps text-on-surface-variant" style={{ fontSize: "10px" }}>{label}</p>
                <p className="font-headline-sm mt-1 truncate" style={{ color, fontSize: "16px" }}>{value}</p>
              </div>
            ))}
          </div>

          {Object.values(result.plots).some(Boolean) && (
            <div className="p-5 rounded-lg" style={{ backgroundColor: "#141b2b", border: "1px solid #424754" }}>
              <h3 className="font-headline-sm text-on-surface mb-4">Analysis Plots</h3>
              <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
                {Object.entries(result.plots).map(([key, url]) => url ? (
                  <div key={key} className="rounded-lg overflow-hidden" style={{ backgroundColor: "#0c1322", border: "1px solid #2e3545" }}>
                    <p className="font-label-caps text-on-surface-variant mb-1" style={{ fontSize: "10px" }}>{key.replace(/_/g, " ").toUpperCase()}</p>
                    <a href={workspaceAssetUrl(url)} target="_blank" rel="noreferrer">
                      <img src={workspaceAssetUrl(url)} alt={key.replace(/_/g, " ")} className="w-full" style={{ display: "block", backgroundColor: "#ffffff", aspectRatio: "16 / 10", objectFit: "contain" }} />
                    </a>
                  </div>
                ) : null)}
              </div>
            </div>
          )}

          <div className="p-5 rounded-lg" style={{ backgroundColor: "#141b2b", border: "1px solid #424754" }}>
            <div className="flex items-end justify-between gap-3 flex-wrap">
              <div>
                <h3 className="font-headline-sm text-on-surface">CSV to Contract Correlation</h3>
                <p className="font-body-sm text-body-sm text-on-surface-variant mt-1">
                  Compare a CSV anomaly row with the last Solidity audit result.
                </p>
              </div>
              <div className="flex items-center gap-2">
                <input
                  value={rowNumber}
                  onChange={(e) => setRowNumber(e.target.value)}
                  placeholder="Row number"
                  className="rounded px-3 py-2 font-code-sm text-on-surface outline-none"
                  style={{ backgroundColor: "#191f2f", border: "1px solid #424754", width: "130px", fontSize: "12px" }}
                />
                <button
                  onClick={handleCorrelate}
                  disabled={correlating || !session.auditResult}
                  className="px-4 py-2 rounded font-label-caps font-bold transition-all active:scale-95"
                  style={{ backgroundColor: correlating || !session.auditResult ? "#2e3545" : "#adc6ff", color: correlating || !session.auditResult ? "#424754" : "#002e6a", fontSize: "10px" }}
                >
                  {correlating ? "CORRELATING..." : "CORRELATE WITH CONTRACT"}
                </button>
              </div>
            </div>
            {!session.auditResult && (
              <p className="font-body-sm text-body-sm text-on-surface-variant mt-3">Run a Solidity audit first, then return here to correlate CSV rows.</p>
            )}
            {correlationError && <p className="font-body-sm mt-3" style={{ color: "#ffb4ab" }}>{correlationError}</p>}
            {correlationText && (
              <div className="mt-4 rounded-lg p-4" style={{ backgroundColor: "#0c1322", border: "1px solid #2e3545" }}>
                <MarkdownText text={correlationText} />
              </div>
            )}
          </div>

          <div className="rounded-lg overflow-hidden" style={{ border: "1px solid #424754" }}>
            <div className="flex border-b" style={{ backgroundColor: "#191f2f", borderColor: "#424754" }}>
              {(["analysis", "explanation"] as const).map(t => (
                <button key={t} onClick={() => setTab(t)} className="px-5 py-3 font-label-caps transition-colors"
                  style={{ fontSize: "10px", color: tab === t ? "#adc6ff" : "#8c909f", borderBottom: tab === t ? "2px solid #adc6ff" : "2px solid transparent", backgroundColor: "transparent" }}>
                  {t === "analysis" ? "ANALYSIS REPORT" : "LLM EXPLANATION"}
                </button>
              ))}
            </div>
            <div className="p-5" style={{ backgroundColor: "#141b2b" }}>
              <MarkdownText text={tab === "analysis" ? result.analysis_text : result.explanation} />
            </div>
          </div>
        </div>
      )}

      {!result && !running && !error && (
        <div className="flex flex-col items-center gap-4 py-20">
          <span className="material-symbols-outlined" style={{ fontSize: "56px", color: "#2e3545" }}>table_chart</span>
          <p className="font-body-sm text-on-surface-variant text-center max-w-md">Select a CSV file and click <strong className="text-on-surface">RUN ANALYSIS</strong> to detect anomalies using Autoencoder + Isolation Forest consensus.</p>
        </div>
      )}
    </div>
  );
}
