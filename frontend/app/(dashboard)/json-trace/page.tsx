"use client";
import { useState } from "react";
import type { ReactNode } from "react";
import { correlateTraceWithContract, runJSONTrace, listFiles } from "../../lib/api";
import { useSession } from "../../context/SessionContext";

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
          <table className="w-full border-collapse" style={{ minWidth: "680px" }}>
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
      blocks.push(<h4 key={`h3-${i}`} className="font-headline-sm mt-5 mb-3" style={{ color: "#adc6ff", fontSize: "16px" }}>{inline(line.slice(4))}</h4>);
      continue;
    }
    if (line.startsWith("#### ")) {
      blocks.push(<h5 key={`h4-${i}`} className="font-label-caps mt-4 mb-2" style={{ color: "#8fb3ff", fontSize: "11px" }}>{inline(line.slice(5))}</h5>);
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
            <li key={index} className="flex gap-2" style={{ color: "#c2c6d6", fontSize: "13px", lineHeight: 1.65 }}>
              <span style={{ color: "#4cd7f6" }}>-</span>
              <span>{inline(item)}</span>
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

const isTraceJson = (filename: string) => {
  const lower = filename.toLowerCase();
  return lower.endsWith(".json") && !lower.includes("abi") && (lower.includes("trace") || lower.includes("transaction"));
};

export default function JSONTracePage() {
  const session = useSession();
  const [fileList, setFileList]       = useState<string[]>([]);
  const [filesLoaded, setFilesLoaded] = useState(false);
  const [selected, setSelected]       = useState(session.traceFile || "");
  const [running, setRunning]         = useState(false);
  const [error, setError]             = useState<string | null>(null);
  const [correlating, setCorrelating] = useState(false);
  const [correlationError, setCorrelationError] = useState<string | null>(null);
  const [correlationText, setCorrelationText] = useState("");

  const result = session.traceResult;

  const loadFiles = async () => {
    if (filesLoaded) return;
    try { const { files } = await listFiles(); setFileList(files.filter(isTraceJson)); setFilesLoaded(true); }
    catch { setFileList([]); }
  };

  const handleRun = async () => {
    if (!selected) return;
    setRunning(true); setError(null); session.setTraceResult(selected, null);
    try { const r = await runJSONTrace(selected); session.setTraceResult(selected, r); }
    catch (e: unknown) { setError(e instanceof Error ? e.message : "Analysis failed"); }
    finally { setRunning(false); }
  };

  const handleCorrelate = async () => {
    if (!result || !session.auditResult) return;
    setCorrelating(true);
    setCorrelationError(null);
    setCorrelationText("");
    try {
      const response = await correlateTraceWithContract(
        session.auditResult.filename,
        session.auditResult.audit_text,
        session.auditResult.line_map,
        result.trace_text
      );
      setCorrelationText(response.correlation_text);
    } catch (e: unknown) {
      setCorrelationError(e instanceof Error ? e.message : "Correlation failed");
    } finally {
      setCorrelating(false);
    }
  };

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-start justify-between gap-4 flex-wrap">
        <div>
          <h1 className="font-headline-md text-headline-md text-on-surface">JSON Trace Analysis</h1>
          <p className="font-body-sm text-body-sm text-on-surface-variant mt-1">Isolation Forest anomaly scoring · ABI decoding · Execution call tree</p>
        </div>
        <div className="flex items-center gap-3">
          <select value={selected} onFocus={loadFiles} onChange={e => setSelected(e.target.value)}
            className="rounded px-3 py-2 font-code-sm text-on-surface outline-none"
            style={{ backgroundColor: "#191f2f", border: "1px solid #424754", minWidth: "220px", fontSize: "12px" }}>
            <option value="">Select a trace .json file...</option>
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
          <p className="font-body-sm text-on-surface-variant">Flattening call tree and scoring anomalies on {selected}…</p>
        </div>
      )}

      {result && (
        <div className="space-y-4">
        <div className="p-5 rounded-lg" style={{ backgroundColor: "#141b2b", border: "1px solid #424754" }}>
          <div className="flex items-center justify-between mb-4">
            <h3 className="font-headline-sm text-on-surface">Trace Analysis — {session.traceFile}</h3>
          </div>
          <MarkdownText text={result.trace_text} />
        </div>
        <div className="p-5 rounded-lg" style={{ backgroundColor: "#141b2b", border: "1px solid #424754" }}>
          <div className="flex items-center justify-between gap-3 flex-wrap">
            <div>
              <h3 className="font-headline-sm text-on-surface">Trace to Contract Correlation</h3>
              <p className="font-body-sm text-body-sm text-on-surface-variant mt-1">Compare runtime trace behavior with the last Solidity audit result.</p>
            </div>
            <button
              onClick={handleCorrelate}
              disabled={correlating || !session.auditResult}
              className="px-4 py-2 rounded font-label-caps font-bold transition-all active:scale-95"
              style={{ backgroundColor: correlating || !session.auditResult ? "#2e3545" : "#adc6ff", color: correlating || !session.auditResult ? "#424754" : "#002e6a", fontSize: "10px" }}
            >
              {correlating ? "CORRELATING..." : "CORRELATE WITH CONTRACT"}
            </button>
          </div>
          {!session.auditResult && (
            <p className="font-body-sm text-body-sm text-on-surface-variant mt-3">Run a Solidity audit first, then return here to correlate this trace.</p>
          )}
          {correlationError && <p className="font-body-sm mt-3" style={{ color: "#ffb4ab" }}>{correlationError}</p>}
          {correlationText && (
            <div className="mt-4 rounded-lg p-4" style={{ backgroundColor: "#0c1322", border: "1px solid #2e3545" }}>
              <MarkdownText text={correlationText} />
            </div>
          )}
        </div>
        </div>
      )}

      {!result && !running && !error && (
        <div className="flex flex-col items-center gap-4 py-20">
          <span className="material-symbols-outlined" style={{ fontSize: "56px", color: "#2e3545" }}>schema</span>
          <p className="font-body-sm text-on-surface-variant text-center max-w-md">Select a JSON trace file and click <strong className="text-on-surface">RUN ANALYSIS</strong> to flatten the execution call tree, score anomalous calls, and decode function selectors.</p>
        </div>
      )}
    </div>
  );
}
