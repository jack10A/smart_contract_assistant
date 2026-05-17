"use client";
import { useState } from "react";
import type { ReactNode } from "react";
import { runImageSecurity, listFiles } from "../../lib/api";
import { useSession } from "../../context/SessionContext";

const BASE = process.env.NEXT_PUBLIC_BACKEND_URL ?? "http://localhost:7860";
const IMAGE_EXTS = [".png", ".jpg", ".jpeg", ".webp"];

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

    if (line.startsWith("```")) {
      const codeLines: string[] = [];
      i += 1;
      while (i < lines.length && !lines[i].trim().startsWith("```")) {
        codeLines.push(lines[i]);
        i += 1;
      }
      blocks.push(
        <pre key={`code-${i}`} className="overflow-auto rounded p-3" style={{ backgroundColor: "#03060b", border: "1px solid #2e3545", color: "#dce2f7", fontSize: "12px", lineHeight: 1.7, maxHeight: "360px" }}>
          {codeLines.join("\n")}
        </pre>
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

export default function ImageSecurityPage() {
  const session = useSession();
  const [fileList, setFileList]       = useState<string[]>([]);
  const [filesLoaded, setFilesLoaded] = useState(false);
  const [selected, setSelected]       = useState(session.imageFile || "");
  const [running, setRunning]         = useState(false);
  const [error, setError]             = useState<string | null>(null);

  const result = session.imageResult;
  const imageUrl = result?.image_url ?? (session.imageFile ? `/uploads/${session.imageFile}` : "");
  const riskLevel = result?.risk_level ?? "Unknown";
  const riskScore = result?.risk_score ?? 0;
  const riskColor = riskLevel.toLowerCase().includes("high") ? "#ffb4ab" : riskLevel.toLowerCase().includes("medium") ? "#ffb786" : "#4cd7f6";

  const loadFiles = async () => {
    if (filesLoaded) return;
    try { const { files } = await listFiles(); setFileList(files.filter(f => IMAGE_EXTS.some(ext => f.toLowerCase().endsWith(ext)))); setFilesLoaded(true); }
    catch { setFileList([]); }
  };

  const handleRun = async () => {
    if (!selected) return;
    setRunning(true); setError(null); session.setImageResult(selected, null);
    try { const r = await runImageSecurity(selected); session.setImageResult(selected, r); }
    catch (e: unknown) { setError(e instanceof Error ? e.message : "Analysis failed"); }
    finally { setRunning(false); }
  };

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-start justify-between gap-4 flex-wrap">
        <div>
          <h1 className="font-headline-md text-headline-md text-on-surface">Image Security Analysis</h1>
          <p className="font-body-sm text-body-sm text-on-surface-variant mt-1">OCR text extraction · Phishing indicator detection · Address and hash extraction</p>
        </div>
        <div className="flex items-center gap-3">
          <select value={selected} onFocus={loadFiles} onChange={e => setSelected(e.target.value)}
            className="rounded px-3 py-2 font-code-sm text-on-surface outline-none"
            style={{ backgroundColor: "#191f2f", border: "1px solid #424754", minWidth: "220px", fontSize: "12px" }}>
            <option value="">Select an image file…</option>
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
          <p className="font-body-sm text-on-surface-variant">Running OCR and security analysis on {selected}…</p>
        </div>
      )}

      {result && (
        <div className="space-y-4">
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            {[
              { label: "Risk Score", value: `${riskScore}/100`, color: riskColor },
              { label: "Risk Level", value: riskLevel, color: riskColor },
              { label: "Classifier", value: result.classifier_label ?? "Unknown", color: "#adc6ff" },
              { label: "OCR Engine", value: result.ocr_engine ?? "Unknown", color: "#c2c6d6" },
            ].map(({ label, value, color }) => (
              <div key={label} className="p-4 rounded-lg" style={{ backgroundColor: "#191f2f", border: "1px solid #424754" }}>
                <p className="font-label-caps text-on-surface-variant" style={{ fontSize: "10px" }}>{label}</p>
                <p className="font-headline-sm mt-1 truncate" style={{ color, fontSize: "16px" }}>{value}</p>
              </div>
            ))}
          </div>

          <div className="grid grid-cols-12 gap-4">
          <div className="col-span-12 lg:col-span-4">
            <div className="p-4 rounded-lg" style={{ backgroundColor: "#141b2b", border: "1px solid #424754" }}>
              <h3 className="font-headline-sm text-on-surface mb-3">Image</h3>
              <a href={`${BASE}${imageUrl}`} target="_blank" rel="noreferrer">
                <img src={`${BASE}${imageUrl}`} alt={result.filename ?? session.imageFile} className="w-full rounded" style={{ border: "1px solid #424754", maxHeight: "520px", objectFit: "contain", backgroundColor: "#ffffff" }} />
              </a>
              <div className="flex items-center justify-between gap-2 mt-3">
                <p className="font-code-sm text-on-surface-variant truncate" style={{ fontSize: "11px" }}>{result.filename ?? session.imageFile}</p>
                <span className="font-label-caps px-2 py-1 rounded" style={{ fontSize: "10px", color: riskColor, backgroundColor: `${riskColor}18` }}>{result.dimensions}</span>
              </div>
            </div>
          </div>
          <div className="col-span-12 lg:col-span-8">
            <div className="p-5 rounded-lg" style={{ backgroundColor: "#141b2b", border: "1px solid #424754" }}>
              <h3 className="font-headline-sm text-on-surface mb-4">Security Analysis Report</h3>
              <MarkdownText text={result.image_text} />
            </div>
          </div>
          </div>
        </div>
      )}

      {!result && !running && !error && (
        <div className="flex flex-col items-center gap-4 py-20">
          <span className="material-symbols-outlined" style={{ fontSize: "56px", color: "#2e3545" }}>image_search</span>
          <p className="font-body-sm text-on-surface-variant text-center max-w-md">Select a screenshot and click <strong className="text-on-surface">RUN ANALYSIS</strong> to extract text via OCR and detect phishing indicators.</p>
        </div>
      )}
    </div>
  );
}
