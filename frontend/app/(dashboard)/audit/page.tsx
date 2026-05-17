"use client";
import { useState } from "react";
import type { ReactNode } from "react";
import { runAudit, generateFix, listFiles } from "../../lib/api";
import { useSession } from "../../context/SessionContext";

const STATIC_CODE_LINES = [
  { ln: 44, code: "function withdraw(uint256 _amount) public {",             highlight: null,        note: null },
  { ln: 45, code: "    require(balances[msg.sender] >= _amount);",           highlight: null,        note: null },
  { ln: 47, code: '    (bool success, ) = msg.sender.call{value: _amount}("");', highlight: "error", note: "← Primary Evidence: Unchecked External Call" },
  { ln: 48, code: "    require(success);",                                   highlight: null,        note: null },
  { ln: 50, code: "    balances[msg.sender] -= _amount;",                   highlight: "tertiary",  note: "← Late State Update" },
  { ln: 51, code: "}",                                                       highlight: null,        note: null },
];
const highlightBg:     Record<string, string> = { error: "rgba(255,180,171,0.08)", tertiary: "rgba(223,116,18,0.08)" };
const highlightBorder: Record<string, string> = { error: "#ffb4ab",              tertiary: "#df7412" };

function DiffViewer({ raw }: { raw: string }) {
  return (
    <div className="font-code-base text-code-base leading-relaxed">
      {raw.split("\n").map((line, i) => {
        const isDel = line.startsWith("-") && !line.startsWith("---");
        const isAdd = line.startsWith("+") && !line.startsWith("+++");
        const isHdr = line.startsWith("@@");
        return (
          <div key={i} style={{
            backgroundColor: isDel ? "rgba(255,180,171,0.08)" : isAdd ? "rgba(76,215,246,0.06)" : isHdr ? "rgba(173,198,255,0.05)" : "transparent",
            color: isDel ? "#ffb4ab" : isAdd ? "#4cd7f6" : isHdr ? "#adc6ff" : "#dce2f7",
            padding: "1px 8px", whiteSpace: "pre", fontSize: "12px",
          }}>{line}</div>
        );
      })}
    </div>
  );
}

function InlineMarkdown({ text }: { text: string }) {
  const parts = text.split(/(`[^`]+`|\*\*[^*]+\*\*)/g).filter(Boolean);
  return (
    <>
      {parts.map((part, index) => {
        if (part.startsWith("`") && part.endsWith("`")) {
          return <code key={index} className="px-1 py-0.5 rounded" style={{ backgroundColor: "#070e1d", color: "#adc6ff" }}>{part.slice(1, -1)}</code>;
        }
        if (part.startsWith("**") && part.endsWith("**")) {
          return <strong key={index} style={{ color: "#f5f7ff" }}>{part.slice(2, -2)}</strong>;
        }
        return <span key={index}>{part}</span>;
      })}
    </>
  );
}

function MarkdownText({ text }: { text: string }) {
  const lines = text.split("\n");
  const blocks: ReactNode[] = [];

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
          <table className="w-full border-collapse" style={{ minWidth: "620px" }}>
            <thead style={{ backgroundColor: "#191f2f" }}>
              <tr>
                {headers.map((header, index) => (
                  <th key={index} className="text-left px-3 py-2 font-label-caps" style={{ color: "#adc6ff", fontSize: "10px", borderBottom: "1px solid #2e3545" }}>
                    <InlineMarkdown text={header} />
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {bodyRows.map((row, rowIndex) => (
                <tr key={rowIndex} style={{ borderTop: rowIndex ? "1px solid #20283a" : undefined }}>
                  {row.map((cell, cellIndex) => (
                    <td key={cellIndex} className="align-top px-3 py-2" style={{ color: "#dce2f7", fontSize: "12px", lineHeight: 1.6 }}>
                      <InlineMarkdown text={cell} />
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

    if (line.startsWith("### ")) {
      blocks.push(<h4 key={`h3-${i}`} className="font-headline-sm mt-5 mb-3" style={{ color: "#adc6ff", fontSize: "16px" }}><InlineMarkdown text={line.slice(4)} /></h4>);
      continue;
    }

    if (line.startsWith("#### ")) {
      blocks.push(<h5 key={`h4-${i}`} className="font-label-caps mt-4 mb-2" style={{ color: "#8fb3ff", fontSize: "11px" }}><InlineMarkdown text={line.slice(5)} /></h5>);
      continue;
    }

    if (line.startsWith("- ")) {
      const items = [line.slice(2)];
      while (i + 1 < lines.length && lines[i + 1].trim().startsWith("- ")) {
        i += 1;
        items.push(lines[i].trim().slice(2));
      }
      blocks.push(
        <ul key={`list-${i}`} className="space-y-1.5 my-3 pl-0">
          {items.map((item, index) => (
            <li key={index} className="flex gap-2" style={{ color: "#c2c6d6", fontSize: "13px", lineHeight: 1.65 }}>
              <span style={{ color: "#4cd7f6" }}>-</span>
              <span><InlineMarkdown text={item} /></span>
            </li>
          ))}
        </ul>
      );
      continue;
    }

    if (line.startsWith("> ")) {
      blocks.push(
        <blockquote key={`quote-${i}`} className="my-3 rounded px-3 py-2" style={{ backgroundColor: "rgba(76,215,246,0.06)", borderLeft: "3px solid #4cd7f6", color: "#dce2f7", fontSize: "13px" }}>
          <InlineMarkdown text={line.slice(2)} />
        </blockquote>
      );
      continue;
    }

    blocks.push(<p key={`p-${i}`} className="my-2" style={{ color: "#dce2f7", fontSize: "13px", lineHeight: 1.7 }}><InlineMarkdown text={line} /></p>);
  }

  return <div>{blocks}</div>;
}

function ConfBar({ label, score, color }: { label: string; score: number; color: string }) {
  return (
    <div className="mb-2">
      <div className="flex justify-between mb-0.5">
        <span className="font-label-caps text-on-surface-variant" style={{ fontSize: "10px" }}>{label}</span>
        <span className="font-code-sm" style={{ color, fontSize: "11px" }}>{(score * 100).toFixed(1)}%</span>
      </div>
      <div className="h-1.5 rounded-full overflow-hidden" style={{ backgroundColor: "#2e3545" }}>
        <div className="h-full rounded-full" style={{ width: `${score * 100}%`, backgroundColor: color }} />
      </div>
    </div>
  );
}

export default function AuditPage() {
  const session = useSession();

  const [fileList, setFileList]       = useState<string[]>([]);
  const [filesLoaded, setFilesLoaded] = useState(false);
  const [selectedFile, setSelectedFile] = useState(session.selectedFile || "");
  const [auditRunning, setAuditRunning] = useState(false);
  const [auditError, setAuditError]     = useState<string | null>(null);
  const [fixRunning, setFixRunning]     = useState(false);
  const [fixError, setFixError]         = useState<string | null>(null);
  const [fixTab, setFixTab]             = useState<"diff" | "explanation">("diff");

  const auditResult = session.auditResult;
  const fixResult   = session.fixResult;
  const selectedAuditFile = selectedFile || session.selectedFile;
  const visibleFileList = session.selectedFile?.toLowerCase().endsWith(".sol") && !fileList.includes(session.selectedFile)
    ? [...fileList, session.selectedFile].sort()
    : fileList;

  const loadFiles = async () => {
    if (filesLoaded) return;
    try {
      const { files } = await listFiles();
      setFileList(files.filter((f) => f.toLowerCase().endsWith(".sol")));
      setFilesLoaded(true);
    } catch { setFileList([]); }
  };

  const handleRunAudit = async () => {
    if (!selectedAuditFile) return;
    setAuditRunning(true);
    setAuditError(null);
    session.setAuditResult(null);
    session.setFixResult(null);
    session.setSelectedFile(selectedAuditFile);
    try {
      const result = await runAudit(selectedAuditFile);
      session.setAuditResult(result);
    } catch (e: unknown) {
      setAuditError(e instanceof Error ? e.message : "Audit failed");
    } finally {
      setAuditRunning(false);
    }
  };

  const handleGenerateFix = async () => {
    if (!auditResult) return;
    setFixRunning(true);
    setFixError(null);
    session.setFixResult(null);
    try {
      const result = await generateFix(auditResult.filename, auditResult.audit_text, auditResult.risk_text);
      session.setFixResult(result);
    } catch (e: unknown) {
      setFixError(e instanceof Error ? e.message : "Fix generation failed");
    } finally {
      setFixRunning(false);
    }
  };

  const pred = auditResult?.prediction;
  const riskColor = pred?.confidence && pred.confidence >= 0.65 ? "#ffb4ab" : pred?.confidence && pred.confidence >= 0.40 ? "#ffb786" : "#4cd7f6";

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex items-start justify-between gap-4 flex-wrap">
        <div>
          <h1 className="font-headline-md text-headline-md text-on-surface">Smart Contract Audit</h1>
          <p className="font-body-sm text-body-sm text-on-surface-variant mt-1">CodeBERT classifier · Slither static analyzer · AI fix generator</p>
        </div>
        <div className="flex items-center gap-3">
          <select
            value={selectedAuditFile}
            onFocus={loadFiles}
            onChange={(e) => {
              setSelectedFile(e.target.value);
              session.setSelectedFile(e.target.value);
            }}
            className="rounded px-3 py-2 font-code-sm text-code-sm text-on-surface outline-none"
            style={{ backgroundColor: "#191f2f", border: "1px solid #424754", minWidth: "240px" }}
          >
            <option value="">Select a .sol file…</option>
            {visibleFileList.map((f) => <option key={f} value={f}>{f}</option>)}
          </select>
          <button
            onClick={handleRunAudit}
            disabled={!selectedAuditFile || auditRunning}
            className="px-6 py-2 rounded font-label-caps font-bold transition-all active:scale-95"
            style={{ backgroundColor: !selectedAuditFile || auditRunning ? "#2e3545" : "#adc6ff", color: !selectedAuditFile || auditRunning ? "#424754" : "#002e6a" }}
          >
            {auditRunning ? "AUDITING…" : "RUN AUDIT"}
          </button>
        </div>
      </div>

      {auditError && (
        <div className="p-4 rounded-lg font-body-sm" style={{ backgroundColor: "rgba(255,180,171,0.08)", border: "1px solid rgba(255,180,171,0.3)", color: "#ffb4ab" }}>
          {auditError}
        </div>
      )}

      {auditRunning && (
        <div className="space-y-3">
          {[80, 60, 90].map((w, i) => (
            <div key={i} className="h-4 rounded animate-pulse" style={{ width: `${w}%`, backgroundColor: "#191f2f" }} />
          ))}
          <p className="font-body-sm text-body-sm text-on-surface-variant">Running CodeBERT + Slither on {selectedAuditFile}…</p>
        </div>
      )}

      {auditResult ? (
        <div className="grid grid-cols-12 gap-4">
          {/* Prediction */}
          <div className="col-span-12 lg:col-span-4 p-5 rounded-lg" style={{ backgroundColor: "#141b2b", border: `1px solid ${riskColor}40` }}>
            <h3 className="font-headline-sm text-headline-sm text-on-surface mb-4">Prediction</h3>
            <div className="flex items-center gap-3 p-3 rounded-lg mb-4" style={{ backgroundColor: `${riskColor}10`, border: `1px solid ${riskColor}30` }}>
              <span className="material-symbols-outlined" style={{ fontSize: "28px", color: riskColor }}>{pred?.is_vulnerable ? "warning" : "verified"}</span>
              <div>
                <p className="font-label-caps" style={{ color: riskColor }}>{pred?.label ?? "—"}</p>
                <p className="font-body-sm text-body-sm text-on-surface-variant">{pred?.risk ?? "—"}</p>
              </div>
            </div>
            {Object.entries(pred?.all_scores ?? {}).map(([label, score]) => (
              <ConfBar key={label} label={label} score={score} color={score >= 0.65 ? "#ffb4ab" : score >= 0.40 ? "#ffb786" : "#8c909f"} />
            ))}
          </div>

          {/* Audit text */}
          <div className="col-span-12 lg:col-span-8 p-5 rounded-lg" style={{ backgroundColor: "#141b2b", border: "1px solid #424754" }}>
            <h3 className="font-headline-sm text-headline-sm text-on-surface mb-4">Audit Report</h3>
            <MarkdownText text={auditResult.audit_text} />
          </div>

          {/* Risk dashboard */}
          <div className="col-span-12 lg:col-span-6 p-5 rounded-lg" style={{ backgroundColor: "#141b2b", border: "1px solid #424754" }}>
            <h3 className="font-headline-sm text-headline-sm text-on-surface mb-4">Risk Dashboard</h3>
            <MarkdownText text={auditResult.risk_text} />
          </div>

          {/* Slither */}
          <div className="col-span-12 lg:col-span-6 p-5 rounded-lg" style={{ backgroundColor: "#141b2b", border: "1px solid #424754" }}>
            <h3 className="font-headline-sm text-headline-sm text-on-surface mb-4">Slither Static Analysis</h3>
            <MarkdownText text={auditResult.slither_report} />
          </div>

          {/* Function analysis */}
          <div className="col-span-12 p-5 rounded-lg" style={{ backgroundColor: "#141b2b", border: "1px solid #424754" }}>
            <h3 className="font-headline-sm text-headline-sm text-on-surface mb-4">Function Analysis</h3>
            <MarkdownText text={auditResult.function_analysis} />
          </div>

          {/* Embedded Fix Generator */}
          <div className="col-span-12 rounded-lg overflow-hidden" style={{ border: "1px solid #424754" }}>
            <div className="flex items-center justify-between px-6 py-4" style={{ backgroundColor: "#191f2f", borderBottom: "1px solid #424754" }}>
              <div className="flex items-center gap-3">
                <span className="material-symbols-outlined" style={{ fontSize: "20px", color: "#adc6ff" }}>auto_fix</span>
                <div>
                  <h3 className="font-headline-sm text-headline-sm text-on-surface">Fix Generator</h3>
                  <p className="font-body-sm text-body-sm text-on-surface-variant">Llama 3.3-70B generates a patched contract + re-audits with Slither</p>
                </div>
              </div>
              <button
                onClick={handleGenerateFix}
                disabled={fixRunning}
                className="px-6 py-2 rounded font-label-caps font-bold transition-all active:scale-95"
                style={{ backgroundColor: fixRunning ? "#2e3545" : "#adc6ff", color: fixRunning ? "#424754" : "#002e6a" }}
              >
                {fixRunning ? "GENERATING…" : "GENERATE FIX"}
              </button>
            </div>

            {fixError && (
              <div className="px-6 py-4" style={{ backgroundColor: "rgba(255,180,171,0.05)" }}>
                <p className="font-body-sm" style={{ color: "#ffb4ab" }}>{fixError}</p>
              </div>
            )}

            {fixRunning && (
              <div className="px-6 py-8 flex flex-col items-center gap-3">
                <div className="flex gap-2">{[0,1,2].map(i => <div key={i} className="w-2 h-2 rounded-full animate-bounce" style={{ backgroundColor: "#4cd7f6", animationDelay: `${i*150}ms` }} />)}</div>
                <p className="font-body-sm text-body-sm text-on-surface-variant">Generating fix with Llama 3.3-70B · re-auditing with Slither…</p>
              </div>
            )}

            {fixResult ? (
              <div className="p-6 space-y-4">
                {!fixResult.fixed_filename ? (
                  <div className="p-4 rounded-lg flex items-start gap-3" style={{ backgroundColor: "rgba(76,215,246,0.06)", border: "1px solid rgba(76,215,246,0.24)" }}>
                    <span className="material-symbols-outlined" style={{ fontSize: "20px", color: "#4cd7f6" }}>verified</span>
                    <div>
                      <h4 className="font-label-caps mb-2" style={{ color: "#4cd7f6" }}>NO PATCH GENERATED</h4>
                      <MarkdownText text={fixResult.diff_markdown || fixResult.fix_explanation} />
                    </div>
                  </div>
                ) : (
                  <>
                    <div className="flex gap-1">
                      {(["diff", "explanation"] as const).map((tab) => (
                        <button key={tab} onClick={() => setFixTab(tab)}
                          className="px-4 py-1.5 rounded font-label-caps transition-colors"
                          style={{ backgroundColor: fixTab === tab ? "#adc6ff" : "#2e3545", color: fixTab === tab ? "#002e6a" : "#8c909f", fontSize: "10px" }}
                        >
                          {tab === "diff" ? "PATCH DIFF" : "EXPLANATION + RE-AUDIT"}
                        </button>
                      ))}
                    </div>

                    {fixTab === "diff" ? (
                      <div className="rounded-lg overflow-auto" style={{ backgroundColor: "#03060b", border: "1px solid #2e3545", maxHeight: "500px", padding: "16px" }}>
                        <DiffViewer raw={fixResult.diff_markdown.replace(/^### Patch Diff\n\n```diff\n/, "").replace(/\n```$/, "")} />
                      </div>
                    ) : (
                      <div className="space-y-4">
                        <div className="p-4 rounded-lg" style={{ backgroundColor: "#141b2b", border: "1px solid #424754" }}>
                          <h4 className="font-label-caps text-on-surface-variant mb-3">FIX EXPLANATION</h4>
                          <MarkdownText text={fixResult.fix_explanation} />
                        </div>
                        <div className="p-4 rounded-lg" style={{ backgroundColor: "#141b2b", border: "1px solid #424754" }}>
                          <h4 className="font-label-caps text-on-surface-variant mb-3">SLITHER RE-AUDIT</h4>
                          <MarkdownText text={fixResult.reaudit} />
                        </div>
                      </div>
                    )}

                    <div className="flex items-center justify-between pt-2" style={{ borderTop: "1px solid #2e3545" }}>
                      <span className="font-label-caps text-on-surface-variant" style={{ fontSize: "10px" }}>Fixed file: {fixResult.fixed_filename}</span>
                      <a
                        href={`${process.env.NEXT_PUBLIC_BACKEND_URL ?? "http://localhost:7860"}/api/download/fixed/${fixResult.fixed_filename}`}
                        download={fixResult.fixed_filename}
                        className="flex items-center gap-1.5 px-3 py-1.5 rounded font-label-caps"
                        style={{ backgroundColor: "#adc6ff", color: "#002e6a", fontSize: "10px" }}
                      >
                        <span className="material-symbols-outlined" style={{ fontSize: "14px" }}>download</span>
                        DOWNLOAD FIXED CONTRACT
                      </a>
                    </div>
                  </>
                )}
              </div>
            ) : !fixRunning && !fixError && (
              <div className="px-6 py-8 flex flex-col items-center gap-2 text-center">
                <span className="material-symbols-outlined" style={{ fontSize: "40px", color: "#424754" }}>auto_fix_high</span>
                <p className="font-label-caps text-on-surface-variant" style={{ fontSize: "11px" }}>Click GENERATE FIX to produce a patched contract and patch diff</p>
              </div>
            )}
          </div>
        </div>
      ) : !auditRunning && (
        <div className="space-y-4">
          <div className="rounded-lg overflow-hidden" style={{ backgroundColor: "#03060b", border: "1px solid #424754" }}>
            <div className="flex items-center justify-between px-4 py-2" style={{ backgroundColor: "#191f2f", borderBottom: "1px solid #424754" }}>
              <span className="font-label-caps" style={{ color: "#adc6ff" }}>hybrid_vulnerable_test.sol</span>
              <span className="font-label-caps text-on-surface-variant" style={{ fontSize: "10px" }}>Select a file and run audit to see results</span>
            </div>
            <div className="p-4 font-code-base text-code-base">
              {STATIC_CODE_LINES.map((line, i) => (
                <div key={i} className="flex items-start rounded-sm mb-0.5" style={{ backgroundColor: line.highlight ? highlightBg[line.highlight] : "transparent", borderLeft: line.highlight ? `3px solid ${highlightBorder[line.highlight]}` : "3px solid transparent", padding: "2px 8px" }}>
                  <span className="w-8 shrink-0 text-right pr-3 select-none" style={{ color: "#424754", fontSize: "12px" }}>{line.ln}</span>
                  <span style={{ color: line.highlight === "error" ? "#ffb4ab" : "#dce2f7", whiteSpace: "pre", fontSize: "12px" }}>{line.code}</span>
                  {line.note && <span className="ml-3 font-label-caps" style={{ fontSize: "10px", color: highlightBorder[line.highlight!] }}>{line.note}</span>}
                </div>
              ))}
            </div>
          </div>
          <div className="flex items-center gap-3 p-4 rounded-lg" style={{ backgroundColor: "#141b2b", border: "1px solid #424754" }}>
            <span className="material-symbols-outlined" style={{ fontSize: "24px", color: "#424754" }}>info</span>
            <p className="font-body-sm text-body-sm text-on-surface-variant">Select a Solidity file and click <strong className="text-on-surface">RUN AUDIT</strong>. Results persist when you switch tabs.</p>
          </div>
        </div>
      )}
    </div>
  );
}
