"use client";
import { useEffect, useMemo, useState } from "react";
import { getSourceFile } from "../../lib/api";
import { useSession } from "../../context/SessionContext";

type EvidenceLine = {
  ln: number;
  code: string;
  severity: "PRIMARY" | "SURFACE" | "OTHER";
  tag: string;
  note: string;
};

const sevColors: Record<EvidenceLine["severity"], { bg: string; text: string; border: string; label: string }> = {
  PRIMARY: { bg: "rgba(255,180,171,0.08)", text: "#ffb4ab", border: "#ffb4ab", label: "PRIMARY" },
  SURFACE: { bg: "rgba(255,183,134,0.08)", text: "#ffb786", border: "#df7412", label: "SURFACE" },
  OTHER: { bg: "rgba(76,215,246,0.06)", text: "#4cd7f6", border: "#03b5d3", label: "OTHER" },
};

const parseEvidenceLines = (lineMap?: string): EvidenceLine[] => {
  if (!lineMap) return [];
  const lines = lineMap.split("\n");
  const evidence: EvidenceLine[] = [];
  let group: EvidenceLine["severity"] = "OTHER";

  for (let i = 0; i < lines.length; i += 1) {
    const line = lines[i].trim();
    if (line.startsWith("#### Primary Evidence")) group = "PRIMARY";
    if (line.startsWith("#### Related Attack Surface")) group = "SURFACE";
    if (line.startsWith("#### Other Security-Relevant Lines")) group = "OTHER";

    const heading = line.match(/^\*\*Line\s+(\d+):\s+([^*]+)\*\*$/);
    if (!heading) continue;

    const snippet: string[] = [];
    let note = "";
    i += 1;
    while (i < lines.length && !lines[i].trim().startsWith("```solidity")) i += 1;
    i += 1;
    while (i < lines.length && !lines[i].trim().startsWith("```")) {
      snippet.push(lines[i]);
      i += 1;
    }
    if (i + 1 < lines.length && lines[i + 1].trim().startsWith("Review note:")) {
      note = lines[i + 1].trim().replace(/^Review note:\s*/, "");
    }

    evidence.push({
      ln: Number(heading[1]),
      tag: heading[2].trim(),
      code: snippet.join("\n").trim(),
      severity: group,
      note,
    });
  }

  return evidence;
};

export default function LineEvidencePage() {
  const session = useSession();
  const audit = session.auditResult;
  const [fetchedSource, setFetchedSource] = useState<{ filename: string; source: string } | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const timer = window.setTimeout(() => {
      setError(null);
      if (!audit?.filename || audit.source_code) return;
      getSourceFile(audit.filename)
        .then((response) => setFetchedSource({ filename: response.filename, source: response.source_code }))
        .catch((e: unknown) => setError(e instanceof Error ? e.message : "Could not load source file"));
    }, 0);
    return () => window.clearTimeout(timer);
  }, [audit?.filename, audit?.source_code]);

  const evidenceLines = useMemo(() => parseEvidenceLines(audit?.line_map), [audit?.line_map]);
  const evidenceByLine = useMemo(() => {
    const map = new Map<number, EvidenceLine>();
    evidenceLines.forEach((item) => map.set(item.ln, item));
    return map;
  }, [evidenceLines]);

  const sourceCode = audit?.source_code ?? (fetchedSource?.filename === audit?.filename ? fetchedSource.source : "");
  const sourceLines = sourceCode ? sourceCode.split("\n") : [];

  if (!audit) {
    return (
      <div className="p-6 space-y-6">
        <div>
          <h1 className="font-headline-md text-headline-md text-on-surface">Line Evidence</h1>
          <p className="font-body-sm text-body-sm text-on-surface-variant mt-1">Source-code evidence from the current Solidity audit.</p>
        </div>
        <div className="flex flex-col items-center gap-4 py-20 rounded-lg" style={{ backgroundColor: "#141b2b", border: "1px solid #424754" }}>
          <span className="material-symbols-outlined" style={{ fontSize: "56px", color: "#2e3545" }}>terminal</span>
          <p className="font-body-sm text-body-sm text-on-surface-variant text-center max-w-md">
            Run a <strong className="text-on-surface">Smart Contract Audit</strong> first. Highlighted source evidence will appear here.
          </p>
        </div>
      </div>
    );
  }

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-start justify-between gap-4 flex-wrap">
        <div>
          <h1 className="font-headline-md text-headline-md text-on-surface">Line Evidence</h1>
          <p className="font-body-sm text-body-sm text-on-surface-variant mt-1">
            Source code lines tagged as evidence - {audit.filename}
          </p>
        </div>
        <div className="flex gap-2 flex-wrap">
          {(["PRIMARY", "SURFACE", "OTHER"] as const).map((sev) => (
            <div key={sev} className="flex items-center gap-1.5 px-2 py-1 rounded" style={{ backgroundColor: sevColors[sev].bg, border: `1px solid ${sevColors[sev].border}30` }}>
              <div className="w-2 h-2 rounded-full" style={{ backgroundColor: sevColors[sev].text }} />
              <span className="font-label-caps" style={{ fontSize: "10px", color: sevColors[sev].text }}>{sevColors[sev].label}</span>
            </div>
          ))}
          <div className="px-3 py-1.5 rounded font-label-caps" style={{ backgroundColor: "rgba(76,215,246,0.1)", color: "#4cd7f6", border: "1px solid rgba(76,215,246,0.3)", fontSize: "10px" }}>
            {evidenceLines.length} TAGGED LINES
          </div>
        </div>
      </div>

      {error && (
        <div className="p-4 rounded-lg font-body-sm" style={{ backgroundColor: "rgba(255,180,171,0.08)", border: "1px solid rgba(255,180,171,0.3)", color: "#ffb4ab" }}>
          {error}
        </div>
      )}

      <div className="rounded-lg overflow-hidden" style={{ backgroundColor: "#03060b", border: "1px solid #424754" }}>
        <div className="flex items-center justify-between px-4 py-2" style={{ backgroundColor: "rgba(46,53,69,0.5)", borderBottom: "1px solid #424754" }}>
          <div className="flex gap-4 min-w-0">
            <span className="font-label-caps text-label-caps truncate" style={{ color: "#adc6ff" }}>{audit.filename}</span>
            <span className="font-label-caps text-label-caps text-on-surface-variant">Evidence View</span>
          </div>
          <span className="font-label-caps text-on-surface-variant" style={{ fontSize: "10px" }}>{sourceLines.length} lines</span>
        </div>

        <div className="p-4 font-code-base text-code-base overflow-auto" style={{ maxHeight: "68vh" }}>
          {sourceLines.length === 0 ? (
            <p className="font-body-sm text-body-sm text-on-surface-variant">Source code is not available for this audit result. Re-run the audit to attach the source viewer data.</p>
          ) : (
            sourceLines.map((code, index) => {
              const ln = index + 1;
              const evidence = evidenceByLine.get(ln);
              const colors = evidence ? sevColors[evidence.severity] : null;
              return (
                <div
                  key={ln}
                  className="flex items-start rounded-sm group"
                  style={{
                    backgroundColor: colors?.bg ?? "transparent",
                    borderLeft: evidence ? `3px solid ${colors?.border}` : "3px solid transparent",
                    padding: "2px 8px 2px 0",
                  }}
                >
                  <span
                    className="w-12 inline-block text-right pr-3 mr-3 shrink-0 select-none"
                    style={{ color: colors?.text ?? "#596174", borderRight: "1px solid #20283a" }}
                  >
                    {ln}
                  </span>
                  <div className="flex-1 min-w-0">
                    <pre className="whitespace-pre-wrap break-words text-on-surface" style={{ fontFamily: "inherit", fontSize: "12px", lineHeight: 1.7 }}>{code || " "}</pre>
                    {evidence && (
                      <div className="flex items-center gap-2 mt-1.5 mb-1 flex-wrap">
                        <span className="font-label-caps px-2 py-0.5 rounded" style={{ fontSize: "9px", backgroundColor: colors?.bg, color: colors?.text, border: `1px solid ${colors?.border}30` }}>
                          {colors?.label}
                        </span>
                        <span className="font-label-caps text-on-surface-variant" style={{ fontSize: "10px" }}>{evidence.tag}</span>
                        {evidence.note && <span className="font-body-sm text-on-surface-variant" style={{ fontSize: "11px" }}>{evidence.note}</span>}
                      </div>
                    )}
                  </div>
                </div>
              );
            })
          )}
        </div>
      </div>

      <div className="rounded-lg overflow-hidden" style={{ border: "1px solid #424754" }}>
        <div className="px-6 py-3" style={{ backgroundColor: "#191f2f", borderBottom: "1px solid #424754" }}>
          <h3 className="font-label-caps text-label-caps text-on-surface-variant">EVIDENCE SUMMARY TABLE</h3>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-left" style={{ borderCollapse: "collapse", minWidth: "760px" }}>
            <thead style={{ backgroundColor: "#070e1d" }}>
              <tr>
                {["Line", "Category", "Code Snippet", "Review Note"].map((h) => (
                  <th key={h} className="px-4 py-3 font-label-caps text-label-caps text-on-surface-variant">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {evidenceLines.length === 0 ? (
                <tr>
                  <td colSpan={4} className="px-4 py-6 font-body-sm text-body-sm text-on-surface-variant">No suspicious source lines were matched for this audit.</td>
                </tr>
              ) : evidenceLines.map((line) => {
                const colors = sevColors[line.severity];
                return (
                  <tr key={`${line.ln}-${line.tag}`} className="transition-colors hover:bg-surface-container-highest" style={{ borderTop: "1px solid #424754" }}>
                    <td className="px-4 py-3 font-code-sm text-code-sm" style={{ color: colors.text }}>{line.ln}</td>
                    <td className="px-4 py-3">
                      <span className="font-label-caps px-2 py-0.5 rounded" style={{ fontSize: "10px", backgroundColor: colors.bg, color: colors.text, border: `1px solid ${colors.border}30` }}>
                        {line.tag}
                      </span>
                    </td>
                    <td className="px-4 py-3 font-code-sm text-code-sm text-on-surface max-w-md truncate">{line.code}</td>
                    <td className="px-4 py-3 font-body-sm text-body-sm text-on-surface-variant">{line.note || "-"}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
