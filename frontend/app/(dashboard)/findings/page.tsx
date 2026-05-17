"use client";
import { useState } from "react";

const findings = [
  { id: "FND-001", name: "Reentrancy (State After Call)", severity: "CRITICAL", confidence: "98.2%", file: "hybrid_vulnerable_test.sol", fn: "withdrawBalances()", lines: "112-118", detectedBy: ["AI", "SL"], status: "OPEN",   description: "External call made before state update. Attacker can recursively drain balance." },
  { id: "FND-002", name: "Dangerous Delegatecall",       severity: "CRITICAL", confidence: "94.1%", file: "hybrid_vulnerable_test.sol", fn: "executeDelegate()", lines: "55",      detectedBy: ["AI", "SL"], status: "OPEN",   description: "Unprotected delegatecall allows arbitrary caller to manipulate proxy storage." },
  { id: "FND-003", name: "Integer Overflow (Legacy)",    severity: "HIGH",     confidence: "85.4%", file: "hybrid_vulnerable_test.sol", fn: "addLiquidity()",   lines: "44",      detectedBy: ["SM"],       status: "REVIEW", description: "Arithmetic overflow in unchecked block; pre-0.8 pattern." },
  { id: "FND-004", name: "Unprotected Ether Withdrawal", severity: "HIGH",     confidence: "91.0%", file: "hybrid_vulnerable_test.sol", fn: "emergencyExit()",  lines: "821-825", detectedBy: ["AI", "SL"], status: "OPEN",   description: "No access control on high-value withdrawal function." },
  { id: "FND-005", name: "Timestamp Dependency (PRNG)",  severity: "MEDIUM",   confidence: "76.8%", file: "hybrid_vulnerable_test.sol", fn: "lottery()",        lines: "442",     detectedBy: ["AI"],       status: "REVIEW", description: "block.timestamp can be manipulated within ~15 second window." },
  { id: "FND-006", name: "Missing Zero-Address Check",   severity: "MEDIUM",   confidence: "68.0%", file: "SafeMath.sol",              fn: "initialize()",     lines: "22",      detectedBy: ["SL"],       status: "REVIEW", description: "Contract can be initialized with zero address owner." },
  { id: "FND-007", name: "Unchecked Return Value",       severity: "LOW",      confidence: "55.0%", file: "hybrid_vulnerable_test.sol", fn: "transfer()",       lines: "200",     detectedBy: ["SL"],       status: "FIXED",  description: "Low-level call return value not checked." },
];

const sevColors: Record<string, { bg: string; text: string }> = {
  CRITICAL: { bg: "#93000a",              text: "#ffb4ab" },
  HIGH:     { bg: "rgba(223,116,18,0.2)", text: "#ffb786" },
  MEDIUM:   { bg: "rgba(76,215,246,0.1)", text: "#4cd7f6" },
  LOW:      { bg: "rgba(173,198,255,0.1)",text: "#adc6ff" },
  INFO:     { bg: "#2e3545",              text: "#c2c6d6" },
};
const statusColors: Record<string, string> = { OPEN: "#ffb4ab", REVIEW: "#ffb786", FIXED: "#4cd7f6" };
const detectorColors: Record<string, { bg: string; text: string }> = {
  AI: { bg: "#4cd7f6", text: "#003640" },
  SL: { bg: "#adc6ff", text: "#002e6a" },
  SM: { bg: "#ffb786", text: "#502400" },
};

export default function FindingsPage() {
  const [filter, setFilter] = useState("ALL");
  const [selected, setSelected] = useState<string | null>("FND-001");

  const filtered = filter === "ALL" ? findings : findings.filter((f) => f.severity === filter);
  const detail = findings.find((f) => f.id === selected);

  return (
    <div className="p-6 space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="font-headline-md text-headline-md text-on-surface">Vulnerability Findings</h1>
          <p className="font-body-sm text-body-sm text-on-surface-variant mt-1">
            {findings.length} findings detected across {new Set(findings.map((f) => f.file)).size} files
          </p>
        </div>
        <div className="flex gap-2">
          {["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW"].map((sev) => (
            <button
              key={sev}
              onClick={() => setFilter(sev)}
              className="px-3 py-1.5 rounded font-label-caps text-label-caps transition-colors"
              style={{
                backgroundColor: filter === sev ? "#adc6ff" : "#191f2f",
                color: filter === sev ? "#002e6a" : "#c2c6d6",
                border: "1px solid #424754",
              }}
            >
              {sev}
            </button>
          ))}
        </div>
      </div>

      <div className="grid grid-cols-12 gap-4">
        {/* Table */}
        <div className="col-span-12 xl:col-span-8">
          <div className="rounded-lg overflow-hidden" style={{ border: "1px solid #424754" }}>
            <table className="w-full text-left" style={{ borderCollapse: "collapse" }}>
              <thead style={{ backgroundColor: "#070e1d", borderBottom: "1px solid #424754" }}>
                <tr>
                  {["ID", "Finding", "Severity", "Confidence", "Detected By", "Function", "Lines", "Status", "Actions"].map((h) => (
                    <th key={h} className="px-4 py-3 font-label-caps text-label-caps text-on-surface-variant">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {filtered.map((row) => (
                  <tr
                    key={row.id}
                    onClick={() => setSelected(row.id)}
                    className="cursor-pointer transition-colors"
                    style={{
                      borderTop: "1px solid #424754",
                      backgroundColor: selected === row.id ? "#232a3a" : undefined,
                    }}
                  >
                    <td className="px-4 py-3 font-code-sm text-code-sm text-on-surface-variant">{row.id}</td>
                    <td className="px-4 py-3 font-body-sm font-bold text-on-surface max-w-xs truncate">{row.name}</td>
                    <td className="px-4 py-3">
                      <span className="px-2 py-0.5 rounded font-label-caps" style={{ fontSize: "10px", ...sevColors[row.severity] }}>
                        {row.severity}
                      </span>
                    </td>
                    <td className="px-4 py-3 font-code-sm text-code-sm text-on-surface">{row.confidence}</td>
                    <td className="px-4 py-3">
                      <div className="flex -space-x-1">
                        {row.detectedBy.map((d) => (
                          <div key={d} className="w-5 h-5 rounded-full flex items-center justify-center font-bold"
                            style={{ fontSize: "8px", ...detectorColors[d], border: "2px solid #0c1322" }}>
                            {d}
                          </div>
                        ))}
                      </div>
                    </td>
                    <td className="px-4 py-3 font-code-sm text-code-sm text-on-surface">{row.fn}</td>
                    <td className="px-4 py-3 font-code-sm text-code-sm text-on-surface">{row.lines}</td>
                    <td className="px-4 py-3">
                      <span className="font-label-caps" style={{ fontSize: "11px", color: statusColors[row.status] }}>
                        {row.status}
                      </span>
                    </td>
                    <td className="px-4 py-3">
                      <div className="flex gap-2">
                        <button className="font-label-caps text-label-caps hover:underline" style={{ color: "#adc6ff", fontSize: "10px" }}>
                          VIEW
                        </button>
                        <button className="font-label-caps text-label-caps hover:underline" style={{ color: "#4cd7f6", fontSize: "10px" }}>
                          FIX
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        {/* Detail pane */}
        {detail && (
          <div className="col-span-12 xl:col-span-4">
            <div className="p-5 rounded-lg space-y-4 sticky top-0" style={{ backgroundColor: "#141b2b", border: "1px solid #424754" }}>
              <div className="flex justify-between items-start">
                <span className="font-code-sm text-code-sm text-on-surface-variant">{detail.id}</span>
                <span className="px-2 py-0.5 rounded font-label-caps" style={{ fontSize: "10px", ...sevColors[detail.severity] }}>
                  {detail.severity}
                </span>
              </div>
              <h2 className="font-headline-sm text-headline-sm text-on-surface">{detail.name}</h2>
              <p className="font-body-sm text-body-sm text-on-surface-variant leading-relaxed">{detail.description}</p>

              <div className="space-y-2">
                {[
                  { k: "File",        v: detail.file },
                  { k: "Function",    v: detail.fn },
                  { k: "Lines",       v: detail.lines },
                  { k: "Confidence",  v: detail.confidence },
                ].map(({ k, v }) => (
                  <div key={k} className="flex justify-between py-1" style={{ borderBottom: "1px solid #424754" }}>
                    <span className="font-label-caps text-label-caps text-on-surface-variant">{k}</span>
                    <span className="font-code-sm text-code-sm text-on-surface">{v}</span>
                  </div>
                ))}
              </div>

              <div className="flex gap-2 pt-2">
                <button
                  className="flex-1 py-2 rounded font-label-caps text-label-caps transition-all active:scale-95"
                  style={{ backgroundColor: "#adc6ff", color: "#002e6a" }}
                >
                  Generate Fix
                </button>
                <button
                  className="flex-1 py-2 rounded font-label-caps text-label-caps transition-colors"
                  style={{ border: "1px solid #424754", color: "#c2c6d6" }}
                >
                  View Trace
                </button>
              </div>
              <button
                className="w-full py-2 rounded font-label-caps text-label-caps transition-colors"
                style={{ backgroundColor: "rgba(255,180,171,0.1)", color: "#ffb4ab", border: "1px solid rgba(255,180,171,0.2)" }}
              >
                Mark False Positive
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
