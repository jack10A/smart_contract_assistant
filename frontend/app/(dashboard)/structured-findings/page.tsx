"use client";

const findings = [
  {
    id: "SF-001",
    title: "Dangerous Delegatecall",
    severity: "CRITICAL",
    borderColor: "#ffb4ab",
    tag: "CONFIRMED",
    tagBg: "rgba(255,180,171,0.1)",
    tagColor: "#ffb4ab",
    tagBorder: "rgba(255,180,171,0.3)",
    fn: "executeDelegate(address, bytes)",
    lines: "55",
    description: "External contract can hijack storage slot 0 through delegatecall in upgrade function. An attacker supplying a malicious implementation address gains full write access to the proxy's storage, enabling ownership takeover.",
    impact: "Complete protocol compromise. All user funds at risk.",
    recommendation: "Restrict delegatecall targets to a trusted whitelist or registry. Add onlyOwner or onlyProxy modifier.",
    references: ["SWC-112", "EIP-1967"],
  },
  {
    id: "SF-002",
    title: "Reentrancy (State After Call)",
    severity: "CRITICAL",
    borderColor: "#ffb4ab",
    tag: "CONFIRMED",
    tagBg: "rgba(255,180,171,0.1)",
    tagColor: "#ffb4ab",
    tagBorder: "rgba(255,180,171,0.3)",
    fn: "withdrawBalances()",
    lines: "112-118",
    description: "State update occurs after external call. Classic CEI violation allows recursive re-entry through fallback().",
    impact: "Total ETH drain from contract.",
    recommendation: "Apply nonReentrant modifier (OpenZeppelin ReentrancyGuard) or move balance update before external call.",
    references: ["SWC-107"],
  },
  {
    id: "SF-003",
    title: "Unprotected Ether Withdrawal",
    severity: "HIGH",
    borderColor: "#ffb786",
    tag: "SLITHER_HIGH",
    tagBg: "rgba(255,183,134,0.1)",
    tagColor: "#ffb786",
    tagBorder: "rgba(255,183,134,0.3)",
    fn: "emergencyExit()",
    lines: "821-825",
    description: "emergencyExit() lacks access control. Any EOA can call it to drain the vault.",
    impact: "Protocol-level ETH drain without authorization.",
    recommendation: "Add onlyOwner or onlyAdmin modifier.",
    references: ["SWC-105"],
  },
  {
    id: "SF-004",
    title: "Timestamp Dependency (Weak PRNG)",
    severity: "MEDIUM",
    borderColor: "#4cd7f6",
    tag: "AI_MEDIUM",
    tagBg: "rgba(76,215,246,0.08)",
    tagColor: "#4cd7f6",
    tagBorder: "rgba(76,215,246,0.2)",
    fn: "lottery()",
    lines: "442",
    description: "Usage of block.timestamp as entropy source. Miners can influence within ±15 seconds.",
    impact: "Predictable randomness; lottery outcomes can be gamed.",
    recommendation: "Use Chainlink VRF or commit-reveal scheme for secure randomness.",
    references: ["SWC-116"],
  },
];

export default function StructuredFindingsPage() {
  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="font-headline-md text-headline-md text-on-surface">Structured Findings</h1>
          <p className="font-body-sm text-body-sm text-on-surface-variant mt-1">
            Analyst-grade write-ups for {findings.length} findings
          </p>
        </div>
        <div className="flex gap-2">
          <button
            className="flex items-center gap-2 px-4 py-2 rounded font-label-caps text-label-caps transition-all active:scale-95"
            style={{ backgroundColor: "#adc6ff", color: "#002e6a" }}
          >
            <span className="material-symbols-outlined" style={{ fontSize: "16px" }}>download</span>
            Export All
          </button>
        </div>
      </div>

      <div className="space-y-4">
        {findings.map((f) => (
          <div
            key={f.id}
            className="p-5 rounded-lg"
            style={{ backgroundColor: "#141b2b", border: "1px solid #424754", borderLeft: `4px solid ${f.borderColor}` }}
          >
            {/* Header */}
            <div className="flex items-start justify-between mb-3">
              <div className="flex items-center gap-3">
                <span className="font-code-sm text-code-sm text-on-surface-variant">{f.id}</span>
                <h3 className="font-headline-sm text-headline-sm" style={{ color: f.borderColor }}>{f.title}</h3>
              </div>
              <div className="flex items-center gap-2 shrink-0">
                <span
                  className="font-label-caps px-2 py-0.5 rounded"
                  style={{ fontSize: "10px", backgroundColor: f.tagBg, color: f.tagColor, border: `1px solid ${f.tagBorder}` }}
                >
                  {f.tag}
                </span>
                <span
                  className="font-label-caps px-2 py-0.5 rounded"
                  style={{
                    fontSize: "10px",
                    backgroundColor: f.severity === "CRITICAL" ? "#93000a" : "rgba(223,116,18,0.2)",
                    color: f.borderColor,
                  }}
                >
                  {f.severity}
                </span>
              </div>
            </div>

            {/* Meta */}
            <div className="flex gap-4 mb-4" style={{ borderBottom: "1px solid #424754", paddingBottom: "12px" }}>
              <div className="flex items-center gap-1">
                <span className="material-symbols-outlined text-on-surface-variant" style={{ fontSize: "14px" }}>functions</span>
                <span className="font-code-sm text-code-sm text-on-surface">{f.fn}</span>
              </div>
              <div className="flex items-center gap-1">
                <span className="material-symbols-outlined text-on-surface-variant" style={{ fontSize: "14px" }}>code</span>
                <span className="font-code-sm text-code-sm text-on-surface">Line {f.lines}</span>
              </div>
            </div>

            {/* Body */}
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              <div>
                <p className="font-label-caps text-label-caps text-on-surface-variant mb-2" style={{ fontSize: "10px" }}>DESCRIPTION</p>
                <p className="font-body-sm text-body-sm text-on-surface-variant leading-relaxed">{f.description}</p>
              </div>
              <div>
                <p className="font-label-caps text-label-caps text-on-surface-variant mb-2" style={{ fontSize: "10px" }}>IMPACT</p>
                <p className="font-body-sm text-body-sm leading-relaxed" style={{ color: f.borderColor }}>{f.impact}</p>
              </div>
              <div>
                <p className="font-label-caps text-label-caps text-on-surface-variant mb-2" style={{ fontSize: "10px" }}>RECOMMENDATION</p>
                <p className="font-body-sm text-body-sm text-on-surface-variant leading-relaxed">{f.recommendation}</p>
              </div>
            </div>

            {/* References + actions */}
            <div className="flex items-center justify-between mt-4 pt-3" style={{ borderTop: "1px solid #424754" }}>
              <div className="flex gap-2">
                {f.references.map((r) => (
                  <span
                    key={r}
                    className="font-code-sm text-code-sm px-2 py-0.5 rounded"
                    style={{ backgroundColor: "#191f2f", color: "#adc6ff", border: "1px solid #424754" }}
                  >
                    {r}
                  </span>
                ))}
              </div>
              <div className="flex gap-2">
                <button
                  className="px-3 py-1.5 rounded font-label-caps text-label-caps transition-colors hover:bg-surface-container-highest"
                  style={{ border: "1px solid #424754", color: "#c2c6d6", fontSize: "10px" }}
                >
                  View Code
                </button>
                <button
                  className="px-3 py-1.5 rounded font-label-caps text-label-caps transition-all active:scale-95"
                  style={{ backgroundColor: "#adc6ff", color: "#002e6a", fontSize: "10px" }}
                >
                  Generate Fix
                </button>
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
