"use client";
import { useState } from "react";

const diffLines = [
  { ln: 18, code: "// Withdraw tokens from the vault",              type: "ctx" },
  { ln: 19, code: "function withdraw(uint256 _amount) public {",    type: "ctx" },
  { ln: "20-", code: 'require(balances[msg.sender] >= _amount);',  type: "del" },
  { ln: "20+", code: 'require(balances[msg.sender] >= _amount, "Insufficient balance");', type: "add" },
  { ln: "21-", code: '(bool success, ) = msg.sender.call{value: _amount}("");', type: "del" },
  { ln: "22-", code: "require(success);",                           type: "del" },
  { ln: "23-", code: "balances[msg.sender] -= _amount;",            type: "del" },
  { ln: "21+", code: "balances[msg.sender] -= _amount;",            type: "add" },
  { ln: "22+", code: '(bool success, ) = msg.sender.call{value: _amount}("");', type: "add" },
  { ln: "23+", code: 'require(success, "Transfer failed");',        type: "add" },
  { ln: 24,   code: "}",                                            type: "ctx" },
  { ln: 25,   code: "",                                             type: "ctx" },
];

const fixedFindings = [
  { id: "ID-001", label: "REENTRANCY",       color: "#ffb4ab", bg: "#93000a" },
  { id: "ID-014", label: "UNCHECKED CALL",   color: "#ffb4ab", bg: "#93000a" },
  { id: "ID-042", label: "OVERFLOW",         color: "#4cd7f6", bg: "rgba(3,181,211,0.2)" },
];

export default function FixGeneratorPage() {
  const [generating, setGenerating] = useState(false);
  const [generated, setGenerated] = useState(true);

  return (
    <div className="overflow-y-auto" style={{ height: "100%" }}>
      <div className="p-6 space-y-6 max-w-screen-xl mx-auto">
        {/* Top summary */}
        <div className="grid grid-cols-1 lg:grid-cols-4 gap-4">
          <div
            className="lg:col-span-3 p-4 rounded-lg flex items-center justify-between"
            style={{ backgroundColor: "#191f2f", border: "1px solid #424754" }}
          >
            <div className="flex items-center gap-4">
              <div
                className="w-10 h-10 flex items-center justify-center rounded"
                style={{ backgroundColor: "rgba(77,142,255,0.2)", color: "#4d8eff" }}
              >
                <span className="material-symbols-outlined" style={{ fontSize: "20px" }}>auto_fix</span>
              </div>
              <div>
                <h2 className="font-headline-sm text-headline-sm text-on-surface">
                  Fix Generation:{" "}
                  <span style={{ color: "#adc6ff" }}>hybrid_vulnerable_test.sol</span>
                </h2>
                <p className="font-body-sm text-body-sm text-on-surface-variant">
                  Active Patch Workflow: Reentrancy and Integer Overflow Mitigation
                </p>
              </div>
            </div>
            <button
              onClick={() => { setGenerating(true); setTimeout(() => setGenerating(false), 2000); }}
              className="px-6 py-2 rounded font-label-caps text-label-caps font-bold active:scale-95 transition-all shadow-lg"
              style={{ backgroundColor: "#adc6ff", color: "#002e6a" }}
            >
              {generating ? "GENERATING…" : "GENERATE FIX"}
            </button>
          </div>

          {/* Validation result */}
          <div
            className="p-4 rounded-lg"
            style={{ backgroundColor: "#191f2f", border: "2px solid rgba(223,116,18,0.5)" }}
          >
            <div className="flex justify-between items-start mb-2">
              <span className="font-label-caps text-label-caps" style={{ color: "#ffb786" }}>VALIDATION RESULT</span>
              <span
                className="font-label-caps px-2 py-0.5 rounded"
                style={{ fontSize: "10px", backgroundColor: "rgba(223,116,18,0.2)", color: "#ffb786" }}
              >
                IN PROGRESS
              </span>
            </div>
            <div className="flex items-center gap-3">
              <span className="material-symbols-outlined" style={{ fontSize: "24px", color: "#ffb786" }}>warning</span>
              <h3 className="font-headline-sm text-headline-sm text-on-surface">Needs another pass</h3>
            </div>
            <div className="mt-4 grid grid-cols-2 gap-2">
              <div className="p-2 rounded text-center" style={{ backgroundColor: "#232a3a" }}>
                <p className="font-label-caps text-on-surface-variant" style={{ fontSize: "10px" }}>REMAINING</p>
                <p className="font-headline-md text-headline-md" style={{ color: "#ffb786" }}>2</p>
                <p style={{ fontSize: "10px", color: "#c2c6d6" }}>Medium Findings</p>
              </div>
              <div className="p-2 rounded text-center" style={{ backgroundColor: "#232a3a" }}>
                <p className="font-label-caps text-on-surface-variant" style={{ fontSize: "10px" }}>SLITHER</p>
                <span className="material-symbols-outlined mt-1" style={{ color: "#4cd7f6", fontSize: "20px" }}>sync</span>
                <p style={{ fontSize: "10px", color: "#4cd7f6" }}>Re-auditing…</p>
              </div>
            </div>
          </div>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
          {/* Diff viewer */}
          <div
            className="lg:col-span-2 rounded-lg flex flex-col overflow-hidden"
            style={{ backgroundColor: "#03060b", border: "1px solid #424754", height: "600px" }}
          >
            {/* Diff header */}
            <div
              className="p-3 flex justify-between items-center"
              style={{ backgroundColor: "#191f2f", borderBottom: "1px solid #424754" }}
            >
              <div className="flex items-center gap-2">
                <span className="material-symbols-outlined text-on-surface-variant" style={{ fontSize: "16px" }}>code</span>
                <span className="font-label-caps text-label-caps text-on-surface-variant">BEFORE/AFTER DIFF VIEWER</span>
              </div>
              <div className="flex gap-4">
                <div className="flex items-center gap-1.5">
                  <div className="w-3 h-3" style={{ backgroundColor: "rgba(147,0,10,0.4)", border: "1px solid #ffb4ab" }} />
                  <span className="font-label-caps text-on-surface-variant" style={{ fontSize: "10px" }}>VULNERABLE</span>
                </div>
                <div className="flex items-center gap-1.5">
                  <div className="w-3 h-3" style={{ backgroundColor: "rgba(3,181,211,0.3)", border: "1px solid #4cd7f6" }} />
                  <span className="font-label-caps text-on-surface-variant" style={{ fontSize: "10px" }}>FIXED</span>
                </div>
              </div>
            </div>

            {/* Diff lines */}
            <div className="flex-1 overflow-auto p-4 font-code-base text-code-base leading-relaxed">
              {diffLines.map((line, i) => (
                <div
                  key={i}
                  className={line.type === "del" ? "code-diff-deleted" : line.type === "add" ? "code-diff-added" : ""}
                  style={{ display: "flex", width: "100%", padding: "1px 0", opacity: line.type === "ctx" ? 0.4 : 1 }}
                >
                  <span
                    className="w-8 shrink-0 select-none pr-2"
                    style={{ color: "#424754", textAlign: "right" }}
                  >
                    {typeof line.ln === "string" ? line.ln : line.ln}
                  </span>
                  <span
                    style={{
                      color: line.type === "del" ? "#ffb4ab" : line.type === "add" ? "#4cd7f6" : "#dce2f7",
                      whiteSpace: "pre",
                    }}
                  >
                    {line.code}
                  </span>
                </div>
              ))}
            </div>

            {/* Diff footer */}
            <div
              className="p-3 flex justify-end gap-3"
              style={{ backgroundColor: "#232a3a", borderTop: "1px solid #424754" }}
            >
              <button
                className="flex items-center gap-2 px-3 py-1.5 rounded font-label-caps text-label-caps transition-colors hover:bg-surface-container-highest"
                style={{ backgroundColor: "#191f2f", border: "1px solid #424754", color: "#c2c6d6" }}
              >
                <span className="material-symbols-outlined" style={{ fontSize: "14px" }}>download</span>
                DOWNLOAD CONTRACT
              </button>
              <button
                className="flex items-center gap-2 px-3 py-1.5 rounded font-label-caps text-label-caps transition-colors hover:bg-surface-container-highest"
                style={{ backgroundColor: "#191f2f", border: "1px solid #424754", color: "#c2c6d6" }}
              >
                <span className="material-symbols-outlined" style={{ fontSize: "14px" }}>description</span>
                EXPORT REPORT
              </button>
            </div>
          </div>

          {/* Right panel */}
          <div className="flex flex-col gap-4">
            {/* Fix explanation */}
            <div
              className="flex-1 p-5 rounded-lg"
              style={{ backgroundColor: "#191f2f", border: "1px solid #424754" }}
            >
              <h3 className="font-headline-sm text-headline-sm text-on-surface mb-4" style={{ color: "#adc6ff" }}>
                Fix Explanation
              </h3>

              <div className="space-y-5">
                <div>
                  <h4 className="font-label-caps text-label-caps text-on-surface-variant mb-3" style={{ letterSpacing: "0.08em" }}>
                    CHANGES IMPLEMENTED
                  </h4>
                  <ul className="space-y-3">
                    {[
                      "Moved state update balances[msg.sender] -= _amount before the external call.",
                      "Added descriptive revert messages to require statements for better debugability.",
                      "Implemented Checks-Effects-Interactions pattern globally for the withdraw module.",
                    ].map((item, i) => (
                      <li key={i} className="flex gap-3">
                        <span className="material-symbols-outlined shrink-0" style={{ fontSize: "16px", color: "#4cd7f6" }}>check_circle</span>
                        <p className="font-body-sm text-body-sm text-on-surface-variant">{item}</p>
                      </li>
                    ))}
                  </ul>
                </div>

                <div>
                  <h4 className="font-label-caps text-label-caps text-on-surface-variant mb-2" style={{ letterSpacing: "0.08em" }}>
                    RISK REDUCTION
                  </h4>
                  <p className="font-body-sm text-body-sm text-on-surface-variant leading-relaxed mb-3">
                    By adopting the CEI pattern, the contract is now immune to cross-function reentrancy attacks where a
                    malicious contract could drain funds by re-entering withdraw before the balance is zeroed.
                  </p>
                  <div
                    className="p-3"
                    style={{ borderLeft: "2px solid #4cd7f6", backgroundColor: "rgba(3,181,211,0.05)" }}
                  >
                    <div className="flex justify-between items-center mb-1">
                      <span className="font-label-caps text-on-surface-variant" style={{ fontSize: "10px" }}>ATTACK REPLAY MITIGATION</span>
                      <span className="font-label-caps" style={{ fontSize: "10px", color: "#4cd7f6", fontWeight: 700 }}>100% COVERED</span>
                    </div>
                    <p style={{ fontSize: "11px", color: "#c2c6d6" }}>
                      Mitigates identified path:{" "}
                      <code
                        className="px-1 rounded"
                        style={{ fontSize: "10px", backgroundColor: "#232a3a", color: "#adc6ff" }}
                      >
                        TX_0x4a…9b → Reentry → Balance Drain
                      </code>
                    </p>
                  </div>
                </div>

                <div>
                  <h4 className="font-label-caps text-label-caps text-on-surface-variant mb-2" style={{ letterSpacing: "0.08em" }}>
                    ADDRESSED FINDINGS
                  </h4>
                  <div className="flex flex-wrap gap-2">
                    {fixedFindings.map((f) => (
                      <span
                        key={f.id}
                        className="font-label-caps px-2 py-1 rounded"
                        style={{ fontSize: "10px", backgroundColor: f.bg, color: f.color }}
                      >
                        {f.id}: {f.label}
                      </span>
                    ))}
                  </div>
                </div>
              </div>
            </div>

            {/* AI suggestion card */}
            <div
              className="p-4 rounded-lg relative overflow-hidden group"
              style={{ backgroundColor: "#232a3a", border: "1px solid rgba(173,198,255,0.2)" }}
            >
              <div className="relative z-10">
                <div className="flex items-center gap-2 mb-2">
                  <span className="material-symbols-outlined" style={{ color: "#adc6ff" }}>auto_awesome</span>
                  <span className="font-label-caps text-label-caps" style={{ color: "#adc6ff" }}>SENTINEL AI SUGGESTION</span>
                </div>
                <p className="font-body-sm text-body-sm text-on-surface-variant leading-relaxed">
                  &ldquo;I detected two remaining Medium findings related to GAS OPTIMIZATION. Would you like me to refactor
                  the loops in the{" "}
                  <code className="font-code-sm px-1" style={{ color: "#adc6ff" }}>distributeRewards</code> function next?&rdquo;
                </p>
                <button
                  className="mt-3 w-full py-2 rounded font-label-caps text-label-caps transition-all hover:bg-primary"
                  style={{ backgroundColor: "#191f2f", border: "1px solid rgba(173,198,255,0.4)", color: "#adc6ff" }}
                >
                  OPTIMIZE GAS NOW
                </button>
              </div>
              <div className="absolute top-0 right-0 p-4 opacity-10 group-hover:opacity-20 transition-opacity">
                <span className="material-symbols-outlined" style={{ fontSize: "64px", color: "#adc6ff" }}>rocket_launch</span>
              </div>
            </div>
          </div>
        </div>

        {/* Footer */}
        <div className="flex items-center justify-between py-6" style={{ borderTop: "1px solid #424754" }}>
          <div className="flex items-center gap-4">
            <span className="font-label-caps text-label-caps text-on-surface-variant">VERSION HISTORY:</span>
            <div className="flex -space-x-2">
              {[
                { label: "v1",   active: false, title: "v1.0.0" },
                { label: "v1.1", active: true,  title: "Current: v1.1.0" },
              ].map(({ label, active, title }) => (
                <div
                  key={label}
                  className="w-8 h-8 rounded-full flex items-center justify-center font-bold cursor-pointer"
                  style={{
                    fontSize: "10px",
                    backgroundColor: active ? "#4d8eff" : "#2e3545",
                    color: active ? "#00285d" : "#c2c6d6",
                    border: "2px solid #0c1322",
                  }}
                  title={title}
                >
                  {label}
                </div>
              ))}
            </div>
          </div>
          <div className="flex gap-3">
            <button
              className="flex items-center gap-2 px-6 py-2 rounded font-label-caps text-label-caps transition-colors hover:bg-surface-container-high"
              style={{ border: "1px solid #424754", color: "#c2c6d6" }}
            >
              <span className="material-symbols-outlined" style={{ fontSize: "16px" }}>close</span>
              DISCARD CHANGES
            </button>
            <button
              className="flex items-center gap-2 px-8 py-2 rounded font-label-caps text-label-caps font-bold transition-all active:scale-95"
              style={{ backgroundColor: "#4d8eff", color: "#00285d" }}
            >
              <span className="material-symbols-outlined" style={{ fontSize: "16px" }}>verified_user</span>
              COMMIT &amp; VALIDATE
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
