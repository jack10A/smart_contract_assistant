"use client";
import { useState } from "react";

const functions = [
  { name: "withdraw(uint256)",              vis: "Public",   payable: false, risk: "Critical", aiConf: "98.2%", aiClass: "Reentrancy",         slither: true,  lines: "44-51",  calls: ["msg.sender.call"], mods: [] },
  { name: "executeDelegate(address,bytes)", vis: "Public",   payable: false, risk: "Critical", aiConf: "94.1%", aiClass: "Dangerous Delegatecall", slither: true,  lines: "54-57",  calls: ["target.delegatecall"], mods: [] },
  { name: "emergencyExit()",               vis: "Public",   payable: false, risk: "High",     aiConf: "91.0%", aiClass: "Access Control",      slither: true,  lines: "821-825", calls: ["payable.transfer"],   mods: [] },
  { name: "addLiquidity(uint256,uint256)", vis: "Public",   payable: true,  risk: "High",     aiConf: "85.4%", aiClass: "Integer Overflow",    slither: false, lines: "44",     calls: [],                    mods: [] },
  { name: "claimReward()",                 vis: "Public",   payable: false, risk: "Medium",   aiConf: "72.0%", aiClass: "Unchecked Math",      slither: false, lines: "200-210", calls: [],                    mods: ["onlyStaker"] },
  { name: "lottery()",                     vis: "Public",   payable: false, risk: "Medium",   aiConf: "76.8%", aiClass: "Weak PRNG",           slither: false, lines: "440-446", calls: [],                    mods: [] },
  { name: "initialize(address)",           vis: "Public",   payable: false, risk: "Medium",   aiConf: "60.0%", aiClass: "Missing Zero Address", slither: true,  lines: "20-28",  calls: [],                    mods: [] },
  { name: "transfer(address,uint256)",     vis: "Public",   payable: false, risk: "Low",      aiConf: "55.0%", aiClass: "Unchecked Return",    slither: true,  lines: "196-202", calls: ["token.transfer"],     mods: [] },
  { name: "owner()",                       vis: "View",     payable: false, risk: "Safe",     aiConf: "—",     aiClass: "—",                   slither: false, lines: "15",     calls: [],                    mods: [] },
  { name: "balances(address)",             vis: "View",     payable: false, risk: "Safe",     aiConf: "—",     aiClass: "—",                   slither: false, lines: "18",     calls: [],                    mods: [] },
  { name: "totalSupply()",                 vis: "View",     payable: false, risk: "Safe",     aiConf: "—",     aiClass: "—",                   slither: false, lines: "21",     calls: [],                    mods: [] },
  { name: "setOwner(address)",             vis: "Internal", payable: false, risk: "Low",      aiConf: "48.0%", aiClass: "Access Scope",        slither: false, lines: "30-33",  calls: [],                    mods: ["onlyOwner"] },
];

const riskColors: Record<string, { bg: string; text: string }> = {
  Critical: { bg: "rgba(255,180,171,0.15)", text: "#ffb4ab" },
  High:     { bg: "rgba(223,116,18,0.15)",  text: "#ffb786" },
  Medium:   { bg: "rgba(76,215,246,0.1)",   text: "#4cd7f6" },
  Low:      { bg: "rgba(173,198,255,0.1)",  text: "#adc6ff" },
  Safe:     { bg: "#2e3545",               text: "#8c909f" },
};
const visColors: Record<string, { bg: string; text: string }> = {
  Public:   { bg: "rgba(77,142,255,0.2)",  text: "#4d8eff" },
  View:     { bg: "rgba(3,181,211,0.15)",  text: "#03b5d3" },
  Internal: { bg: "#2e3545",              text: "#c2c6d6" },
  Private:  { bg: "#2e3545",              text: "#8c909f" },
};

export default function FunctionAnalysisPage() {
  const [selected, setSelected] = useState<string | null>("withdraw(uint256)");
  const detail = functions.find((f) => f.name === selected);

  return (
    <div className="p-6 space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="font-headline-md text-headline-md text-on-surface">Function Analysis</h1>
          <p className="font-body-sm text-body-sm text-on-surface-variant mt-1">
            {functions.length} functions · {functions.filter((f) => f.risk !== "Safe").length} risky
          </p>
        </div>
        <div className="flex gap-2">
          {[
            { label: "Critical", color: "#ffb4ab" },
            { label: "High", color: "#ffb786" },
            { label: "Safe", color: "#8c909f" },
          ].map(({ label, color }) => (
            <div key={label} className="flex items-center gap-1">
              <div className="w-2 h-2 rounded-full" style={{ backgroundColor: color }} />
              <span className="font-label-caps" style={{ fontSize: "10px", color: "#c2c6d6" }}>
                {label} ({functions.filter((f) => f.risk === label).length})
              </span>
            </div>
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
                  {["Function", "Visibility", "Payable", "Risk", "AI Confidence", "AI Class", "Slither", "Lines"].map((h) => (
                    <th key={h} className="px-4 py-3 font-label-caps text-label-caps text-on-surface-variant">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {functions.map((fn) => (
                  <tr
                    key={fn.name}
                    onClick={() => setSelected(fn.name)}
                    className="cursor-pointer transition-colors"
                    style={{
                      borderTop: "1px solid #424754",
                      backgroundColor: selected === fn.name ? "#232a3a" : undefined,
                    }}
                  >
                    <td className="px-4 py-3 font-code-sm text-code-sm text-on-surface">{fn.name}</td>
                    <td className="px-4 py-3">
                      <span className="px-2 py-0.5 rounded font-label-caps" style={{ fontSize: "10px", ...visColors[fn.vis] }}>
                        {fn.vis}
                      </span>
                    </td>
                    <td className="px-4 py-3">
                      {fn.payable ? (
                        <span className="font-label-caps" style={{ fontSize: "10px", color: "#ffb786" }}>PAYABLE</span>
                      ) : (
                        <span style={{ color: "#424754", fontSize: "10px" }}>—</span>
                      )}
                    </td>
                    <td className="px-4 py-3">
                      <span className="px-2 py-0.5 rounded font-label-caps" style={{ fontSize: "10px", ...riskColors[fn.risk] }}>
                        {fn.risk}
                      </span>
                    </td>
                    <td className="px-4 py-3 font-code-sm text-code-sm text-on-surface">{fn.aiConf}</td>
                    <td className="px-4 py-3 font-body-sm text-body-sm text-on-surface-variant">{fn.aiClass}</td>
                    <td className="px-4 py-3">
                      {fn.slither ? (
                        <span className="material-symbols-outlined" style={{ fontSize: "16px", color: "#ffb786" }}>warning</span>
                      ) : (
                        <span className="material-symbols-outlined" style={{ fontSize: "16px", color: "#4cd7f6" }}>check_circle</span>
                      )}
                    </td>
                    <td className="px-4 py-3 font-code-sm text-code-sm text-on-surface-variant">{fn.lines}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        {/* Detail pane */}
        {detail && (
          <div className="col-span-12 xl:col-span-4">
            <div
              className="p-5 rounded-lg sticky top-0 space-y-4"
              style={{ backgroundColor: "#141b2b", border: "1px solid #424754" }}
            >
              <h3 className="font-headline-sm text-headline-sm text-on-surface">{detail.name}</h3>

              {/* Risk badge */}
              <div
                className="p-3 rounded-lg flex items-center gap-3"
                style={{ ...riskColors[detail.risk], border: `1px solid ${riskColors[detail.risk].text}30` }}
              >
                <span className="material-symbols-outlined" style={{ fontSize: "24px", color: riskColors[detail.risk].text }}>
                  {detail.risk === "Critical" || detail.risk === "High" ? "warning" : "info"}
                </span>
                <div>
                  <p className="font-label-caps text-label-caps" style={{ color: riskColors[detail.risk].text }}>{detail.risk}</p>
                  <p className="font-body-sm text-body-sm text-on-surface-variant">{detail.aiClass}</p>
                </div>
              </div>

              <div className="space-y-2">
                {[
                  { k: "Visibility",  v: detail.vis },
                  { k: "Payable",     v: detail.payable ? "Yes" : "No" },
                  { k: "Lines",       v: detail.lines },
                  { k: "AI Conf.",    v: detail.aiConf },
                  { k: "Slither Hit", v: detail.slither ? "Yes" : "No" },
                ].map(({ k, v }) => (
                  <div key={k} className="flex justify-between py-1.5" style={{ borderBottom: "1px solid #424754" }}>
                    <span className="font-label-caps text-label-caps text-on-surface-variant">{k}</span>
                    <span className="font-code-sm text-code-sm text-on-surface">{v}</span>
                  </div>
                ))}
              </div>

              {detail.calls.length > 0 && (
                <div>
                  <p className="font-label-caps text-label-caps text-on-surface-variant mb-2" style={{ fontSize: "10px" }}>
                    EXTERNAL CALLS
                  </p>
                  <div className="space-y-1">
                    {detail.calls.map((c) => (
                      <div key={c} className="font-code-sm text-code-sm px-2 py-1 rounded" style={{ backgroundColor: "rgba(255,180,171,0.08)", color: "#ffb4ab" }}>
                        {c}
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {detail.mods.length > 0 && (
                <div>
                  <p className="font-label-caps text-label-caps text-on-surface-variant mb-2" style={{ fontSize: "10px" }}>
                    MODIFIERS
                  </p>
                  <div className="flex gap-1 flex-wrap">
                    {detail.mods.map((m) => (
                      <span key={m} className="font-code-sm text-code-sm px-2 py-0.5 rounded" style={{ backgroundColor: "#191f2f", color: "#4cd7f6", border: "1px solid #424754" }}>
                        {m}
                      </span>
                    ))}
                  </div>
                </div>
              )}

              <div className="flex gap-2 pt-2">
                <button
                  className="flex-1 py-2 rounded font-label-caps text-label-caps transition-all active:scale-95"
                  style={{ backgroundColor: "#adc6ff", color: "#002e6a" }}
                >
                  Audit This Fn
                </button>
                <button
                  className="flex-1 py-2 rounded font-label-caps text-label-caps transition-colors"
                  style={{ border: "1px solid #424754", color: "#c2c6d6" }}
                >
                  View Code
                </button>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
