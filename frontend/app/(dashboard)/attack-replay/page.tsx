"use client";
import { useState } from "react";
import { useSession } from "../../context/SessionContext";

type ReplayCard = {
  index?: number;
  title?: string;
  finding_id?: string;
  finding?: string;
  severity?: string;
  confidence?: number;
  file?: string | null;
  attacker_goal?: string;
  preconditions?: string[];
  steps?: string[];
  evidence?: { source?: string; file?: string | null; line?: number | null; summary?: string }[];
  impact?: string;
  fix?: string;
};

const severityColor = (severity?: string) => {
  const lower = (severity ?? "").toLowerCase();
  if (lower.includes("critical") || lower.includes("high")) return "#ffb4ab";
  if (lower.includes("medium")) return "#ffb786";
  return "#4cd7f6";
};

const stepIcon = (index: number) => ["login", "call_made", "sync_problem", "repeat", "flag"][index] ?? "radio_button_checked";

const parseLineEvidence = (lineMap?: string) => {
  if (!lineMap) return [] as NonNullable<ReplayCard["evidence"]>;
  const matches = [...lineMap.matchAll(/\*\*Line\s+(\d+):\s+([^*]+)\*\*\s*```solidity\n([\s\S]*?)\n```/g)];
  return matches.slice(0, 8).map((match) => ({
    source: "source_line",
    line: Number(match[1]),
    summary: `${match[2].trim()}: ${match[3].trim()}`,
  }));
};

const auditReplayCards = (session: ReturnType<typeof useSession>): ReplayCard[] => {
  const audit = session.auditResult;
  if (!audit) return [];

  const label = audit.prediction?.label ?? "Security Finding";
  const lower = `${label} ${audit.audit_text} ${audit.line_map}`.toLowerCase();
  const severity = audit.risk_text.match(/Risk level:\*\*\s+\*\*([^*]+)\*\*/i)?.[1] ?? audit.prediction?.risk ?? "Medium";
  const confidence = audit.prediction?.confidence ?? 0;
  const evidence = parseLineEvidence(audit.line_map).map((item) => ({ ...item, file: audit.filename }));

  if (lower.includes("reentrancy")) {
    return [{
      index: 1,
      title: "Reentrancy Drain Path",
      finding_id: "audit-reentrancy",
      finding: `Reentrancy risk in ${audit.filename}`,
      severity,
      confidence,
      file: audit.filename,
      attacker_goal: "Withdraw the same balance more than once before accounting is finalized.",
      steps: [
        "Attacker deposits enough ETH to create a withdrawable balance.",
        "Attacker calls the vulnerable withdrawal function.",
        "The contract sends value to the attacker through an external call.",
        "The attacker's receive or fallback function re-enters withdrawal before protection completes.",
        "The loop repeats until the contract balance, gas, or a guard stops execution.",
      ],
      evidence,
      impact: "Contract funds can be drained or user balances can become inconsistent.",
      fix: "Apply Checks-Effects-Interactions, update balances before external calls, and add a reentrancy guard.",
    }];
  }

  if (lower.includes("delegatecall")) {
    return [{
      index: 1,
      title: "Delegatecall Takeover Path",
      finding_id: "audit-delegatecall",
      finding: `Dangerous delegatecall risk in ${audit.filename}`,
      severity,
      confidence,
      file: audit.filename,
      attacker_goal: "Execute attacker-controlled code inside the victim contract storage context.",
      steps: [
        "Attacker deploys a malicious implementation contract.",
        "Attacker reaches a public or owner-routed function that accepts a delegatecall target or payload.",
        "The victim executes delegatecall into attacker code.",
        "The malicious code writes into the victim contract storage layout.",
        "Ownership, balances, approvals, or control flags can be corrupted.",
      ],
      evidence,
      impact: "The attacker may seize control or corrupt contract accounting.",
      fix: "Remove untrusted delegatecall, use allowlisted implementations, and validate storage-layout assumptions.",
    }];
  }

  if (lower.includes("overflow") || lower.includes("underflow")) {
    return [{
      index: 1,
      title: "Arithmetic Corruption Path",
      finding_id: "audit-arithmetic",
      finding: `Arithmetic risk in ${audit.filename}`,
      severity,
      confidence,
      file: audit.filename,
      attacker_goal: "Force arithmetic into an unexpected value and bypass balance or limit checks.",
      steps: [
        "Attacker finds an arithmetic operation influenced by user input.",
        "Attacker submits a boundary value near zero or the maximum integer range.",
        "The contract computes an unexpected balance, allowance, or counter value.",
        "The attacker uses the corrupted value to bypass a transfer, mint, or withdrawal constraint.",
      ],
      evidence,
      impact: "Balances, supply, or authorization counters may become incorrect.",
      fix: "Use Solidity 0.8+ checked arithmetic and validate input bounds around critical calculations.",
    }];
  }

  if (lower.includes("timestamp")) {
    return [{
      index: 1,
      title: "Timestamp Manipulation Path",
      finding_id: "audit-timestamp",
      finding: `Timestamp dependency in ${audit.filename}`,
      severity,
      confidence,
      file: audit.filename,
      attacker_goal: "Influence time-dependent logic enough to win or bypass a contract condition.",
      steps: [
        "Attacker identifies logic based on block.timestamp or a nearby time condition.",
        "Attacker waits for a favorable block window.",
        "A block producer or timing strategy nudges execution into the desired branch.",
        "The attacker claims a reward, bypasses a lock, or affects randomness.",
      ],
      evidence,
      impact: "Time-sensitive payouts or eligibility checks may be biased.",
      fix: "Avoid timestamp randomness and use wider time windows or trusted randomness where needed.",
    }];
  }

  return [{
    index: 1,
    title: "Manual Review Path",
    finding_id: "audit-generic",
    finding: `${label} in ${audit.filename}`,
    severity,
    confidence,
    file: audit.filename,
    attacker_goal: "Validate whether the model-selected pattern is reachable and exploitable.",
    steps: [
      "Review the tagged source lines and public entrypoints.",
      "Check whether untrusted users can reach the suspicious operation.",
      "Trace state changes before and after the risky line.",
      "Confirm the behavior with a unit test or transaction trace.",
    ],
    evidence,
    impact: "Impact depends on reachability and whether static/source evidence confirms the model signal.",
    fix: "Prioritize confirmed Slither findings and line-level evidence before accepting generated patches.",
  }];
};

export default function AttackReplayPage() {
  const session = useSession();
  const cards = ((session.investigateResult?.attack_replay_cards?.length ?? 0) > 0
    ? session.investigateResult?.attack_replay_cards
    : auditReplayCards(session)) as ReplayCard[];
  const [activeIndex, setActiveIndex] = useState(0);
  const active = cards[activeIndex] ?? cards[0];
  const color = severityColor(active?.severity);

  if (!active) {
    return (
      <div className="p-6 space-y-6">
        <div>
          <h1 className="font-headline-md text-headline-md text-on-surface">Attack Replay</h1>
          <p className="font-body-sm text-body-sm text-on-surface-variant mt-1">Exploit path narratives generated from the current audit or multi-agent investigation.</p>
        </div>
        <div className="flex flex-col items-center gap-4 py-20 rounded-lg" style={{ backgroundColor: "#141b2b", border: "1px solid #424754" }}>
          <span className="material-symbols-outlined" style={{ fontSize: "56px", color: "#2e3545" }}>history_edu</span>
          <p className="font-body-sm text-body-sm text-on-surface-variant text-center max-w-md">
            Run a <strong className="text-on-surface">Smart Contract Audit</strong> first. Replay cards will appear here when supported exploit patterns are found.
          </p>
        </div>
      </div>
    );
  }

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-start justify-between gap-4 flex-wrap">
        <div>
          <h1 className="font-headline-md text-headline-md text-on-surface">Attack Replay</h1>
          <p className="font-body-sm text-body-sm text-on-surface-variant mt-1">Generated from current audit evidence, multi-agent findings, and exploit templates.</p>
        </div>
        <div className="flex gap-2 flex-wrap">
          {cards.map((card, index) => (
            <button
              key={`${card.finding_id ?? card.title}-${index}`}
              onClick={() => setActiveIndex(index)}
              className="px-3 py-1.5 rounded font-label-caps transition-all"
              style={{
                backgroundColor: activeIndex === index ? "#adc6ff" : "#191f2f",
                color: activeIndex === index ? "#002e6a" : "#c2c6d6",
                border: `1px solid ${activeIndex === index ? "#adc6ff" : "#424754"}`,
                fontSize: "10px",
              }}
            >
              AR-{String(index + 1).padStart(3, "0")}
            </button>
          ))}
        </div>
      </div>

      <div className="grid grid-cols-12 gap-4">
        <div className="col-span-12 p-5 rounded-lg" style={{ backgroundColor: "#141b2b", border: `1px solid ${color}40`, borderLeft: `4px solid ${color}` }}>
          <div className="flex items-start justify-between gap-4 flex-wrap">
            <div>
              <div className="flex items-center gap-2 mb-2">
                <span className="font-code-sm text-code-sm text-on-surface-variant">AR-{String(active.index ?? activeIndex + 1).padStart(3, "0")}</span>
                <span className="font-label-caps px-2 py-0.5 rounded" style={{ fontSize: "10px", color, backgroundColor: `${color}18` }}>{active.severity ?? "Unknown"}</span>
              </div>
              <h2 className="font-headline-sm text-headline-sm" style={{ color }}>{active.title ?? "Attack Replay Path"}</h2>
              <p className="font-body-sm text-body-sm text-on-surface-variant mt-2">{active.attacker_goal}</p>
            </div>
            <div className="text-right">
              <p className="font-label-caps text-on-surface-variant" style={{ fontSize: "10px" }}>Finding</p>
              <p className="font-code-sm text-code-sm text-on-surface">{active.finding_id ?? "N/A"}</p>
              <p className="font-label-caps mt-2" style={{ fontSize: "10px", color }}>Confidence {Math.round((active.confidence ?? 0) * 100)}%</p>
            </div>
          </div>
        </div>

        <div className="col-span-12 lg:col-span-8 p-6 rounded-lg" style={{ backgroundColor: "#141b2b", border: "1px solid #424754" }}>
          <h3 className="font-headline-sm text-headline-sm text-on-surface mb-6">Replay Steps</h3>
          <div className="relative">
            <div className="absolute left-5 top-0 bottom-0 w-0.5" style={{ backgroundColor: "#424754" }} />
            <div className="space-y-5 relative">
              {(active.steps ?? []).map((step, index) => (
                <div key={index} className="flex items-start gap-4 relative">
                  <div className="w-10 h-10 rounded-full flex items-center justify-center shrink-0 z-10" style={{ backgroundColor: index >= 2 ? `${color}` : "#232a3a", border: `2px solid ${index >= 2 ? color : "#424754"}`, color: index >= 2 ? "#190b0b" : "#c2c6d6" }}>
                    <span className="material-symbols-outlined" style={{ fontSize: "18px" }}>{stepIcon(index)}</span>
                  </div>
                  <div className="flex-1 p-4 rounded-lg" style={{ backgroundColor: index >= 2 ? `${color}08` : "#191f2f", border: `1px solid ${index >= 2 ? `${color}30` : "#424754"}` }}>
                    <div className="flex items-center gap-2 mb-1">
                      <span className="font-label-caps text-on-surface-variant" style={{ fontSize: "10px" }}>STEP {index + 1}</span>
                    </div>
                    <p className="font-body-sm text-body-sm text-on-surface-variant">{step}</p>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>

        <div className="col-span-12 lg:col-span-4 space-y-4">
          <div className="p-5 rounded-lg" style={{ backgroundColor: "#141b2b", border: "1px solid #424754" }}>
            <h3 className="font-headline-sm text-headline-sm text-on-surface mb-4">Replay Context</h3>
            {[
              ["Finding", active.finding ?? "N/A"],
              ["File", active.file ?? "Workspace-level"],
              ["Impact", active.impact ?? "Review required"],
              ["Break Path", active.fix ?? "No remediation path was generated."],
            ].map(([label, value]) => (
              <div key={label} className="py-3" style={{ borderBottom: "1px solid #2e3545" }}>
                <p className="font-label-caps text-on-surface-variant mb-1" style={{ fontSize: "10px" }}>{label}</p>
                <p className="font-body-sm text-body-sm text-on-surface">{value}</p>
              </div>
            ))}
          </div>

          <div className="p-5 rounded-lg" style={{ backgroundColor: "#141b2b", border: "1px solid #424754" }}>
            <h3 className="font-headline-sm text-headline-sm text-on-surface mb-4">Evidence</h3>
            <div className="space-y-2">
              {(active.evidence ?? []).map((item, index) => (
                <div key={index} className="p-3 rounded" style={{ backgroundColor: "#191f2f", border: "1px solid #2e3545" }}>
                  <p className="font-label-caps" style={{ fontSize: "10px", color: "#adc6ff" }}>{item.source ?? "Evidence"}</p>
                  <p className="font-body-sm text-body-sm text-on-surface-variant mt-1">{item.summary}</p>
                  {item.file && <p className="font-code-sm text-code-sm text-on-surface-variant mt-2">{item.file}{item.line ? `:${item.line}` : ""}</p>}
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
