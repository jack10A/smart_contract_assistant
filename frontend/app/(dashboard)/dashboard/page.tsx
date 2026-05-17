"use client";
import Link from "next/link";
import RiskGauge from "../../components/ui/RiskGauge";
import ProgressBar from "../../components/ui/ProgressBar";
import ChatPanel from "../../components/ui/ChatPanel";
import { useSession } from "../../context/SessionContext";

type FindingRow = {
  name: string;
  severity: string;
  confidence: string;
  detectedBy: string[];
  fn: string;
  lines: string;
  status: string;
};

const sevColors: Record<string, { bg: string; text: string }> = {
  CRITICAL: { bg: "#93000a", text: "#ffb4ab" },
  HIGH: { bg: "rgba(223,116,18,0.2)", text: "#ffb786" },
  MEDIUM: { bg: "rgba(76,215,246,0.1)", text: "#4cd7f6" },
  LOW: { bg: "rgba(173,198,255,0.1)", text: "#adc6ff" },
  INFO: { bg: "#2e3545", text: "#8c909f" },
};

const detectorColors: Record<string, { bg: string; text: string }> = {
  AI: { bg: "#4cd7f6", text: "#003640" },
  SL: { bg: "#adc6ff", text: "#002e6a" },
  SRC: { bg: "#ffb786", text: "#502400" },
};

const statusColors: Record<string, string> = {
  OPEN: "#ffb4ab",
  REVIEW: "#ffb786",
  FIXED: "#4cd7f6",
};

const extract = (text: string | undefined, pattern: RegExp, fallback = "") => {
  const match = (text ?? "").match(pattern);
  return match?.[1]?.trim() ?? fallback;
};

const riskColor = (score: number) => (score >= 80 ? "#ffb4ab" : score >= 60 ? "#ffb786" : score >= 40 ? "#4cd7f6" : "#adc6ff");
const riskBand = (score: number) => (score >= 80 ? "CRITICAL_RANGE" : score >= 60 ? "HIGH_RANGE" : score >= 40 ? "MEDIUM_RANGE" : "LOW_RANGE");
const riskTitle = (score: number) => (score >= 80 ? "Critical Risk Detected" : score >= 60 ? "High Risk Detected" : score >= 40 ? "Medium Risk Detected" : "Low Risk Detected");

const parseLineCount = (source?: string) => (source ? source.split("\n").length : 0);
const formatBytes = (text?: string) => {
  const bytes = new Blob([text ?? ""]).size;
  if (bytes < 1024) return `${bytes} B`;
  return `${Math.round(bytes / 1024)} KB`;
};

const parseEvidenceCount = (lineMap?: string) => [...(lineMap ?? "").matchAll(/\*\*Line\s+\d+:/g)].length;

const parseImpactCounts = (auditText?: string) => {
  const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const line of (auditText ?? "").split("\n")) {
    const cells = line.split("|").map((cell) => cell.trim()).filter(Boolean);
    if (cells.length < 5) continue;
    const impact = cells[0].toLowerCase();
    if (impact === "high") counts.high += 1;
    else if (impact === "medium") counts.medium += 1;
    else if (impact === "low") counts.low += 1;
    else if (impact === "informational" || impact === "optimization") counts.info += 1;
  }
  return counts;
};

const parseSlitherFindings = (auditText?: string): FindingRow[] => {
  const rows: FindingRow[] = [];
  for (const line of (auditText ?? "").split("\n")) {
    const cells = line.split("|").map((cell) => cell.trim()).filter(Boolean);
    if (cells.length < 5) continue;
    const [impact, confidence, detector, lines, description] = cells;
    if (impact === "---" || impact.toLowerCase() === "impact") continue;
    const normalizedImpact = impact.toLowerCase();
    if (!["high", "medium", "low", "informational", "optimization"].includes(normalizedImpact)) continue;
    const severity = normalizedImpact === "high" ? "HIGH" : normalizedImpact === "medium" ? "MEDIUM" : normalizedImpact === "low" ? "LOW" : "INFO";
    const fn = description.match(/in\s+([A-Za-z0-9_]+\.[A-Za-z0-9_]+(?:\([^)]*\))?)/)?.[1] ?? "-";
    rows.push({
      name: detector.replace(/`/g, ""),
      severity,
      confidence,
      detectedBy: ["SL"],
      fn,
      lines,
      status: severity === "INFO" ? "REVIEW" : "OPEN",
    });
  }
  return rows.slice(0, 8);
};

const parseFunctionRows = (functionText?: string): FindingRow[] => {
  const rows: FindingRow[] = [];
  for (const line of (functionText ?? "").split("\n")) {
    const cells = line.split("|").map((cell) => cell.trim().replace(/`/g, "")).filter(Boolean);
    if (cells.length < 5 || cells[0].toLowerCase() === "function" || cells[0] === "---") continue;
    rows.push({
      name: cells[2],
      severity: Number.parseFloat(cells[3]) >= 70 ? "HIGH" : "MEDIUM",
      confidence: cells[3],
      detectedBy: ["AI"],
      fn: cells[0],
      lines: cells[1],
      status: cells[4].toLowerCase().includes("low confidence") ? "REVIEW" : "OPEN",
    });
  }
  return rows.slice(0, 5);
};

export default function DashboardPage() {
  const session = useSession();
  const audit = session.auditResult;
  const score = Number.parseInt(extract(audit?.risk_text, /Risk score:\*\*\s+\*\*(\d+)\/100/i, "0"), 10) || 0;
  const riskLevel = extract(audit?.risk_text, /Risk level:\*\*\s+\*\*([A-Za-z]+)/i, audit ? "Medium" : "No audit");
  const verdict = extract(audit?.risk_text, /#### Final Verdict\s+([\s\S]*?)(?:\n####|\n$)/i, audit ? "Review the generated audit evidence." : "Run a Smart Contract Audit to populate this dashboard.");
  const confidence = Math.round((audit?.prediction?.confidence ?? 0) * 100);
  const impactCounts = parseImpactCounts(audit?.audit_text);
  const evidenceCount = parseEvidenceCount(audit?.line_map);
  const slitherRows = parseSlitherFindings(audit?.audit_text);
  const functionRows = parseFunctionRows(audit?.function_analysis);
  const findings = [
    ...(audit ? [{
      name: audit.prediction.label,
      severity: riskLevel.toUpperCase() === "LOW" ? "LOW" : riskLevel.toUpperCase(),
      confidence: `${confidence}%`,
      detectedBy: ["AI", ...(slitherRows.some((row) => row.severity === "HIGH" || row.severity === "MEDIUM") ? ["SL"] : [])],
      fn: "contract-wide",
      lines: evidenceCount ? `${evidenceCount} tagged` : "-",
      status: session.fixResult ? "FIXED" : "OPEN",
    }] : []),
    ...slitherRows,
    ...functionRows,
  ].slice(0, 10);
  const totalFindings = impactCounts.high + impactCounts.medium + impactCounts.low + impactCounts.info + (audit ? 1 : 0);
  const activeFile = audit?.filename || session.selectedFile || "No active audit";
  const sourceLines = parseLineCount(audit?.source_code);
  const replayCount = session.investigateResult?.attack_replay_cards?.length || (audit ? 1 : 0);
  const staticConfirmed = slitherRows.some((row) => row.severity === "HIGH" || row.severity === "MEDIUM");

  const workspaceItems = [
    { label: activeFile, icon: "description", active: true, badge: audit ? riskLevel.toUpperCase() : "NO_AUDIT" },
    { label: session.csvFile || "CSV not run", icon: "table_chart", active: Boolean(session.csvResult), badge: session.csvResult ? `${session.csvResult.risk_score}/100` : "" },
    { label: session.traceFile || "Trace not run", icon: "route", active: Boolean(session.traceResult), badge: session.traceResult ? "TRACE" : "" },
    { label: session.imageFile || "Image not run", icon: "image_search", active: Boolean(session.imageResult), badge: session.imageResult?.risk_level ?? "" },
    { label: session.investigateResult ? "Multi-agent complete" : "Multi-agent not run", icon: "hub", active: Boolean(session.investigateResult), badge: session.investigateResult ? "CASE" : "" },
  ];

  const breakdownCards = [
    { label: "STATIC_ANALYSIS", value: staticConfirmed ? "CONFIRMED" : audit ? "REVIEW" : "WAITING", sub: staticConfirmed ? "Slither supports audit risk" : "Run audit for static evidence", valueColor: staticConfirmed ? "#4cd7f6" : "#8c909f" },
    { label: "AI_CLASSIFIER", value: audit ? `${confidence}%` : "-", sub: audit ? `Pattern match: ${audit.prediction.label}` : "No model output yet", valueColor: audit ? riskColor(score) : "#8c909f" },
    { label: "FUNCTION_LEVEL", value: `${functionRows.length} ROWS`, sub: "Function classifier output", valueColor: functionRows.length ? "#ffb786" : "#8c909f" },
    { label: "LINE_EVIDENCE", value: `${evidenceCount} LOC`, sub: "Tagged for source review", valueColor: evidenceCount ? "#dce2f7" : "#8c909f" },
    { label: "ATTACK_REPLAY", value: audit ? "READY" : "WAITING", sub: `${replayCount} path${replayCount === 1 ? "" : "s"} available`, valueColor: audit ? "#ffb786" : "#8c909f" },
    { label: "CSV_SIGNAL", value: session.csvResult ? `${session.csvResult.risk_score}/100` : "-", sub: session.csvResult ? `${session.csvResult.anomaly_count} anomalies` : "No CSV analysis yet", valueColor: session.csvResult ? riskColor(session.csvResult.risk_score) : "#8c909f" },
    { label: "TRACE_SIGNAL", value: session.traceResult ? "LINKED" : "-", sub: session.traceResult ? "Runtime evidence available" : "No trace analysis yet", valueColor: session.traceResult ? "#4cd7f6" : "#8c909f" },
    { label: "IMAGE_SIGNAL", value: session.imageResult?.risk_level?.toUpperCase() ?? "-", sub: session.imageResult ? session.imageResult.classifier_label ?? "Image analyzed" : "No image analysis yet", valueColor: session.imageResult?.risk_score ? riskColor(session.imageResult.risk_score) : "#8c909f" },
    { label: "FIX_VALIDATION", value: session.fixResult ? "GENERATED" : "PENDING", sub: session.fixResult ? "Patch and re-audit available" : "No patch generated yet", valueColor: session.fixResult ? "#4cd7f6" : "#8c909f" },
  ];

  const structuredFindings = [
    ...(audit ? [{
      title: audit.prediction.label,
      tag: staticConfirmed ? "CONFIRMED" : "ML_SIGNAL",
      desc: verdict.replace(/\n/g, " ").slice(0, 220),
      color: riskColor(score),
    }] : []),
    ...(session.csvResult ? [{
      title: "CSV Transaction Signal",
      tag: session.csvResult.risk_level.toUpperCase(),
      desc: `${session.csvResult.anomaly_count} consensus anomaly rows in ${session.csvFile}.`,
      color: riskColor(session.csvResult.risk_score),
    }] : []),
    ...(session.traceResult ? [{
      title: "Runtime Trace Evidence",
      tag: "TRACE",
      desc: "Trace analysis is available for correlation with contract findings.",
      color: "#4cd7f6",
    }] : []),
    ...(session.imageResult ? [{
      title: "Image Security Signal",
      tag: session.imageResult.risk_level?.toUpperCase() ?? "IMAGE",
      desc: `${session.imageResult.filename ?? session.imageFile} classified as ${session.imageResult.classifier_label ?? "analyzed"}.`,
      color: session.imageResult.risk_score ? riskColor(session.imageResult.risk_score) : "#4cd7f6",
    }] : []),
  ];

  const chatMessages = audit ? [
    { id: "1", role: "user" as const, content: `Why is ${audit.filename} risky?` },
    {
      id: "2",
      role: "assistant" as const,
      content: `The current audit selected ${audit.prediction.label} with ${confidence}% confidence. ${verdict.replace(/\n/g, " ")}`,
      sourceRef: audit.line_map.match(/\*\*Line\s+(\d+):\s+([^*]+)/)?.[0]?.replace(/\*\*/g, "") ?? audit.filename,
    },
  ] : undefined;

  return (
    <div className="flex flex-col h-full">
      <div className="flex-1 overflow-y-auto p-6 space-y-6">
        <div className="grid grid-cols-12 gap-4">
          <div className="col-span-12 lg:col-span-4 space-y-4">
            <section className="p-4 rounded-lg" style={{ backgroundColor: "#141b2b", border: "1px solid #424754" }}>
              <h2 className="font-label-caps text-label-caps text-on-surface-variant mb-4 flex items-center gap-2">
                <span className="material-symbols-outlined" style={{ fontSize: "16px" }}>workspaces</span>
                WORKSPACE_PANEL
              </h2>
              <div className="rounded-lg p-5 flex flex-col items-center justify-center text-on-surface-variant mb-4" style={{ border: "2px dashed #424754" }}>
                <span className="material-symbols-outlined mb-2" style={{ fontSize: "34px" }}>upload_file</span>
                <p className="font-body-sm text-body-sm text-center">Upload or select files, then run analysis. This panel follows the active session.</p>
              </div>
              <div className="space-y-1">
                {workspaceItems.map((item) => (
                  <div key={item.label} className="flex items-center justify-between p-2 rounded-sm" style={{ backgroundColor: item.active ? "#2e3545" : "transparent", borderLeft: item.active ? "2px solid #adc6ff" : "2px solid transparent" }}>
                    <div className="flex items-center gap-2 min-w-0">
                      <span className="material-symbols-outlined" style={{ fontSize: "16px", color: item.active ? "#adc6ff" : "#8c909f" }}>{item.icon}</span>
                      <span className="font-code-sm text-code-sm truncate" style={{ color: item.active ? "#adc6ff" : "#8c909f" }}>{item.label}</span>
                    </div>
                    {item.badge && <span className="font-label-caps px-1.5 py-0.5 rounded" style={{ fontSize: "9px", backgroundColor: item.active ? "rgba(76,215,246,0.1)" : "#191f2f", color: item.active ? "#4cd7f6" : "#8c909f" }}>{item.badge}</span>}
                  </div>
                ))}
              </div>
            </section>

            <div className="p-4 rounded-lg" style={{ backgroundColor: "#141b2b", border: "1px solid #424754" }}>
              <h3 className="font-label-caps text-label-caps text-on-surface-variant mb-3">FILE_SUMMARY</h3>
              <div className="grid grid-cols-2 gap-2">
                {[
                  { k: "TYPE", v: audit ? "SOLIDITY" : "-", vc: "#dce2f7" },
                  { k: "LINES", v: sourceLines ? String(sourceLines) : "-", vc: "#dce2f7" },
                  { k: "SIZE", v: audit?.source_code ? formatBytes(audit.source_code) : "-", vc: "#dce2f7" },
                  { k: "INDEXED", v: audit ? "YES" : "-", vc: audit ? "#4cd7f6" : "#8c909f" },
                  { k: "LAST SCAN", v: audit ? "CURRENT" : "-", vc: "#dce2f7" },
                  { k: "RISK", v: riskLevel.toUpperCase(), vc: riskColor(score) },
                ].map(({ k, v, vc }) => (
                  <div key={k} className="p-2 rounded" style={{ backgroundColor: "#191f2f" }}>
                    <p style={{ fontSize: "10px", color: "#c2c6d6", marginBottom: "2px" }}>{k}</p>
                    <p className="font-code-sm text-code-sm" style={{ color: vc }}>{v}</p>
                  </div>
                ))}
              </div>
            </div>
          </div>

          <div className="col-span-12 lg:col-span-4 p-6 rounded-lg relative overflow-hidden flex flex-col items-center justify-center text-center" style={{ backgroundColor: "#232a3a", border: "1px solid #424754" }}>
            <div className="absolute top-4 left-4 font-label-caps text-label-caps text-on-surface-variant flex items-center gap-1" style={{ fontSize: "10px" }}>
              <span className="material-symbols-outlined" style={{ fontSize: "14px" }}>shield</span>
              RISK_SCORE
            </div>
            <RiskGauge score={score} label={riskBand(score)} size={192} />
            <div className="mt-4">
              <h4 className="font-headline-sm text-headline-sm" style={{ color: riskColor(score) }}>{riskTitle(score)}</h4>
              <p className="font-body-sm text-body-sm text-on-surface-variant mt-2 max-w-xs">{verdict}</p>
              <div className="mt-4 flex items-center justify-center gap-5">
                {[
                  ["CONFIDENCE", audit ? `${confidence}%` : "-"],
                  ["AI_CONF", audit ? `${confidence}%` : "-"],
                  ["SLITHER", staticConfirmed ? "CONFIRMED" : audit ? "REVIEW" : "-"],
                ].map(([label, value], index) => (
                  <div key={label} className="text-center flex items-center gap-5">
                    {index > 0 && <div className="h-8 w-px" style={{ backgroundColor: "#424754" }} />}
                    <div>
                      <p style={{ fontSize: "10px", color: "#c2c6d6" }}>{label}</p>
                      <p className="font-code-base text-code-base" style={{ color: value === "CONFIRMED" ? "#4cd7f6" : riskColor(score) }}>{value}</p>
                    </div>
                  </div>
                ))}
              </div>
              <div className="mt-3 px-3 py-1.5 rounded font-label-caps text-label-caps" style={{ backgroundColor: session.fixResult ? "rgba(76,215,246,0.12)" : "rgba(223,116,18,0.15)", color: session.fixResult ? "#4cd7f6" : "#ffb786", border: "1px solid rgba(223,116,18,0.3)", fontSize: "10px" }}>
                Fix Validation: {session.fixResult ? "Patch generated" : "Pending"}
              </div>
            </div>
          </div>

          <div className="col-span-12 lg:col-span-4 p-6 rounded-lg" style={{ backgroundColor: "#141b2b", border: "1px solid #424754" }}>
            <h3 className="font-label-caps text-label-caps text-on-surface-variant mb-6 flex items-center gap-2">
              <span className="material-symbols-outlined" style={{ fontSize: "16px" }}>bar_chart</span>
              SEVERITY_DISTRIBUTION
            </h3>
            <div className="space-y-4">
              <ProgressBar label="HIGH" count={impactCounts.high} total={Math.max(1, totalFindings)} color="#ffb786" />
              <ProgressBar label="MEDIUM" count={impactCounts.medium + (audit && score >= 40 && score < 60 ? 1 : 0)} total={Math.max(1, totalFindings)} color="#4cd7f6" />
              <ProgressBar label="LOW" count={impactCounts.low} total={Math.max(1, totalFindings)} color="#adc6ff" />
              <ProgressBar label="INFO/OPT" count={impactCounts.info} total={Math.max(1, totalFindings)} color="#8c909f" />
            </div>
            <div className="mt-6 pt-4" style={{ borderTop: "1px solid #424754" }}>
              <p className="font-label-caps text-label-caps text-on-surface-variant mb-3" style={{ fontSize: "10px" }}>TOTAL FINDINGS: {totalFindings}</p>
              <div className="flex gap-1 items-end h-16">
                {[impactCounts.high, impactCounts.medium, impactCounts.low, impactCounts.info, evidenceCount, replayCount].map((count, i) => (
                  <div key={i} className="flex-1 rounded-sm opacity-80" style={{ height: `${Math.max(8, Math.min(100, count * 18))}%`, backgroundColor: ["#ffb786", "#4cd7f6", "#adc6ff", "#8c909f", "#dce2f7", "#ffb4ab"][i] }} />
                ))}
              </div>
              <div className="flex justify-between mt-1" style={{ fontSize: "9px", color: "#8c909f" }}>
                <span>High</span><span>Med</span><span>Low</span><span>Info</span><span>LOC</span><span>Replay</span>
              </div>
            </div>
          </div>
        </div>

        <div className="grid grid-cols-12 gap-4">
          <div className="col-span-12 lg:col-span-8 grid grid-cols-1 sm:grid-cols-3 gap-4">
            {breakdownCards.map((card) => (
              <div key={card.label} className="p-4 rounded-lg" style={{ backgroundColor: "#191f2f", border: "1px solid #424754" }}>
                <p className="font-label-caps text-on-surface-variant" style={{ fontSize: "10px" }}>{card.label}</p>
                <p className="font-headline-sm text-headline-sm mt-1" style={{ color: card.valueColor }}>{card.value}</p>
                <p className="font-body-sm text-body-sm text-on-surface-variant mt-1">{card.sub}</p>
              </div>
            ))}
          </div>

          <div className="col-span-12 lg:col-span-4">
            <section className="p-4 rounded-lg h-full flex flex-col" style={{ backgroundColor: "#141b2b", border: "1px solid #424754" }}>
              <h3 className="font-label-caps text-label-caps text-on-surface-variant mb-4 flex items-center gap-2">
                <span className="material-symbols-outlined" style={{ fontSize: "16px" }}>list_alt</span>
                STRUCTURED_FINDINGS
              </h3>
              <div className="space-y-3 flex-1 overflow-y-auto">
                {structuredFindings.length === 0 ? (
                  <p className="font-body-sm text-body-sm text-on-surface-variant">Run audit, CSV, trace, or image analysis to populate structured findings.</p>
                ) : structuredFindings.map((finding) => (
                  <div key={`${finding.title}-${finding.tag}`} className="p-3 rounded-sm" style={{ backgroundColor: "#2e3545", borderLeft: `4px solid ${finding.color}` }}>
                    <div className="flex justify-between items-start gap-2 mb-1">
                      <span className="font-body-sm font-bold" style={{ color: finding.color }}>{finding.title}</span>
                      <span className="font-label-caps px-1 rounded" style={{ fontSize: "10px", backgroundColor: `${finding.color}18`, color: finding.color }}>{finding.tag}</span>
                    </div>
                    <p className="font-body-sm text-body-sm text-on-surface-variant leading-relaxed">{finding.desc}</p>
                  </div>
                ))}

                <div className="p-3 rounded flex flex-col items-center" style={{ border: "1px dashed #424754", backgroundColor: "rgba(25,31,47,0.3)" }}>
                  <span className="material-symbols-outlined mb-2" style={{ color: "#4cd7f6" }}>play_circle</span>
                  <p className="font-label-caps text-label-caps text-on-surface" style={{ fontSize: "10px" }}>ATTACK_REPLAY_PATHS</p>
                  <p className="font-body-sm text-body-sm text-on-surface-variant text-center mt-1">{replayCount} exploit scenario{replayCount === 1 ? "" : "s"} available</p>
                  <Link href="/attack-replay" className="mt-3 px-4 py-1.5 rounded font-label-caps text-label-caps font-bold active:scale-95 transition-transform" style={{ fontSize: "10px", backgroundColor: "#03b5d3", color: "#00424e" }}>
                    LAUNCH_SIMULATOR
                  </Link>
                </div>
              </div>
            </section>
          </div>
        </div>

        <div className="rounded-lg overflow-hidden" style={{ border: "1px solid #424754" }}>
          <div className="px-6 py-4 flex justify-between items-center flex-wrap gap-3" style={{ backgroundColor: "#191f2f", borderBottom: "1px solid #424754" }}>
            <h3 className="font-label-caps text-label-caps text-on-surface-variant">VULNERABILITY_DETECTION_MATRIX</h3>
            <div className="flex gap-6">
              {[["#4cd7f6", "AI_MODEL"], ["#adc6ff", "SLITHER"], ["#ffb786", "SOURCE"]].map(([color, label]) => (
                <div key={label} className="flex items-center gap-2">
                  <div className="w-3 h-3 rounded-full" style={{ backgroundColor: color }} />
                  <span className="font-label-caps" style={{ fontSize: "10px", color: "#c2c6d6" }}>{label}</span>
                </div>
              ))}
            </div>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-left" style={{ borderCollapse: "collapse", minWidth: "920px" }}>
              <thead style={{ backgroundColor: "#070e1d", borderBottom: "1px solid #424754" }}>
                <tr>
                  {["Name", "Severity", "Confidence", "Detected By", "Function", "Lines", "Status", "Action"].map((heading) => (
                    <th key={heading} className="px-6 py-3 font-label-caps text-label-caps text-on-surface-variant">{heading}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {findings.length === 0 ? (
                  <tr><td colSpan={8} className="px-6 py-8 font-body-sm text-body-sm text-on-surface-variant">No detection matrix yet. Run Smart Contract Audit to populate this table.</td></tr>
                ) : findings.map((row, index) => (
                  <tr key={`${row.name}-${index}`} className="transition-colors hover:bg-surface-container-highest" style={{ borderTop: "1px solid #424754" }}>
                    <td className="px-6 py-4 font-body-sm font-bold text-on-surface">{row.name}</td>
                    <td className="px-6 py-4">
                      <span className="font-label-caps px-2 py-0.5 rounded" style={{ fontSize: "10px", backgroundColor: sevColors[row.severity]?.bg ?? sevColors.INFO.bg, color: sevColors[row.severity]?.text ?? sevColors.INFO.text }}>{row.severity}</span>
                    </td>
                    <td className="px-6 py-4 font-code-sm text-code-sm text-on-surface">{row.confidence}</td>
                    <td className="px-6 py-4">
                      <div className="flex -space-x-1">
                        {row.detectedBy.map((detector) => (
                          <div key={detector} className="w-5 h-5 rounded-full flex items-center justify-center font-bold" style={{ fontSize: "8px", backgroundColor: detectorColors[detector]?.bg, color: detectorColors[detector]?.text, border: "2px solid #0c1322" }}>{detector}</div>
                        ))}
                      </div>
                    </td>
                    <td className="px-6 py-4 font-code-sm text-code-sm text-on-surface">{row.fn}</td>
                    <td className="px-6 py-4 font-code-sm text-code-sm text-on-surface">{row.lines}</td>
                    <td className="px-6 py-4"><span className="font-label-caps" style={{ fontSize: "11px", color: statusColors[row.status] ?? "#8c909f" }}>{row.status}</span></td>
                    <td className="px-6 py-4"><Link href="/line-evidence" className="font-label-caps text-label-caps transition-colors hover:underline" style={{ color: "#adc6ff", fontSize: "11px" }}>VIEW_TRACE</Link></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </div>

      <ChatPanel groundedFile={activeFile} initialMessages={chatMessages} />
      <Link href="/attack-replay" className="fixed bottom-24 right-8 w-14 h-14 rounded-full shadow-lg flex items-center justify-center transition-transform hover:scale-105 active:scale-95 z-50 group" style={{ backgroundColor: "#ffb4ab", color: "#690005" }} title="REPLAY_EXPLOIT_NOW">
        <span className="material-symbols-outlined text-2xl" style={{ fontSize: "28px" }}>terminal</span>
        <div className="absolute right-16 px-3 py-1 rounded font-label-caps text-label-caps whitespace-nowrap opacity-0 group-hover:opacity-100 transition-opacity" style={{ backgroundColor: "#2e3545", border: "1px solid #424754", color: "#dce2f7", fontSize: "10px" }}>
          REPLAY_EXPLOIT_NOW
        </div>
      </Link>
    </div>
  );
}
