const BASE = process.env.NEXT_PUBLIC_BACKEND_URL ?? "http://localhost:7860";

// ── Types ─────────────────────────────────────────────────────────────────────

export type AuditResult = {
  filename: string;
  source_code?: string;
  audit_text: string;
  risk_text: string;
  function_analysis: string;
  slither_report: string;
  line_map: string;
  prediction: {
    label: string;
    confidence: number;
    is_vulnerable: boolean;
    risk: string;
    all_scores: Record<string, number>;
  };
};

export type FixResult = {
  fix_explanation: string;
  reaudit: string;
  diff_markdown: string;
  fixed_filename: string | null;
};

export type AgentOut = {
  name: string;
  role: string;
  status: string;
  output: string;
  metrics: Record<string, unknown>;
};

export type InvestigateResult = {
  summary: string;
  agents: Record<string, AgentOut>;
  findings: unknown[];
  report_path: string | null;
  audit_text: string;
  fix_text: string;
  attack_replay_cards: unknown[];
};

export type CSVAnomalyResult = {
  analysis_text: string;
  explanation: string;
  risk_score: number;
  risk_level: string;
  anomaly_count: number;
  model_path: string | null;
  plots: Record<string, string | null>;
};

export type TraceResult = {
  trace_text: string;
};

export type CorrelationResult = {
  correlation_text: string;
};

export type ImageSecurityResult = {
  image_text: string;
  filename?: string;
  image_url?: string;
  risk_score?: number;
  risk_level?: string;
  classifier_label?: string;
  classifier_confidence?: number;
  ocr_engine?: string;
  dimensions?: string;
};

export type AssistantResponse = {
  answer: string;
  source?: string;
};

export type UploadResponse = {
  filename: string;
  size: number;
  status: string;
};

export type ReportFile = {
  filename: string;
  type: string;
  size: number;
  modified: number;
  download_url: string;
};

export type AuditHistoryEntry = {
  id: string;
  timestamp: string;
  file: string;
  risk_score: number;
  risk_score_label: string;
  risk_level: string;
  ml_prediction: string;
  ml_interpretation: string;
  static_status: string;
  slither_findings: number;
  fix_included: boolean;
  patch_included: boolean;
  status: string;
};

export type AuditHistoryResponse = {
  entries: AuditHistoryEntry[];
  summary: {
    total: number;
    average_risk: number;
    high_risk: number;
    fixed: number;
  };
};

export type ExportReportPayload = {
  selected_file?: string | null;
  risk_text?: string;
  audit_text?: string;
  fix_text?: string;
  line_map_text?: string;
  patch_diff_text?: string;
  csv_text?: string;
  csv_explanation?: string;
  trace_text?: string;
  image_text?: string;
  investigation_summary?: string;
  attack_replay_text?: string;
};

export type ExportReportResult = {
  report_path: string;
  filename: string;
  download_url: string;
};

// ── Helpers ───────────────────────────────────────────────────────────────────

async function api<T>(path: string, options?: RequestInit): Promise<T> {
  const res = await fetch(`${BASE}${path}`, {
    headers: { "Content-Type": "application/json" },
    ...options,
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: res.statusText }));
    throw new Error(err.detail ?? `HTTP ${res.status}`);
  }
  return res.json();
}

// ── Endpoints ─────────────────────────────────────────────────────────────────

export async function checkHealth(): Promise<{ status: string }> {
  return api("/api/health");
}

export async function listFiles(): Promise<{ files: string[] }> {
  return api("/api/files");
}

export async function getSourceFile(filename: string): Promise<{ filename: string; source_code: string }> {
  return api(`/api/source/${encodeURIComponent(filename)}`);
}

export async function listReports(): Promise<{ reports: ReportFile[] }> {
  return api("/api/reports");
}

export async function listAuditHistory(): Promise<AuditHistoryResponse> {
  return api("/api/audit-history");
}

export async function exportReport(payload: ExportReportPayload): Promise<ExportReportResult> {
  return api("/api/export-report", {
    method: "POST",
    body: JSON.stringify(payload),
  });
}

export async function uploadFile(file: File): Promise<UploadResponse> {
  const form = new FormData();
  form.append("file", file);
  const res = await fetch(`${BASE}/api/upload`, { method: "POST", body: form });
  if (!res.ok) throw new Error(`Upload failed: ${res.statusText}`);
  return res.json();
}

export async function runAudit(filename: string): Promise<AuditResult> {
  return api("/api/audit", { method: "POST", body: JSON.stringify({ filename }) });
}

export async function generateFix(
  filename: string,
  audit_text: string,
  risk_text: string
): Promise<FixResult> {
  return api("/api/fix", {
    method: "POST",
    body: JSON.stringify({ filename, audit_text, risk_text }),
  });
}

export async function runCSVAnomaly(filename: string): Promise<CSVAnomalyResult> {
  return api("/api/csv-anomaly", { method: "POST", body: JSON.stringify({ filename }) });
}

export async function runJSONTrace(filename: string): Promise<TraceResult> {
  return api("/api/json-trace", { method: "POST", body: JSON.stringify({ filename }) });
}

export async function runImageSecurity(filename: string): Promise<ImageSecurityResult> {
  return api("/api/image-security", { method: "POST", body: JSON.stringify({ filename }) });
}

export async function correlateCSVWithContract(
  solidity_file: string | null,
  audit_text: string,
  line_map_text: string,
  csv_text: string,
  row_number: string
): Promise<CorrelationResult> {
  return api("/api/correlate/csv-contract", {
    method: "POST",
    body: JSON.stringify({ solidity_file, audit_text, line_map_text, csv_text, row_number }),
  });
}

export async function correlateTraceWithContract(
  solidity_file: string | null,
  audit_text: string,
  line_map_text: string,
  trace_text: string
): Promise<CorrelationResult> {
  return api("/api/correlate/trace-contract", {
    method: "POST",
    body: JSON.stringify({ solidity_file, audit_text, line_map_text, trace_text }),
  });
}

export async function chatWithFile(
  message: string,
  selectedFile: string | string[] | null,
  history: { role: string; content: string }[] = []
): Promise<AssistantResponse> {
  const filePayload = Array.isArray(selectedFile)
    ? { selected_files: selectedFile.length > 0 ? selectedFile : null }
    : { selected_file: selectedFile };
  return api("/api/chat", {
    method: "POST",
    body: JSON.stringify({ message, ...filePayload, history }),
  });
}

export async function runInvestigation(files?: string[]): Promise<InvestigateResult> {
  return api("/api/investigate", {
    method: "POST",
    body: JSON.stringify({ files: files ?? null }),
  });
}

export async function askAssistant(
  message: string,
  history: { role: string; content: string }[] = []
): Promise<AssistantResponse> {
  const res = await fetch(`${BASE}/assistant/invoke`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ input: { input: message, chat_history: history } }),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: res.statusText }));
    throw new Error(err.detail ?? `HTTP ${res.status}`);
  }
  const data = await res.json();
  const out = data.output;
  if (typeof out === "string") return { answer: out };
  if (out && typeof out === "object") {
    return {
      answer: out.answer ?? out.response ?? out.result ?? JSON.stringify(out),
      source: out.source ?? out.source_documents?.[0]?.metadata?.source,
    };
  }
  return { answer: "No response from server." };
}
