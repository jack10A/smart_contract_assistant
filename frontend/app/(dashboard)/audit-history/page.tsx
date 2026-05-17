"use client";
import { useEffect, useMemo, useState } from "react";
import { listAuditHistory, type AuditHistoryEntry, type AuditHistoryResponse } from "../../lib/api";

const emptyHistory: AuditHistoryResponse = {
  entries: [],
  summary: {
    total: 0,
    average_risk: 0,
    high_risk: 0,
    fixed: 0,
  },
};

const riskColor = (score: number) =>
  score >= 80 ? "#ffb4ab" : score >= 60 ? "#ffb786" : score >= 40 ? "#4cd7f6" : "#8c909f";

const statusColor: Record<string, { backgroundColor: string; color: string }> = {
  COMPLETE: { backgroundColor: "rgba(76,215,246,0.1)", color: "#4cd7f6" },
  FAILED: { backgroundColor: "rgba(255,180,171,0.1)", color: "#ffb4ab" },
};

const formatDate = (value: string) => {
  if (!value) return "-";
  const normalized = value.includes("T") ? value : value.replace(" ", "T");
  const date = new Date(normalized);
  if (Number.isNaN(date.getTime())) return value;
  return date.toLocaleString(undefined, {
    year: "numeric",
    month: "short",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
  });
};

const riskLabel = (entry: AuditHistoryEntry) => {
  const label = entry.risk_level || "Unknown";
  return label.toUpperCase();
};

export default function AuditHistoryPage() {
  const [history, setHistory] = useState<AuditHistoryResponse>(emptyHistory);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [query, setQuery] = useState("");
  const [riskFilter, setRiskFilter] = useState("all");

  const load = async () => {
    try {
      const response = await listAuditHistory();
      setHistory(response);
      setError(null);
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : "Could not load audit history");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    const timer = window.setTimeout(() => {
      void load();
    }, 0);
    return () => window.clearTimeout(timer);
  }, []);

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    return history.entries.filter((entry) => {
      const riskMatch =
        riskFilter === "all" ||
        (riskFilter === "high" && entry.risk_score >= 60) ||
        (riskFilter === "low" && entry.risk_score < 60) ||
        (riskFilter === "fixed" && entry.fix_included);
      const textMatch =
        !q ||
        `${entry.file} ${entry.ml_prediction} ${entry.static_status} ${entry.risk_level}`
          .toLowerCase()
          .includes(q);
      return riskMatch && textMatch;
    });
  }, [history.entries, query, riskFilter]);

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-start justify-between gap-4 flex-wrap">
        <div>
          <h1 className="font-headline-md text-headline-md text-on-surface">Audit History</h1>
          <p className="font-body-sm text-body-sm text-on-surface-variant mt-1">
            {history.summary.total} saved audit snapshots - most recent first
          </p>
        </div>
        <div className="flex items-center gap-2 flex-wrap">
          <input
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Search history"
            className="rounded px-3 py-2 font-code-sm text-on-surface outline-none"
            style={{ backgroundColor: "#191f2f", border: "1px solid #424754", minWidth: "220px", fontSize: "12px" }}
          />
          <select
            value={riskFilter}
            onChange={(e) => setRiskFilter(e.target.value)}
            className="rounded px-3 py-2 font-label-caps outline-none"
            style={{ backgroundColor: "#191f2f", border: "1px solid #424754", color: "#c2c6d6", fontSize: "10px" }}
          >
            <option value="all">ALL</option>
            <option value="high">HIGH RISK</option>
            <option value="low">LOWER RISK</option>
            <option value="fixed">FIX INCLUDED</option>
          </select>
          <button
            onClick={() => {
              setLoading(true);
              setError(null);
              void load();
            }}
            className="flex items-center gap-2 px-4 py-2 rounded font-label-caps transition-colors"
            style={{ border: "1px solid #424754", color: "#c2c6d6", fontSize: "10px" }}
          >
            <span className="material-symbols-outlined" style={{ fontSize: "15px" }}>refresh</span>
            REFRESH
          </button>
        </div>
      </div>

      {error && (
        <div className="p-4 rounded-lg font-body-sm" style={{ backgroundColor: "rgba(255,180,171,0.08)", border: "1px solid rgba(255,180,171,0.3)", color: "#ffb4ab" }}>
          {error}
        </div>
      )}

      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        {[
          { label: "Total Audits", value: String(history.summary.total), color: "#dce2f7" },
          { label: "Avg Risk Score", value: String(history.summary.average_risk), color: "#ffb786" },
          { label: "High Risk", value: String(history.summary.high_risk), color: "#ffb4ab" },
          { label: "Fix Snapshots", value: String(history.summary.fixed), color: "#4cd7f6" },
        ].map(({ label, value, color }) => (
          <div key={label} className="p-4 rounded-lg" style={{ backgroundColor: "#191f2f", border: "1px solid #424754" }}>
            <p className="font-label-caps text-label-caps text-on-surface-variant">{label}</p>
            <p className="font-headline-sm text-headline-sm mt-1" style={{ color }}>{value}</p>
          </div>
        ))}
      </div>

      <div className="rounded-lg overflow-hidden" style={{ border: "1px solid #424754" }}>
        {loading ? (
          <div className="p-8 text-center" style={{ backgroundColor: "#141b2b" }}>
            <p className="font-body-sm text-body-sm text-on-surface-variant">Loading audit history...</p>
          </div>
        ) : filtered.length === 0 ? (
          <div className="p-12 text-center" style={{ backgroundColor: "#141b2b" }}>
            <span className="material-symbols-outlined" style={{ fontSize: "52px", color: "#2e3545" }}>manage_history</span>
            <p className="font-body-sm text-body-sm text-on-surface-variant mt-3">
              No audit snapshots match this view. Run a Smart Contract Audit to save a new history row.
            </p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left" style={{ borderCollapse: "collapse", minWidth: "980px" }}>
              <thead style={{ backgroundColor: "#070e1d", borderBottom: "1px solid #424754" }}>
                <tr>
                  {["Audit ID", "File", "Date", "Risk", "ML Prediction", "Static Status", "Slither", "Fix", "Status"].map((h) => (
                    <th key={h} className="px-5 py-3 font-label-caps text-label-caps text-on-surface-variant">
                      {h}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {filtered.map((audit) => {
                  const color = riskColor(audit.risk_score);
                  return (
                    <tr
                      key={`${audit.id}-${audit.timestamp}-${audit.file}`}
                      className="transition-colors hover:bg-surface-container-highest"
                      style={{ borderTop: "1px solid #424754" }}
                    >
                      <td className="px-5 py-4 font-code-sm text-code-sm" style={{ color: "#adc6ff" }}>{audit.id}</td>
                      <td className="px-5 py-4 font-code-sm text-code-sm text-on-surface">{audit.file}</td>
                      <td className="px-5 py-4 font-code-sm text-code-sm text-on-surface-variant">{formatDate(audit.timestamp)}</td>
                      <td className="px-5 py-4">
                        <div className="flex items-center gap-2">
                          <span className="font-bold" style={{ color, fontSize: "16px" }}>{audit.risk_score}</span>
                          <span className="font-label-caps px-1.5 py-0.5 rounded" style={{ fontSize: "9px", color, backgroundColor: `${color}15` }}>
                            {riskLabel(audit)}
                          </span>
                        </div>
                      </td>
                      <td className="px-5 py-4 font-code-sm text-code-sm text-on-surface">{audit.ml_prediction}</td>
                      <td className="px-5 py-4 font-body-sm text-body-sm text-on-surface-variant" style={{ maxWidth: "280px" }}>{audit.static_status}</td>
                      <td className="px-5 py-4">
                        <span className="font-label-caps px-2 py-0.5 rounded" style={{ fontSize: "10px", backgroundColor: "#2e3545", color: "#c2c6d6" }}>
                          {audit.slither_findings}
                        </span>
                      </td>
                      <td className="px-5 py-4">
                        <span
                          className="font-label-caps px-2 py-0.5 rounded"
                          style={{ fontSize: "10px", backgroundColor: audit.fix_included ? "rgba(76,215,246,0.1)" : "#2e3545", color: audit.fix_included ? "#4cd7f6" : "#8c909f" }}
                        >
                          {audit.fix_included ? "YES" : "NO"}
                        </span>
                      </td>
                      <td className="px-5 py-4">
                        <span className="font-label-caps px-2 py-0.5 rounded" style={{ fontSize: "10px", ...(statusColor[audit.status] ?? statusColor.COMPLETE) }}>
                          {audit.status}
                        </span>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
