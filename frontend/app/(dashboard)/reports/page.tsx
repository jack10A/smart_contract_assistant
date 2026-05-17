"use client";
import { useEffect, useMemo, useState } from "react";
import { listReports, type ReportFile } from "../../lib/api";

const BASE = process.env.NEXT_PUBLIC_BACKEND_URL ?? "http://localhost:7860";

const formatBytes = (bytes: number) => {
  if (!Number.isFinite(bytes)) return "Unknown";
  const units = ["B", "KB", "MB", "GB"];
  let value = bytes;
  let unitIndex = 0;
  while (value >= 1024 && unitIndex < units.length - 1) {
    value /= 1024;
    unitIndex += 1;
  }
  return `${value.toFixed(unitIndex === 0 ? 0 : 1)} ${units[unitIndex]}`;
};

const formatDate = (seconds: number) =>
  new Date(seconds * 1000).toLocaleString(undefined, {
    year: "numeric",
    month: "short",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
  });

const reportColor = (type: string) => {
  const lower = type.toLowerCase();
  if (lower.includes("multi")) return "#ffb4ab";
  if (lower.includes("full")) return "#ffb786";
  return "#4cd7f6";
};

export default function ReportsPage() {
  const [reports, setReports] = useState<ReportFile[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [query, setQuery] = useState("");

  const load = async () => {
    try {
      const response = await listReports();
      setReports(response.reports);
      setError(null);
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : "Could not load reports");
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
    if (!q) return reports;
    return reports.filter((report) => `${report.filename} ${report.type}`.toLowerCase().includes(q));
  }, [reports, query]);

  const totalSize = reports.reduce((sum, report) => sum + report.size, 0);
  const latest = reports[0];

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-start justify-between gap-4 flex-wrap">
        <div>
          <h1 className="font-headline-md text-headline-md text-on-surface">Reports</h1>
          <p className="font-body-sm text-body-sm text-on-surface-variant mt-1">
            {latest ? `Latest: ${latest.filename} - ${formatDate(latest.modified)}` : "Generated PDFs from audit and multi-agent workflows."}
          </p>
        </div>
        <div className="flex items-center gap-2">
          <input
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Search reports"
            className="rounded px-3 py-2 font-code-sm text-on-surface outline-none"
            style={{ backgroundColor: "#191f2f", border: "1px solid #424754", minWidth: "220px", fontSize: "12px" }}
          />
          <button
            onClick={() => {
              setLoading(true);
              setError(null);
              void load();
            }}
            className="px-4 py-2 rounded font-label-caps transition-colors"
            style={{ border: "1px solid #424754", color: "#c2c6d6", fontSize: "10px" }}
          >
            REFRESH
          </button>
        </div>
      </div>

      {error && <div className="p-4 rounded-lg font-body-sm" style={{ backgroundColor: "rgba(255,180,171,0.08)", border: "1px solid rgba(255,180,171,0.3)", color: "#ffb4ab" }}>{error}</div>}

      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        {[
          { label: "Total Reports", value: String(reports.length), color: "#dce2f7" },
          { label: "Visible", value: String(filtered.length), color: "#4cd7f6" },
          { label: "Total Size", value: formatBytes(totalSize), color: "#ffb786" },
          { label: "Latest Type", value: latest?.type ?? "-", color: "#adc6ff" },
        ].map(({ label, value, color }) => (
          <div key={label} className="p-4 rounded-lg" style={{ backgroundColor: "#191f2f", border: "1px solid #424754" }}>
            <p className="font-label-caps text-label-caps text-on-surface-variant">{label}</p>
            <p className="font-headline-sm text-headline-sm mt-1 truncate" style={{ color }}>{value}</p>
          </div>
        ))}
      </div>

      {loading ? (
        <div className="p-8 rounded-lg text-center" style={{ backgroundColor: "#141b2b", border: "1px solid #424754" }}>
          <p className="font-body-sm text-body-sm text-on-surface-variant">Loading generated reports...</p>
        </div>
      ) : filtered.length === 0 ? (
        <div className="flex flex-col items-center gap-4 py-20 rounded-lg" style={{ backgroundColor: "#141b2b", border: "1px solid #424754" }}>
          <span className="material-symbols-outlined" style={{ fontSize: "56px", color: "#2e3545" }}>description</span>
          <p className="font-body-sm text-body-sm text-on-surface-variant text-center max-w-md">
            No reports match this view. Run an audit export or Multi-Agent Investigation to generate PDF reports.
          </p>
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
          {filtered.map((report) => {
            const color = reportColor(report.type);
            const downloadUrl = `${BASE}${report.download_url}`;
            return (
              <div key={report.filename} className="flex flex-col p-5 rounded-lg" style={{ backgroundColor: "#141b2b", border: "1px solid #424754" }}>
                <div className="flex items-start justify-between gap-3 mb-3">
                  <div className="flex items-center gap-3 min-w-0">
                    <div className="w-10 h-10 rounded-lg flex items-center justify-center shrink-0" style={{ backgroundColor: `${color}15`, border: `1px solid ${color}30` }}>
                      <span className="material-symbols-outlined" style={{ fontSize: "20px", color }}>picture_as_pdf</span>
                    </div>
                    <div className="min-w-0">
                      <p className="font-label-caps" style={{ fontSize: "10px", color }}>{report.type}</p>
                      <h3 className="font-headline-sm text-on-surface truncate" style={{ fontSize: "14px" }}>{report.filename}</h3>
                    </div>
                  </div>
                  <span className="font-label-caps px-2 py-0.5 rounded shrink-0" style={{ fontSize: "10px", backgroundColor: "rgba(76,215,246,0.12)", color: "#4cd7f6" }}>READY</span>
                </div>

                <div className="grid grid-cols-2 gap-2 mb-4 py-3" style={{ borderTop: "1px solid #2e3545" }}>
                  <div>
                    <p className="font-label-caps text-on-surface-variant" style={{ fontSize: "9px" }}>Modified</p>
                    <p className="font-code-sm text-on-surface" style={{ fontSize: "11px" }}>{formatDate(report.modified)}</p>
                  </div>
                  <div>
                    <p className="font-label-caps text-on-surface-variant" style={{ fontSize: "9px" }}>Size</p>
                    <p className="font-code-sm text-on-surface" style={{ fontSize: "11px" }}>{formatBytes(report.size)}</p>
                  </div>
                </div>

                <div className="flex gap-2 mt-auto">
                  <a href={downloadUrl} download className="flex-1 flex items-center justify-center gap-1.5 py-2 rounded font-label-caps transition-all active:scale-95" style={{ backgroundColor: "#adc6ff", color: "#002e6a", fontSize: "10px" }}>
                    <span className="material-symbols-outlined" style={{ fontSize: "14px" }}>download</span>
                    DOWNLOAD
                  </a>
                  <a href={downloadUrl} target="_blank" rel="noreferrer" className="px-3 py-2 rounded font-label-caps transition-colors" style={{ border: "1px solid #424754", color: "#c2c6d6", fontSize: "10px" }}>
                    VIEW
                  </a>
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
