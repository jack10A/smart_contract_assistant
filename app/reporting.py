import os
import re
import json
import textwrap
from datetime import datetime
from glob import glob
from typing import Iterable

import matplotlib

matplotlib.use("Agg")

import matplotlib.image as mpimg
import matplotlib.pyplot as plt
from matplotlib.backends.backend_pdf import PdfPages


REPORT_DIR = os.path.join("workspace_uploads", "reports")
PLOT_DIR = os.path.join("workspace_uploads", "plots")
AUDIT_HISTORY_PATH = os.path.join("workspace_uploads", "audit_history.json")


def _clean_markdown(text: str | None) -> str:
    if not text:
        return "No content available."

    cleaned = re.sub(r"```[\w-]*", "", text)
    cleaned = cleaned.replace("```", "")
    cleaned = re.sub(r"[*_#>`]", "", cleaned)
    cleaned = re.sub(r"\n{3,}", "\n\n", cleaned)
    return cleaned.strip() or "No content available."


def _wrap_lines(text: str, width: int = 92, max_lines: int = 42) -> list[str]:
    lines: list[str] = []
    for paragraph in _clean_markdown(text).splitlines():
        if not paragraph.strip():
            lines.append("")
            continue
        wrapped = textwrap.wrap(
            paragraph,
            width=width,
            subsequent_indent="  " if paragraph.startswith("- ") else "",
        )
        lines.extend(wrapped or [""])
    if len(lines) > max_lines:
        return lines[: max_lines - 1] + ["..."]
    return lines


def _add_text_page(pdf: PdfPages, title: str, body: str, subtitle: str | None = None) -> None:
    fig = plt.figure(figsize=(8.27, 11.69))
    fig.patch.set_facecolor("white")
    plt.axis("off")

    y = 0.94
    fig.text(0.08, y, title, fontsize=20, fontweight="bold", color="#111827")
    y -= 0.035
    if subtitle:
        fig.text(0.08, y, subtitle, fontsize=10, color="#4b5563")
        y -= 0.035

    for line in _wrap_lines(body):
        fig.text(0.08, y, line, fontsize=9.5, color="#111827", family="monospace" if "|" in line else None)
        y -= 0.018
        if y < 0.06:
            break

    pdf.savefig(fig, bbox_inches="tight")
    plt.close(fig)


def _latest_plot_paths(limit: int = 6) -> list[str]:
    if not os.path.exists(PLOT_DIR):
        return []
    paths = [path for path in glob(os.path.join(PLOT_DIR, "*.png")) if os.path.isfile(path)]
    return sorted(paths, key=os.path.getmtime, reverse=True)[:limit]


def _add_plot_pages(pdf: PdfPages, plot_paths: Iterable[str]) -> None:
    paths = list(plot_paths)
    if not paths:
        _add_text_page(pdf, "CSV Anomaly Plots", "No CSV plots were found. Run CSV anomaly detection first.")
        return

    for start in range(0, len(paths), 2):
        chunk = paths[start:start + 2]
        fig, axes = plt.subplots(len(chunk), 1, figsize=(8.27, 11.69))
        if len(chunk) == 1:
            axes = [axes]
        fig.patch.set_facecolor("white")
        fig.suptitle("CSV Anomaly Plots", fontsize=18, fontweight="bold", color="#111827", y=0.98)

        for axis, path in zip(axes, chunk):
            image = mpimg.imread(path)
            axis.imshow(image)
            axis.set_title(os.path.basename(path), fontsize=9, color="#4b5563")
            axis.axis("off")

        fig.tight_layout(rect=(0.04, 0.03, 0.96, 0.95))
        pdf.savefig(fig, bbox_inches="tight")
        plt.close(fig)


def _executive_summary(
    selected_file: str | None,
    audit_text: str | None,
    csv_text: str | None,
    fix_text: str | None,
    investigation_summary: str | None = None,
) -> str:
    audit_available = bool(audit_text and "Upload a Solidity file" not in audit_text)
    csv_available = bool(
        csv_text
        and (
            "CSV summary" in csv_text
            or "Risk score" in csv_text
            or "Consensus anomaly rows" in csv_text
        )
    )
    fix_available = bool(fix_text and "Generate a fix after" not in fix_text)

    bullets = [
        f"Active workspace focus: {selected_file or 'Not selected'}",
        f"Code audit included: {'Yes' if audit_available else 'No'}",
        f"CSV anomaly analysis included: {'Yes' if csv_available else 'No'}",
        f"Automated fix guidance included: {'Yes' if fix_available else 'No'}",
        "Use this report as an executive snapshot. Validate all security-critical findings before production deployment.",
    ]
    if investigation_summary:
        bullets.insert(1, f"Multi-agent investigation summary: {investigation_summary}")
    return "\n\n".join(f"- {bullet}" for bullet in bullets)


def generate_executive_report(
    selected_file: str | None,
    risk_dashboard_text: str | None,
    audit_text: str | None,
    fix_text: str | None,
    csv_analysis_text: str | None,
    csv_explanation_text: str | None,
    investigation_summary_text: str | None = None,
) -> str:
    """Create a multi-page PDF report from the current audit workspace outputs."""
    os.makedirs(REPORT_DIR, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_name = re.sub(r"[^A-Za-z0-9_.-]+", "_", selected_file or "workspace")
    report_path = os.path.join(REPORT_DIR, f"{safe_name}_executive_report_{timestamp}.pdf")

    subtitle = f"Generated {datetime.now().strftime('%Y-%m-%d %H:%M')}"
    with PdfPages(report_path) as pdf:
        _add_text_page(
            pdf,
            "Executive Security Report",
            _executive_summary(
                selected_file,
                audit_text,
                csv_analysis_text,
                fix_text,
                investigation_summary_text,
            ),
            subtitle=subtitle,
        )
        if investigation_summary_text:
            _add_text_page(pdf, "Multi-Agent Investigation Summary", investigation_summary_text)
        _add_text_page(pdf, "Hybrid Risk Dashboard", risk_dashboard_text or "No risk dashboard is available.")
        _add_text_page(pdf, "CodeBERT Vulnerability Results", audit_text or "No Solidity audit has been run.")
        _add_text_page(pdf, "CSV Anomaly Summary", csv_analysis_text or "No CSV anomaly analysis has been run.")
        _add_plot_pages(pdf, _latest_plot_paths())
        _add_text_page(pdf, "Explainable Anomaly Notes", csv_explanation_text or "No explanation was generated.")
        _add_text_page(pdf, "Automated Fix Suggestions", fix_text or "No automated fix suggestion has been generated.")

    return report_path


def _extract_first(pattern: str, text: str | None, default: str = "Unknown") -> str:
    if not text:
        return default
    match = re.search(pattern, text, flags=re.IGNORECASE)
    return match.group(1).strip() if match else default


def _extract_slither_count(audit_text: str | None) -> int:
    value = _extract_first(r"Findings:\s*(\d+)", audit_text, default="0")
    try:
        return int(value)
    except ValueError:
        return 0


def _load_audit_history() -> list[dict]:
    if not os.path.exists(AUDIT_HISTORY_PATH):
        return []
    try:
        with open(AUDIT_HISTORY_PATH, "r", encoding="utf-8") as history_file:
            data = json.load(history_file)
        return data if isinstance(data, list) else []
    except (OSError, json.JSONDecodeError):
        return []


def record_audit_snapshot(
    selected_file: str | None,
    risk_dashboard_text: str | None,
    audit_text: str | None,
    fix_text: str | None,
    patch_diff_text: str | None,
) -> str:
    """Persist a compact audit snapshot for history tracking."""
    os.makedirs(os.path.dirname(AUDIT_HISTORY_PATH), exist_ok=True)
    history = _load_audit_history()
    entry = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "file": selected_file or "No file selected",
        "risk_score": _extract_first(r"Risk score:\*\*\s*\*\*(\d+/100)", risk_dashboard_text),
        "risk_level": _extract_first(r"Risk level:\*\*\s*\*\*([A-Za-z]+)", risk_dashboard_text),
        "ml_prediction": _extract_first(r"Deep learning prediction:\s*\*\*([^*]+)", risk_dashboard_text),
        "ml_interpretation": _extract_first(r"ML interpretation:\s*\*\*([^*]+)", risk_dashboard_text),
        "static_status": _extract_first(r"Static analysis status:\s*\*\*([^*]+)", risk_dashboard_text),
        "slither_findings": _extract_slither_count(audit_text),
        "fix_included": bool(fix_text and "Generate a fix after" not in fix_text),
        "patch_included": bool(patch_diff_text and "---" in patch_diff_text and "+++" in patch_diff_text),
    }
    history.append(entry)
    history = history[-50:]
    with open(AUDIT_HISTORY_PATH, "w", encoding="utf-8") as history_file:
        json.dump(history, history_file, indent=2)
    return f"Saved audit snapshot for `{entry['file']}` at {entry['timestamp']}."


def format_audit_history_markdown(limit: int = 12) -> str:
    """Render recent audit snapshots as a Markdown table."""
    history = list(reversed(_load_audit_history()))[:limit]
    if not history:
        return "### Audit History\n\nNo audit snapshots saved yet."

    rows = [
        "### Audit History",
        "",
        "| Time | File | Risk | ML prediction | Static status | Slither findings | Fix |",
        "|---|---|---|---|---|---:|---|",
    ]
    for entry in history:
        fix_status = "Yes" if entry.get("fix_included") else "No"
        rows.append(
            "| "
            f"{entry.get('timestamp', '-')} | "
            f"`{entry.get('file', '-')}` | "
            f"{entry.get('risk_score', 'Unknown')} {entry.get('risk_level', '')} | "
            f"{entry.get('ml_prediction', 'Unknown')} | "
            f"{entry.get('static_status', 'Unknown')} | "
            f"{entry.get('slither_findings', 0)} | "
            f"{fix_status} |"
        )
    return "\n".join(rows)


def generate_full_audit_report(
    selected_file: str | None,
    risk_dashboard_text: str | None,
    audit_text: str | None,
    fix_text: str | None,
    line_map_text: str | None,
    patch_diff_text: str | None,
    csv_analysis_text: str | None,
    csv_explanation_text: str | None,
) -> str:
    """Create a full technical PDF report for the current workspace state."""
    os.makedirs(REPORT_DIR, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_name = re.sub(r"[^A-Za-z0-9_.-]+", "_", selected_file or "workspace")
    report_path = os.path.join(REPORT_DIR, f"{safe_name}_full_audit_report_{timestamp}.pdf")

    subtitle = f"Generated {datetime.now().strftime('%Y-%m-%d %H:%M')}"
    with PdfPages(report_path) as pdf:
        _add_text_page(
            pdf,
            "Full Audit Report",
            _executive_summary(selected_file, audit_text, csv_analysis_text, fix_text),
            subtitle=subtitle,
        )
        _add_text_page(pdf, "Final Risk Dashboard", risk_dashboard_text or "No risk dashboard is available.")
        _add_text_page(pdf, "ML and Slither Audit", audit_text or "No Solidity audit has been run.")
        _add_text_page(pdf, "Line-Level Finding Map", line_map_text or "No line map is available.")
        _add_text_page(pdf, "Generated Fix and Re-audit", fix_text or "No generated fix is available.")
        _add_text_page(pdf, "Patch Diff", patch_diff_text or "No patch diff is available.")
        _add_text_page(pdf, "CSV Anomaly Summary", csv_analysis_text or "No CSV anomaly analysis has been run.")
        _add_plot_pages(pdf, _latest_plot_paths())
        _add_text_page(pdf, "Explainable Anomaly Notes", csv_explanation_text or "No explanation was generated.")
        _add_text_page(pdf, "Recent Audit History", format_audit_history_markdown())

    return report_path
