import base64
import html
import os
import re
import shutil

import gradio as gr
from langchain_core.messages import AIMessage, HumanMessage
from langchain_core.output_parsers import StrOutputParser
from langchain_core.prompts import ChatPromptTemplate
from langchain_groq import ChatGroq

from app.chain import get_smart_contract_chain
from app.classifier.predict import vulnerability_auditor
from app.csv_anomaly import (
    analyze_csv_dl,
    explain_anomalies_with_llama,
    format_local_anomaly_explanations,
    save_analysis_report_to_workspace,
)
from app.evaluation import run_evaluation
from app.function_analysis import analyze_functions_with_classifier, format_function_analysis_markdown
from app.guardrails import check_query
from app.image_analysis import analyze_security_image, format_image_analysis_markdown
from app.ingestion import ALL_FILES_LABEL, get_retriever, get_workspace_files, process_document
from app.reporting import (
    format_audit_history_markdown,
    generate_executive_report,
    generate_full_audit_report,
    record_audit_snapshot,
)
from app.security_analysis import (
    format_line_map_markdown,
    format_risk_dashboard_markdown,
    load_contract_views,
    render_diff_markdown,
)
from app.slither_analysis import format_slither_reaudit_report, format_slither_report, run_slither_analysis
from app.summarization import summarize_document
from app.trace_analysis import analyze_trace_json, correlate_trace_with_audit, format_trace_analysis_markdown

# ---------------------------------------------------------------------------
# Storage and LLM
# ---------------------------------------------------------------------------

UPLOAD_DIR = "./workspace_uploads"
FIXED_DIR = os.path.join(UPLOAD_DIR, "fixed")
ASSETS_DIR = os.path.join(os.path.dirname(__file__), "assets")
LOGO_PATH = os.path.join(ASSETS_DIR, "chainsentinel-ai-logo.png")
LOGO_MARK_PATH = os.path.join(ASSETS_DIR, "chainsentinel-ai-mark.png")
os.makedirs(UPLOAD_DIR, exist_ok=True)
os.makedirs(FIXED_DIR, exist_ok=True)
os.makedirs(ASSETS_DIR, exist_ok=True)
SELECT_ALL_FILES_LABEL = "All Files"
FILE_TYPE_GROUPS = {
    "sol": "Solidity",
    "pdf": "Documents",
    "doc": "Documents",
    "txt": "Documents",
    "csv": "CSV",
    "json": "JSON",
    "image": "Images",
}
FILE_GROUP_ORDER = ["Solidity", "Documents", "CSV", "JSON", "Images", "Other"]
FILE_TYPE_BADGES = {
    "sol": "SOL",
    "pdf": "PDF",
    "doc": "DOC",
    "txt": "TXT",
    "csv": "CSV",
    "json": "JSON",
    "image": "IMG",
}
FILE_SECTION_DEFS = [
    ("solidity", "Solidity", ("sol",)),
    ("documents", "Documents", ("pdf", "doc", "txt")),
    ("csv", "CSV", ("csv",)),
    ("json", "JSON", ("json",)),
    ("images", "Images", ("image",)),
    ("other", "Other", ("unknown",)),
]

fix_llm = ChatGroq(
    groq_api_key=os.getenv("GROQ_API_KEY"),
    model_name="llama-3.3-70b-versatile",
    temperature=0.1,
)


def get_image_data_uri(path: str) -> str:
    try:
        with open(path, "rb") as image_file:
            encoded = base64.b64encode(image_file.read()).decode("ascii")
        return f"data:image/png;base64,{encoded}"
    except Exception:
        return ""

# ---------------------------------------------------------------------------
# File helpers
# ---------------------------------------------------------------------------


def detect_file_type(filename: str) -> str:
    ext = filename.lower()
    if ext.endswith(".sol"):
        return "sol"
    if ext.endswith(".csv"):
        return "csv"
    if ext.endswith(".json"):
        return "json"
    if ext.endswith((".png", ".jpg", ".jpeg", ".webp")):
        return "image"
    if ext.endswith(".pdf"):
        return "pdf"
    if ext.endswith(".docx") or ext.endswith(".doc"):
        return "doc"
    if ext.endswith(".txt"):
        return "txt"
    return "unknown"


def get_updated_choices():
    files = get_workspace_file_choices()
    if not files:
        return gr.update(choices=[], value=None)
    selected = ALL_FILES_LABEL if ALL_FILES_LABEL in files else files[-1]
    return gr.update(choices=files, value=selected)


def get_workspace_file_choices():
    indexed_files = set(get_workspace_files())
    uploaded_files = set()
    if os.path.exists(UPLOAD_DIR):
        uploaded_files = {
            name
            for name in os.listdir(UPLOAD_DIR)
            if os.path.isfile(os.path.join(UPLOAD_DIR, name))
            and detect_file_type(name) in ("sol", "pdf", "doc", "txt", "csv", "json", "image")
        }
    files = sorted(indexed_files | uploaded_files)
    return [ALL_FILES_LABEL, *files] if files else []


def get_investigation_file_choices():
    return [name for name in get_workspace_file_choices() if name != ALL_FILES_LABEL]


def get_investigation_dropdown_choices():
    files = get_investigation_file_choices()
    if not files:
        return []
    choices = [(SELECT_ALL_FILES_LABEL, SELECT_ALL_FILES_LABEL)]
    grouped_files = {}
    for name in files:
        file_type = detect_file_type(name)
        group = FILE_TYPE_GROUPS.get(file_type, "Other files")
        grouped_files.setdefault(group, []).append(name)

    for group in FILE_GROUP_ORDER:
        if group not in grouped_files:
            continue
        choices.append((f"-- {group} --", f"__group__{group}"))
        for name in grouped_files[group]:
            file_type = detect_file_type(name)
            badge = FILE_TYPE_BADGES.get(file_type, file_type.upper())
            choices.append((f"{badge}  {name}", name))
    return choices


def get_investigation_choices_for_types(file_types: tuple[str, ...]):
    choices = []
    for name in get_investigation_file_choices():
        if detect_file_type(name) in file_types:
            choices.append((name, name))
    return choices


def get_workspace_choices_for_types(file_types: tuple[str, ...]):
    choices = []
    for name in get_investigation_file_choices():
        if detect_file_type(name) in file_types:
            choices.append((name, name))
    return choices


def get_workspace_picker_updates(selected_file=None):
    selected_type = detect_file_type(selected_file) if selected_file and selected_file != ALL_FILES_LABEL else None
    return [
        gr.update(choices=[(ALL_FILES_LABEL, ALL_FILES_LABEL)], value=ALL_FILES_LABEL if selected_file == ALL_FILES_LABEL else None),
        gr.update(choices=get_workspace_choices_for_types(("sol",)), value=selected_file if selected_type == "sol" else None),
        gr.update(choices=get_workspace_choices_for_types(("pdf", "doc", "txt")), value=selected_file if selected_type in ("pdf", "doc", "txt") else None),
        gr.update(choices=get_workspace_choices_for_types(("csv",)), value=selected_file if selected_type == "csv" else None),
        gr.update(choices=get_workspace_choices_for_types(("json",)), value=selected_file if selected_type == "json" else None),
        gr.update(choices=get_workspace_choices_for_types(("image",)), value=selected_file if selected_type == "image" else None),
        gr.update(choices=get_workspace_choices_for_types(("unknown",)), value=selected_file if selected_type == "unknown" else None),
    ]


def get_auto_investigator_choice_updates():
    return [
        gr.update(choices=[(SELECT_ALL_FILES_LABEL, SELECT_ALL_FILES_LABEL)], value=[]),
        gr.update(choices=get_investigation_choices_for_types(("sol",)), value=[]),
        gr.update(choices=get_investigation_choices_for_types(("pdf", "doc", "txt")), value=[]),
        gr.update(choices=get_investigation_choices_for_types(("csv",)), value=[]),
        gr.update(choices=get_investigation_choices_for_types(("json",)), value=[]),
        gr.update(choices=get_investigation_choices_for_types(("image",)), value=[]),
        gr.update(choices=get_investigation_choices_for_types(("unknown",)), value=[]),
    ]


def update_auto_investigator_file_picker(scope):
    if scope == "Select files":
        return (
            gr.update(visible=True),
            *get_auto_investigator_choice_updates(),
            gr.update(value=file_selection_summary_html(), visible=True),
        )
    return (
        gr.update(visible=False),
        *get_auto_investigator_choice_updates(),
        gr.update(value="", visible=False),
    )


def _flatten_selected_files(*groups):
    selected_files = []
    for group in groups:
        selected_files.extend(group or [])
    selected_files = [
        name
        for name in selected_files
        if not str(name).startswith("__group__")
    ]
    return selected_files


def file_selection_summary_html(*groups):
    selected_files = _flatten_selected_files(*groups)
    if SELECT_ALL_FILES_LABEL in selected_files:
        files = get_investigation_file_choices()
        return f'<div class="selection-summary"><strong>All files selected</strong><span>{len(files)} workspace files will be included.</span></div>'
    if not selected_files:
        return '<div class="selection-summary muted"><strong>No files selected</strong><span>Choose one or more files from the list.</span></div>'

    counts = {}
    for name in selected_files:
        file_type = detect_file_type(name).upper()
        counts[file_type] = counts.get(file_type, 0) + 1
    parts = ", ".join(f"{count} {file_type}" for file_type, count in sorted(counts.items()))
    return f'<div class="selection-summary"><strong>{len(selected_files)} files selected</strong><span>{html.escape(parts)}</span></div>'


def choose_workspace_file(selected_file):
    if not selected_file:
        return tuple(gr.update() for _ in range(27))
    return (selected_file, *show_selected_file(selected_file))


def _short_name(filename: str, limit: int = 42) -> str:
    return filename if len(filename) <= limit else f"{filename[: limit - 3]}..."


def _format_bytes(size: int | None) -> str:
    if size is None:
        return "Unknown"
    units = ["B", "KB", "MB", "GB"]
    value = float(size)
    for unit in units:
        if value < 1024 or unit == units[-1]:
            return f"{value:.1f} {unit}" if unit != "B" else f"{int(value)} {unit}"
        value /= 1024
    return "Unknown"


def _file_stats(filename: str) -> dict:
    path = os.path.join(UPLOAD_DIR, filename)
    if not os.path.exists(path):
        return {"size": None, "lines": None, "path": path}

    size = os.path.getsize(path)
    lines = None
    if detect_file_type(filename) in ("sol", "txt"):
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                lines = sum(1 for _ in f)
        except Exception:
            lines = None

    return {"size": size, "lines": lines, "path": path}


def _workflow_steps(file_type: str) -> list[tuple[str, str]]:
    if file_type == "sol":
        return [
            ("1", "Review the automatic audit report."),
            ("2", "Ask the chat about risky functions or modifiers."),
            ("3", "Generate a fix only after confirming the finding."),
        ]
    if file_type in ("pdf", "doc", "txt"):
        return [
            ("1", "Generate a summary to map the document."),
            ("2", "Ask chat for source-backed answers."),
            ("3", "Run evaluation questions for retrieval quality."),
        ]
    return [
        ("1", "Upload a supported file."),
        ("2", "Select it from the workspace."),
        ("3", "Use the relevant analysis tab."),
    ]


# ---------------------------------------------------------------------------
# UI HTML
# ---------------------------------------------------------------------------

EMPTY_PANEL = """
<div class="empty-state">
  <div class="empty-icon">+</div>
  <div class="empty-title">No active file</div>
  <div class="empty-copy">Upload or select a workspace file to begin.</div>
</div>
"""


def get_chat_header_html(selected_file: str | None = None) -> str:
    if selected_file:
        if selected_file == ALL_FILES_LABEL:
            hint = "Workspace-wide chat"
            subtitle = "Questions will search every indexed contract, document, and CSV anomaly report in the workspace."
        else:
            file_type = detect_file_type(selected_file)
            labels = {
                "sol": "Solidity audit chat",
                "pdf": "PDF document chat",
                "doc": "Word document chat",
                "txt": "Text document chat",
                "csv": "CSV anomaly chat",
                "json": "JSON trace analysis",
                "image": "Image security analysis",
            }
            hint = labels.get(file_type, "Workspace chat")
            subtitle = f"Questions will use retrieved context from {_short_name(selected_file, 54)}."
    else:
        hint = "Select a file first"
        subtitle = "Ask precise questions about the selected file. Answers are constrained to retrieved context and include the project disclaimer."

    return f"""
<div class="chat-head">
  <div>
    <div class="chat-title">Source-grounded workspace chat</div>
    <div class="chat-subtitle">{html.escape(subtitle)}</div>
  </div>
  <div class="chat-hint">{html.escape(hint)}</div>
</div>
"""


def _badge(label: str, tone: str = "neutral") -> str:
    return f'<span class="badge {tone}">{html.escape(label)}</span>'


def _tool_card(title: str, body: str, icon: str) -> str:
    return f"""
<div class="tool-card">
  <div class="tool-icon">{icon}</div>
  <div>
    <div class="tool-title">{html.escape(title)}</div>
    <div class="tool-copy">{html.escape(body)}</div>
  </div>
</div>
"""


def _stat_card(label: str, value: str) -> str:
    return f"""
<div class="mini-card">
  <div class="mini-label">{html.escape(label)}</div>
  <div class="mini-value">{html.escape(value)}</div>
</div>
"""


def _workflow_html(file_type: str) -> str:
    steps = "".join(
        f"""
<div class="workflow-step">
  <div class="step-index">{html.escape(index)}</div>
  <div>{html.escape(label)}</div>
</div>
"""
        for index, label in _workflow_steps(file_type)
    )
    return f'<div class="workflow-steps">{steps}</div>'


def get_available_actions_html(file_type: str, filename: str) -> str:
    safe_name = html.escape(_short_name(filename))
    stats = _file_stats(filename)

    if file_type == "sol":
        badge = _badge("Solidity", "solidity")
        focus = "Security analysis, code questions, exploit reasoning, and patch generation."
        tools = [
            ("Audit", "Scan for reentrancy, timestamp, overflow, and access risks.", "S"),
            ("Fix", "Generate a patched contract with a concise explanation.", "F"),
            ("Chat", "Ask targeted questions about functions and behavior.", "Q"),
            ("Summary", "Get a compact contract structure and intent overview.", "D"),
        ]
    elif file_type in ("pdf", "doc", "txt"):
        labels = {"pdf": "PDF", "doc": "Word", "txt": "Text"}
        badge = _badge(labels[file_type], "documents")
        focus = "Document-grounded chat, executive summaries, and retrieval quality checks."
        tools = [
            ("Chat", "Ask questions against the uploaded content.", "Q"),
            ("Summary", "Create an executive summary of the full document.", "D"),
            ("Citations", "Use retrieved context for grounded answers.", "C"),
            ("Evaluation", "Run quality checks from the Advanced tab.", "E"),
        ]
    elif file_type == "csv":
        badge = _badge("CSV", "csv")
        focus = "Deep learning anomaly detection with autoencoder reconstruction and Isolation Forest agreement."
        tools = [
            ("Autoencoder", "Train a PyTorch model on numeric columns.", "A"),
            ("Baseline", "Compare against Isolation Forest for small tabular files.", "B"),
            ("Plot", "Save a reconstruction error distribution chart.", "P"),
            ("Explain", "Use Llama to describe suspicious numeric deviations.", "L"),
        ]
    elif file_type == "json":
        badge = _badge("JSON", "json")
        focus = "Transaction trace behavior analysis with call-feature anomaly scoring."
        tools = [
            ("Trace", "Flatten nested calls and classify execution behavior.", "T"),
            ("Anomaly", "Score unusual calls with Isolation Forest.", "A"),
            ("Calls", "Summarize value transfers, depth, and risky call types.", "C"),
            ("Link", "Use results alongside Solidity audit findings.", "L"),
        ]
    elif file_type == "image":
        badge = _badge("Image", "images")
        focus = "Screenshot OCR and security-indicator detection for wallet, explorer, and audit screenshots."
        tools = [
            ("OCR", "Extract visible text from screenshots when an OCR engine is available.", "O"),
            ("Entities", "Find addresses and transaction hashes in screenshot text.", "E"),
            ("Risk", "Detect wallet approvals, failed transactions, and phishing language.", "R"),
            ("Link", "Use extracted hashes or functions to guide trace and contract review.", "L"),
        ]
    else:
        return """
<div class="notice danger">
  <strong>Unsupported file type.</strong>
  <span>Use .sol, .pdf, .doc, .docx, .txt, .csv, .json, or image files.</span>
</div>
"""

    cards = "".join(_tool_card(title, body, icon) for title, body, icon in tools)
    line_count = f"{stats['lines']:,}" if stats["lines"] is not None else "N/A"
    stat_cards = "".join(
        [
            _stat_card("File size", _format_bytes(stats["size"])),
            _stat_card("Line count", line_count),
            _stat_card("Indexed status", "Ready"),
        ]
    )
    return f"""
<div class="overview-grid">
  <div class="file-panel active-summary">
    <div class="file-panel-head">
      <div>
        <div class="eyebrow">Active file</div>
        <div class="file-name">{safe_name}</div>
        <div class="file-focus">{html.escape(focus)}</div>
      </div>
      <div>{badge}</div>
    </div>
    <div class="mini-grid">{stat_cards}</div>
  </div>
  <div class="file-panel">
    <div class="eyebrow">Suggested path</div>
    {_workflow_html(file_type)}
  </div>
  <div class="file-panel action-span">
    <div class="eyebrow">Available tools</div>
    <div class="tool-grid">{cards}</div>
  </div>
</div>
"""


def get_all_files_actions_html() -> str:
    files = [name for name in get_workspace_file_choices() if name != ALL_FILES_LABEL]
    file_count = len(files)
    cards = "".join(
        _tool_card(title, body, icon)
        for title, body, icon in [
            ("Cross-file chat", "Ask questions that connect Solidity code, documents, and CSV anomaly reports.", "Q"),
            ("Evidence search", "Retrieve from the full workspace instead of one selected file.", "E"),
            ("CSV context", "Use saved anomaly reports after running CSV detection.", "C"),
            ("Evaluation", "Run RAG checks against the combined workspace.", "R"),
        ]
    )
    stat_cards = "".join(
        [
            _stat_card("Workspace files", str(file_count)),
            _stat_card("Search mode", "All indexed files"),
            _stat_card("Best for", "Cross-file questions"),
        ]
    )
    return f"""
<div class="overview-grid">
  <div class="file-panel active-summary">
    <div class="file-panel-head">
      <div>
        <div class="eyebrow">Active context</div>
        <div class="file-name">{html.escape(ALL_FILES_LABEL)}</div>
        <div class="file-focus">Search across contracts, documents, and generated CSV anomaly reports in one answer.</div>
      </div>
      <div>{_badge("Global", "global")}</div>
    </div>
    <div class="mini-grid">{stat_cards}</div>
  </div>
  <div class="file-panel">
    <div class="eyebrow">Suggested path</div>
    {_workflow_html("all")}
  </div>
  <div class="file-panel action-span">
    <div class="eyebrow">Available tools</div>
    <div class="tool-grid">{cards}</div>
  </div>
</div>
"""


def show_selected_file(selected_file):
    if not selected_file:
        return (
            EMPTY_PANEL,
            "Upload a Solidity file to run the vulnerability audit.",
            gr.update(visible=False),
            get_chat_header_html(),
            gr.update(value=None, visible=False),
            "### Contract Risk Dashboard\n\nSelect a Solidity file to calculate risk.",
            "Generate a fix after an audit finds a vulnerability.",
            "### Line-Level Map\n\nSelect a Solidity file to map findings to source lines.",
            "### Patch Diff\n\nGenerate a fix to compare original and patched code.",
            gr.update(),
            gr.update(),
            gr.update(),
            *get_auto_investigator_choice_updates(),
            *get_workspace_picker_updates(),
        )
    if selected_file == ALL_FILES_LABEL:
        return (
            get_all_files_actions_html(),
            "Select a single Solidity file to run the vulnerability audit.",
            gr.update(visible=False),
            get_chat_header_html(selected_file),
            gr.update(value=None, visible=False),
            "### Contract Risk Dashboard\n\nSelect a single Solidity file to calculate contract risk.",
            "Generate a fix after an audit finds a vulnerability.",
            "### Line-Level Map\n\nSelect a single Solidity file to map findings to source lines.",
            "### Patch Diff\n\nGenerate a fix for a Solidity file to view the diff.",
            gr.update(),
            gr.update(),
            gr.update(),
            *get_auto_investigator_choice_updates(),
            *get_workspace_picker_updates(selected_file),
        )
    file_type = detect_file_type(selected_file)
    audit_md = "This file type does not need a Solidity vulnerability audit."
    risk_md, line_md = load_contract_views(UPLOAD_DIR, selected_file, audit_md)
    if file_type == "sol":
        local_path = os.path.join(UPLOAD_DIR, selected_file)
        try:
            with open(local_path, "r", encoding="utf-8", errors="ignore") as f:
                code = f.read()
            result = vulnerability_auditor.predict(code)
            audit_md = vulnerability_auditor.format_report(result)
            function_md = format_function_analysis_markdown(
                analyze_functions_with_classifier(code, vulnerability_auditor)
            )
            slither_md = format_slither_report(run_slither_analysis(local_path))
            audit_md = f"{audit_md}\n\n---\n\n{function_md}\n\n---\n\n{slither_md}"
            risk_md = format_risk_dashboard_markdown(selected_file, audit_md, code)
            line_md = format_line_map_markdown(code, audit_md)
        except Exception as e:
            audit_md = f"**Audit error:** {e}"
    audit_state = audit_md if file_type == "sol" else gr.update()
    line_state = line_md if file_type == "sol" else gr.update()
    file_state = selected_file if file_type == "sol" else gr.update()
    return (
        get_available_actions_html(file_type, selected_file),
        audit_md,
        gr.update(visible=file_type == "sol"),
        get_chat_header_html(selected_file),
        gr.update(value=None, visible=False),
        risk_md,
        "Generate a fix after an audit finds a vulnerability.",
        line_md,
        "### Patch Diff\n\nGenerate a fix to compare original and patched code.",
        audit_state,
        line_state,
        file_state,
        *get_auto_investigator_choice_updates(),
        *get_workspace_picker_updates(selected_file),
    )


# ---------------------------------------------------------------------------
# Upload Handler
# ---------------------------------------------------------------------------


def smart_upload(file):
    if file is None:
        return (
            "Choose a file first.",
            EMPTY_PANEL,
            "Upload a Solidity file to run the vulnerability audit.",
            gr.update(visible=False),
            gr.update(),
            get_chat_header_html(),
            gr.update(value=None, visible=False),
            "### Contract Risk Dashboard\n\nSelect a Solidity file to calculate risk.",
            "Generate a fix after an audit finds a vulnerability.",
            "### Line-Level Map\n\nSelect a Solidity file to map findings to source lines.",
            "### Patch Diff\n\nGenerate a fix to compare original and patched code.",
            gr.update(),
            gr.update(),
            gr.update(),
            *get_auto_investigator_choice_updates(),
            *get_workspace_picker_updates(),
        )

    filename = os.path.basename(file.name)
    local_path = os.path.join(UPLOAD_DIR, filename)
    shutil.copy(file.name, local_path)

    file_type = detect_file_type(filename)
    actions_html = get_available_actions_html(file_type, filename)
    status = process_document(local_path)
    audit_md = "This file type does not need a Solidity vulnerability audit."
    risk_md = "### Contract Risk Dashboard\n\nRisk scoring is available for Solidity files."
    line_md = "### Line-Level Map\n\nLine mapping is available for Solidity files."
    show_audit = file_type == "sol"

    if file_type == "csv":
        status = f"Done! {filename} is ready for CSV anomaly detection in the Advanced tab."
    elif file_type == "json":
        status = f"Done! {filename} is ready for JSON trace analysis in the Advanced tab."
    elif file_type == "image":
        status = f"Done! {filename} is ready for image security analysis in the Advanced tab."

    if file_type == "sol":
        try:
            with open(local_path, "r", encoding="utf-8", errors="ignore") as f:
                code = f.read()
            result = vulnerability_auditor.predict(code)
            audit_md = vulnerability_auditor.format_report(result)
            function_md = format_function_analysis_markdown(
                analyze_functions_with_classifier(code, vulnerability_auditor)
            )
            slither_md = format_slither_report(run_slither_analysis(local_path))
            audit_md = f"{audit_md}\n\n---\n\n{function_md}\n\n---\n\n{slither_md}"
            risk_md = format_risk_dashboard_markdown(filename, audit_md, code)
            line_md = format_line_map_markdown(code, audit_md)
        except Exception as e:
            audit_md = f"**Audit error:** {e}"
    audit_state = audit_md if file_type == "sol" else gr.update()
    line_state = line_md if file_type == "sol" else gr.update()
    file_state = filename if file_type == "sol" else gr.update()

    return (
        status,
        actions_html,
        audit_md,
        gr.update(visible=show_audit),
        gr.update(choices=get_workspace_file_choices(), value=filename),
        get_chat_header_html(filename),
        gr.update(value=None, visible=False),
        risk_md,
        "Generate a fix after an audit finds a vulnerability.",
        line_md,
        "### Patch Diff\n\nGenerate a fix to compare original and patched code.",
        audit_state,
        line_state,
        file_state,
        *get_auto_investigator_choice_updates(),
        *get_workspace_picker_updates(filename),
    )


# ---------------------------------------------------------------------------
# Security Fix
# ---------------------------------------------------------------------------


def suggest_security_fix(selected_file, audit_result_text, risk_dashboard_text):
    if not selected_file:
        return "No file selected.", gr.update(value=None, visible=False), "### Patch Diff\n\nNo file selected."
    if risk_dashboard_text and "Low-signal override active: **Yes**" in risk_dashboard_text:
        return (
            "This audit is marked as a low-confidence, unconfirmed signal. No automated patch was generated because Slither/source evidence did not strongly confirm the ML prediction.",
            gr.update(value=None, visible=False),
            "### Patch Diff\n\nNo patch generated for a low-signal finding.",
        )
    if (
        risk_dashboard_text
        and "Risk level:** **Low**" in risk_dashboard_text
        and "Slither findings by impact: **High 0, Medium 0" in risk_dashboard_text
    ):
        return (
            "No automated patch was generated because the contract is already Low risk and has no High or Medium Slither findings.",
            gr.update(value=None, visible=False),
            "### Patch Diff\n\nNo patch generated for a low-risk contract with no confirmed High/Medium findings.",
        )
    if any(x in audit_result_text for x in ("Not applicable", "Waiting", "Safe", "does not need")):
        return (
            "No vulnerabilities detected, so there is nothing to fix.",
            gr.update(value=None, visible=False),
            "### Patch Diff\n\nNo generated patch is available.",
        )

    local_path = os.path.join(UPLOAD_DIR, selected_file)
    if not os.path.exists(local_path):
        return (
            f"Source file '{selected_file}' was not found. Please upload it again.",
            gr.update(value=None, visible=False),
            "### Patch Diff\n\nSource file was not found.",
        )

    try:
        with open(local_path, "r", encoding="utf-8", errors="ignore") as f:
            original_code = f.read()
    except Exception as e:
        return f"Error reading file: {e}", gr.update(value=None, visible=False), "### Patch Diff\n\nCould not read source file."

    match = re.search(r"Finding:[\s*]*(?:[\u2600-\u27BF]|[\uD83C-\uD83E][\uDC00-\uDFFF])?\s*(.*)", audit_result_text)
    bug_name = match.group(1).strip().split("\n")[0].replace("*", "") if match else "detected vulnerability"

    fix_prompt = ChatPromptTemplate.from_template(
        """
ROLE: Senior Solidity Security Engineer.
TASK: Refactor the Solidity code below to fix the reported vulnerability.

VULNERABILITY: {bug_name}

FULL AUDIT REPORT:
{audit_report}

RISK DASHBOARD:
{risk_dashboard}

ORIGINAL CODE:
```solidity
{code}
```

INSTRUCTIONS:
1. Identify the root cause of {bug_name}.
2. Fix the deep learning finding AND every High or Medium Slither finding shown in the audit report when possible.
3. If the contract uses delegatecall or arbitrary plugin execution, do NOT replace it with low-level call using user-supplied bytes. Remove that external plugin execution path entirely unless a concrete safe replacement already exists in the original code.
4. For Ether withdrawals, apply Checks-Effects-Interactions exactly: validate first, update all internal state second, make the external value transfer last.
5. Do not use block.timestamp, now, blockhash, or modulo arithmetic as randomness. Remove or redesign any lottery/random function if no secure randomness source is available.
6. Avoid raw .send and avoid arbitrary low-level .call(data). For value transfers, prefer transfer for simple contracts. If you use call{{value: amount}}, you MUST require success AND add a nonReentrant guard or equivalent lock modifier.
7. Never use tx.origin for authorization, contract blocking, or reentrancy prevention.
8. If a reentrancy guard is needed, implement it as a reusable modifier named nonReentrant and apply it directly to the withdrawal function. Do not put the lock logic inline inside the function body.
9. Use Solidity ^0.8.20 unless the original code requires an older compiler. In Solidity 0.8+, write constructor() without public or external visibility.
10. If the risk dashboard says Low-signal override active, do not make unrelated security rewrites. Explain that no confirmed vulnerability needs patching.
11. Do not introduce a new Slither High or Medium finding while fixing another issue. Favor simple code that Slither can re-audit cleanly.
12. Return the fixed code in a ```solidity block followed by a concise explanation.
13. Inside the Solidity code block, do not write comments. Do not include placeholder functions, placeholder examples, unused plugin parameters, or commented-out risky calls.
14. Put security explanation text outside the Solidity code block only.
15. Remove dead code and placeholder examples instead of leaving commented-out risky calls.
"""
    )
    chain = fix_prompt | fix_llm | StrOutputParser()
    fix_result = chain.invoke({
        "bug_name": bug_name,
        "audit_report": audit_result_text,
        "risk_dashboard": risk_dashboard_text or "No risk dashboard provided.",
        "code": original_code,
    })

    code_match = re.search(r"```(?:solidity|sol)?\s*(.*?)```", fix_result, re.DOTALL | re.IGNORECASE)
    fixed_code = code_match.group(1).strip() if code_match else fix_result.strip()
    base_name, _ = os.path.splitext(os.path.basename(selected_file))
    fixed_path = os.path.join(FIXED_DIR, f"{base_name}_fixed.sol")

    try:
        with open(fixed_path, "w", encoding="utf-8") as f:
            f.write(fixed_code)
            f.write("\n")
    except Exception as e:
        diff_md = render_diff_markdown(original_code, fixed_code, selected_file, f"{base_name}_fixed.sol")
        return f"{fix_result}\n\n**Download error:** Could not create fixed file: {e}", gr.update(value=None, visible=False), diff_md

    original_slither = run_slither_analysis(local_path)
    fixed_slither = run_slither_analysis(fixed_path)
    reaudit_md = format_slither_reaudit_report(original_slither, fixed_slither)
    diff_md = render_diff_markdown(original_code, fixed_code, selected_file, os.path.basename(fixed_path))
    return f"{fix_result}\n\n---\n\n{reaudit_md}", gr.update(value=fixed_path, visible=True), diff_md


# ---------------------------------------------------------------------------
# Chat, Summary, Evaluation
# ---------------------------------------------------------------------------


def _history_to_messages(history):
    messages = []
    for msg in history or []:
        if isinstance(msg, dict):
            role = msg.get("role", "user")
            content = msg.get("content", "")
        elif isinstance(msg, (list, tuple)) and len(msg) >= 2:
            role, content = msg[0], msg[1]
        else:
            role, content = getattr(msg, "role", "user"), getattr(msg, "content", str(msg))

        if not content:
            continue
        messages.append(HumanMessage(content=content) if role == "user" else AIMessage(content=content))
    return messages


def chat_response(message, history, selected_file):
    if not message or not message.strip():
        return "Ask a question about the active file."

    is_safe, guard_msg = check_query(message)
    if not is_safe:
        return guard_msg

    retriever = get_retriever(selected_filename=selected_file)
    chain = get_smart_contract_chain(retriever)
    try:
        resp = chain.invoke({"input": message, "chat_history": _history_to_messages(history)})
        return resp.get("answer", "No answer generated.")
    except Exception as e:
        return f"Connection error: {e}"


def chat_submit(message, history, selected_file):
    history = history or []
    if not message or not message.strip():
        return "", history

    answer = chat_response(message.strip(), history, selected_file)
    history = history + [
        {"role": "user", "content": message.strip()},
        {"role": "assistant", "content": answer},
    ]
    return "", history


def set_chat_prompt(prompt):
    return prompt


def clear_chat():
    return "", []


def generate_summary(selected_file):
    if not selected_file:
        return "Select a file from the sidebar first."
    try:
        docs = get_retriever(selected_filename=selected_file, k=50).invoke(
            "Summarize this document's content, structure, clauses, code behavior, and key risks."
        )
        return summarize_document(docs)
    except Exception as e:
        return f"Summarization error: {e}"


def run_eval(questions_text, selected_file):
    if not selected_file:
        return "Select a file from the sidebar first."

    lines = [q.strip() for q in questions_text.splitlines() if q.strip()]
    if not lines:
        return "Enter at least one question."
    try:
        results = run_evaluation([{"question": q} for q in lines], selected_filename=selected_file)
        rows = ["| # | Question | Faithfulness | Relevance | Citations |", "|---|---|---|---|---|"]
        for i, r in enumerate(results, 1):
            if "error" in r:
                rows.append(f"| {i} | {r['question'][:45]} | Error: {r['error']} | - | - |")
                continue
            citations = "Yes" if r.get("citation_coverage") else "No"
            rows.append(
                f"| {i} | {r['question'][:45]} | {r.get('faithfulness', '-')} "
                f"| {r.get('answer_relevance', '-')} | {citations} |"
            )
        return "\n".join(rows)
    except Exception as e:
        return f"Evaluation error: {e}"


def run_csv_anomaly_analysis(selected_file):
    if not selected_file:
        return (
            "Select a CSV file from the sidebar first.",
            *([None] * 7),
            gr.update(value=None, visible=False),
            "",
        )

    if detect_file_type(selected_file) != "csv":
        return (
            "Select a .csv file to run deep learning anomaly detection.",
            *([None] * 7),
            gr.update(value=None, visible=False),
            "",
        )

    local_path = os.path.join(UPLOAD_DIR, selected_file)
    if not os.path.exists(local_path):
        return (
            f"CSV file '{selected_file}' was not found. Please upload it again.",
            *([None] * 7),
            gr.update(value=None, visible=False),
            "",
        )

    try:
        analysis = analyze_csv_dl(local_path)
        report_path = save_analysis_report_to_workspace(local_path, analysis, workspace_dir=UPLOAD_DIR)
        try:
            index_status = process_document(report_path)
        except Exception as index_error:
            index_status = f"Report saved, but indexing skipped: {index_error}"
        summary = analysis["summary"]
        risk = analysis["risk_score"]
        anomaly_rows = analysis["anomaly_details"]
        plot_paths = analysis.get("plot_paths", {})

        anomaly_table = [
            "| Row | Score | Main mathematical deviations |",
            "|---:|---:|---|",
        ]
        if anomaly_rows:
            for item in anomaly_rows:
                deviations = ", ".join(
                    f"{col['column']}={col['value']:.4g} (z={col['z_score']:.2f})"
                    for col in item.get("top_deviating_columns", [])
                )
                anomaly_table.append(
                    f"| {item['row_index']} | {item['anomaly_score']:.6f} | {deviations} |"
                )
        else:
            anomaly_table.append("| - | - | No consensus anomalies found by both models. |")

        rows = [
            "### CSV summary",
            f"- Rows: {summary['rows']}",
            f"- Columns: {summary['columns']}",
            f"- Numeric columns used by model: {summary['numeric_column_count']} ({', '.join(summary['numeric_columns'])})",
            f"- Non-numeric columns ignored: {', '.join(summary['non_numeric_columns']) or 'None'}",
            f"- Missing values by column: `{summary['missing_values']}`",
            "",
            "### Risk score",
            f"- Score: **{risk['score']}/100**",
            f"- Level: **{risk['level']}**",
            f"- Anomaly rate: {risk['anomaly_rate']:.2%}",
            f"- Max score / threshold: {risk['max_score_ratio']:.2f}x",
            "",
            "### Anomalies",
            f"- Consensus anomaly rows: `{analysis['anomalies']}`",
            f"- Autoencoder flagged rows: `{analysis['autoencoder_anomalies']}`",
            f"- Isolation Forest flagged rows: `{analysis['isolation_forest_anomalies']}`",
            "",
            *anomaly_table,
            "",
            "### Artifacts",
            f"- Model saved to: `{analysis['model_path']}`",
            f"- Searchable report saved and indexed: `{os.path.basename(report_path)}`",
            f"- Index status: {index_status}",
        ]
        local_explanation = format_local_anomaly_explanations(analysis, max_rows=10)
        try:
            llm_explanation = explain_anomalies_with_llama(local_path, analysis)
            explanation = f"{local_explanation}\n\n### Llama explanation\n{llm_explanation}"
        except Exception as explain_error:
            explanation = f"{local_explanation}\n\n### Llama explanation\nExplanation unavailable: {explain_error}"
        csv_markdown = "\n".join(rows)
        return (
            csv_markdown,
            plot_paths.get("error_distribution"),
            plot_paths.get("error_by_row"),
            plot_paths.get("top_scores"),
            plot_paths.get("numeric_histograms"),
            plot_paths.get("numeric_boxplot"),
            plot_paths.get("column_means_barplot"),
            plot_paths.get("correlation_heatmap"),
            gr.update(value=analysis["model_path"], visible=True),
            explanation,
        )
    except Exception as e:
        return (
            f"CSV anomaly detection error: {e}",
            *([None] * 7),
            gr.update(value=None, visible=False),
            "",
        )


def run_json_trace_analysis(selected_file):
    if not selected_file:
        return "Select a JSON trace file from the sidebar first."

    if detect_file_type(selected_file) != "json":
        return "Select a .json file to run transaction trace analysis."

    local_path = os.path.join(UPLOAD_DIR, selected_file)
    if not os.path.exists(local_path):
        return f"JSON trace file '{selected_file}' was not found. Please upload it again."

    try:
        return format_trace_analysis_markdown(analyze_trace_json(local_path, abi_dir=UPLOAD_DIR))
    except Exception as e:
        return f"JSON trace analysis error: {e}"


def run_trace_contract_correlation(audit_text, line_map_text, trace_text):
    return correlate_trace_with_audit(audit_text, line_map_text, trace_text)


def run_trace_contract_correlation_from_state(solidity_file, audit_text, line_map_text, trace_text):
    if not audit_text:
        return "### Trace to Contract Correlation\n\nRun a Solidity audit first, then run JSON trace analysis."
    report = correlate_trace_with_audit(audit_text, line_map_text, trace_text)
    return f"**Stored Solidity audit:** `{solidity_file or 'Unknown'}`\n\n{report}"


def correlate_csv_with_contract(solidity_file, audit_text, line_map_text, csv_text, row_number):
    if not audit_text:
        return "### CSV to Contract Correlation\n\nRun a Solidity audit first, then run CSV anomaly detection."
    if not csv_text:
        return "### CSV to Contract Correlation\n\nRun CSV anomaly detection first."

    row_query = str(row_number or "").strip()
    anomaly_match = None
    if row_query:
        pattern = re.compile(rf"\|\s*{re.escape(row_query)}\s*\|\s*([0-9.]+)\s*\|\s*(.*?)\s*\|")
        anomaly_match = pattern.search(csv_text)

    csv_lower = csv_text.lower()
    audit_lower = audit_text.lower()
    line_lower = (line_map_text or "").lower()
    transfer_terms = ["amount", "value", "ether", "eth", "transfer", "withdraw", "send"]
    row_or_report_mentions_transfer = any(term in csv_lower for term in transfer_terms)
    contract_transfer_signals = []

    for line in (line_map_text or "").splitlines():
        stripped = line.strip()
        if any(term in stripped.lower() for term in ("call", "transfer", "send", "withdraw", "payable")):
            contract_transfer_signals.append(stripped)

    likely_functions = []
    for function_name in re.findall(r"`([^`]+)`\s*\|\s*[^|]+\|\s*([^|]+)\|", audit_text):
        name, prediction = function_name
        if "-" in name or name in {"unknown-check"}:
            continue
        pred_lower = prediction.lower()
        if any(term in name.lower() for term in ("withdraw", "send", "transfer")) or "reentrancy" in pred_lower:
            likely_functions.append(name)

    confidence = "Possible match" if row_or_report_mentions_transfer and contract_transfer_signals else "Insufficient direct evidence"
    if anomaly_match and contract_transfer_signals:
        confidence = "Possible behavioral match"

    rows = [
        "### CSV to Contract Correlation",
        "",
        f"**Stored Solidity audit:** `{solidity_file or 'Unknown'}`",
        f"**CSV row requested:** `{row_query or 'Not specified'}`",
        f"**Correlation confidence:** **{confidence}**",
        "",
    ]

    if anomaly_match:
        rows.extend(
            [
                "#### CSV Anomaly Evidence",
                f"- Row `{row_query}` anomaly score: **{anomaly_match.group(1)}**",
                f"- Main deviations: {anomaly_match.group(2) or 'Not listed'}",
                "",
            ]
        )
    elif row_query:
        rows.extend(
            [
                "#### CSV Anomaly Evidence",
                f"- Row `{row_query}` was not found in the displayed consensus anomaly table.",
                "- Run CSV anomaly detection and confirm the row appears in the anomaly output.",
                "",
            ]
        )

    rows.extend(["#### Contract Capability Evidence"])
    if contract_transfer_signals:
        for signal in contract_transfer_signals[:8]:
            rows.append(f"- {signal}")
    else:
        rows.append("- No transfer-capable source lines were found in the current line map.")

    rows.extend(["", "#### Likely Transfer-Capable Functions"])
    if likely_functions:
        for function in sorted(set(likely_functions)):
            rows.append(f"- `{function}`")
    else:
        if any(term in audit_lower for term in ("withdraw", "sendether", "transfer", "call.value", "call{value")):
            rows.append("- The audit text mentions transfer-like behavior, but no function table entry was parsed.")
        else:
            rows.append("- No likely transfer-capable function was parsed from the function-level table.")

    rows.extend(
        [
            "",
            "#### Interpretation",
            "- A CSV anomaly can show unusual value movement, but it does not prove which Solidity function executed unless the CSV includes a function selector, transaction hash, trace, or method name.",
            "- If the row contains a transaction hash, upload the related JSON trace and use trace correlation for stronger evidence.",
        ]
    )
    return "\n".join(rows)


def run_image_security_analysis(selected_file):
    if not selected_file:
        return "Select an image file from the sidebar first."

    if detect_file_type(selected_file) != "image":
        return "Select a .png, .jpg, .jpeg, or .webp image to run screenshot security analysis."

    local_path = os.path.join(UPLOAD_DIR, selected_file)
    if not os.path.exists(local_path):
        return f"Image file '{selected_file}' was not found. Please upload it again."

    try:
        return format_image_analysis_markdown(analyze_security_image(local_path))
    except Exception as e:
        return f"Image analysis error: {e}"


def export_executive_report(selected_file, risk_text, audit_text, fix_text, csv_text, csv_explanation):
    try:
        report_path = generate_executive_report(
            selected_file=selected_file,
            risk_dashboard_text=risk_text,
            audit_text=audit_text,
            fix_text=fix_text,
            csv_analysis_text=csv_text,
            csv_explanation_text=csv_explanation,
        )
        return (
            f"Executive report generated: `{report_path}`",
            gr.update(value=report_path, visible=True),
        )
    except Exception as e:
        return f"Report export error: {e}", gr.update(value=None, visible=False)


def save_audit_snapshot(selected_file, risk_text, audit_text, fix_text, patch_diff_text):
    try:
        status = record_audit_snapshot(selected_file, risk_text, audit_text, fix_text, patch_diff_text)
        return status, format_audit_history_markdown()
    except Exception as e:
        return f"Audit history error: {e}", format_audit_history_markdown()


def refresh_audit_history():
    return format_audit_history_markdown()


def export_full_audit_report(
    selected_file,
    risk_text,
    audit_text,
    fix_text,
    line_map_text,
    patch_diff_text,
    csv_text,
    csv_explanation,
):
    try:
        report_path = generate_full_audit_report(
            selected_file=selected_file,
            risk_dashboard_text=risk_text,
            audit_text=audit_text,
            fix_text=fix_text,
            line_map_text=line_map_text,
            patch_diff_text=patch_diff_text,
            csv_analysis_text=csv_text,
            csv_explanation_text=csv_explanation,
        )
        return f"Full audit report generated: `{report_path}`", gr.update(value=report_path, visible=True)
    except Exception as e:
        return f"Full report export error: {e}", gr.update(value=None, visible=False)


def _severity_class(severity: str | None) -> str:
    value = (severity or "unknown").strip().lower()
    if value in {"critical", "high", "medium", "low", "informational"}:
        return value
    return "unknown"


def _format_confidence(value) -> str:
    try:
        number = float(value)
    except (TypeError, ValueError):
        return "N/A"
    return f"{number:.0%}" if number <= 1 else f"{number:.0f}%"


def _render_finding_cards(findings: list[dict]) -> str:
    if not findings:
        return """
<div class="investigation-card-block empty">
  <div class="card-block-title">Findings</div>
  <div class="card-empty">No structured findings were produced for this run.</div>
</div>
"""

    severity_rank = {"critical": 5, "high": 4, "medium": 3, "low": 2, "informational": 1, "unknown": 0}
    ordered = sorted(
        findings,
        key=lambda finding: severity_rank.get(_severity_class(finding.get("severity")), 0),
        reverse=True,
    )
    cards = []
    for finding in ordered[:8]:
        severity = html.escape(finding.get("severity") or "Unknown")
        severity_class = _severity_class(severity)
        title = html.escape(finding.get("title") or "Untitled finding")
        file_name = html.escape(finding.get("file") or "Workspace")
        category = html.escape(finding.get("category") or finding.get("source_agent") or "Unknown")
        confidence = html.escape(_format_confidence(finding.get("confidence")))
        evidence = finding.get("evidence") or []
        evidence_text = "No evidence attached."
        if evidence:
            first = evidence[0]
            location = first.get("file") or file_name
            if first.get("line"):
                location = f"{location}:{first.get('line')}"
            evidence_text = f"{location} - {first.get('summary', '')}"
        cards.append(
            f"""
<article class="finding-card severity-{severity_class}">
  <div class="finding-card-head">
    <span class="severity-pill">{severity}</span>
    <span class="confidence-pill">{confidence}</span>
  </div>
  <h4>{title}</h4>
  <div class="finding-meta">
    <span>{file_name}</span>
    <span>{category}</span>
  </div>
  <p>{html.escape(evidence_text)}</p>
</article>
"""
        )
    return f"""
<div class="investigation-card-block">
  <div class="card-block-head">
    <div>
      <div class="card-block-kicker">Structured Findings</div>
      <div class="card-block-title">{len(findings)} findings detected</div>
    </div>
  </div>
  <div class="finding-card-grid">{''.join(cards)}</div>
</div>
"""


def _render_attack_replay_cards(cards: list[dict]) -> str:
    if not cards:
        return """
<div class="investigation-card-block empty">
  <div class="card-block-title">Attack Replay</div>
  <div class="card-empty">No supported attack replay path was generated for this run.</div>
</div>
"""

    rendered = []
    for card in cards[:6]:
        severity = html.escape(card.get("severity") or "Unknown")
        severity_class = _severity_class(severity)
        title = html.escape(card.get("title") or "Attack path")
        finding = html.escape(card.get("finding") or "Unknown finding")
        confidence = html.escape(_format_confidence(card.get("confidence")))
        file_name = html.escape(card.get("file") or "Workspace")
        steps = "".join(f"<li>{html.escape(step)}</li>" for step in (card.get("steps") or [])[:5])
        evidence = "".join(
            f"<li>{html.escape((item.get('file') or file_name) + (':' + str(item.get('line')) if item.get('line') else ''))}: {html.escape(item.get('summary') or '')}</li>"
            for item in (card.get("evidence") or [])[:3]
        )
        rendered.append(
            f"""
<article class="attack-card severity-{severity_class}">
  <div class="attack-card-top">
    <span class="severity-pill">{severity}</span>
    <span class="confidence-pill">{confidence}</span>
  </div>
  <h4>{title}</h4>
  <div class="attack-file">{file_name}</div>
  <p class="attack-finding">{finding}</p>
  <div class="attack-section">
    <strong>Attacker goal</strong>
    <p>{html.escape(card.get("attacker_goal") or "")}</p>
  </div>
  <div class="attack-section">
    <strong>Replay steps</strong>
    <ol>{steps}</ol>
  </div>
  <div class="attack-section">
    <strong>Evidence</strong>
    <ul>{evidence or '<li>No evidence attached.</li>'}</ul>
  </div>
  <div class="attack-section break-path">
    <strong>Break the path</strong>
    <p>{html.escape(card.get("fix") or "")}</p>
  </div>
</article>
"""
        )
    return f"""
<div class="investigation-card-block attack-replay-block">
  <div class="card-block-head">
    <div>
      <div class="card-block-kicker">Attack Replay</div>
      <div class="card-block-title">{len(cards)} exploit paths generated</div>
    </div>
  </div>
  <div class="attack-card-grid">{''.join(rendered)}</div>
</div>
"""


def render_investigation_cards(result: dict | None) -> str:
    if not result:
        return ""
    return f"""
<div class="investigation-cards">
  {_render_finding_cards(result.get("findings") or [])}
  {_render_attack_replay_cards(result.get("attack_replay_cards") or [])}
</div>
"""


def run_auto_investigator_ui(
    scope,
    selected_file,
    all_files_selection,
    solidity_files,
    document_files,
    csv_files,
    json_files,
    image_files,
    other_files,
):
    try:
        from app.auto_investigator import run_auto_investigation

        files_to_run = None
        if scope == "Active file only":
            if not selected_file or selected_file == ALL_FILES_LABEL:
                return "Select a single active file, or choose Select files.", "", gr.update(value=None, visible=False)
            files_to_run = [selected_file]
        elif scope == "Select files":
            files_to_run = _flatten_selected_files(
                all_files_selection,
                solidity_files,
                document_files,
                csv_files,
                json_files,
                image_files,
                other_files,
            )
            if SELECT_ALL_FILES_LABEL in files_to_run:
                files_to_run = get_investigation_file_choices()
            if not files_to_run:
                return "Select one or more files in the Files to include list.", "", gr.update(value=None, visible=False)

        result = run_auto_investigation(selected_files=files_to_run)
        report_path = result.get("report_path")
        cards_html = render_investigation_cards(result)
        if report_path:
            return result["summary"], cards_html, gr.update(value=report_path, visible=True)
        return result["summary"], cards_html, gr.update(value=None, visible=False)
    except Exception as e:
        return f"Auto-Investigator error: {e}", "", gr.update(value=None, visible=False)


# ---------------------------------------------------------------------------
# CSS
# ---------------------------------------------------------------------------

CSS = """
:root {
    --bg: #f6f7f9;
    --surface: #ffffff;
    --surface-soft: #f9fafb;
    --line: #d9dee7;
    --line-soft: #e9edf3;
    --text: #111827;
    --muted: #4b5563;
    --accent: #2563eb;
    --accent-soft: #e8f0ff;
    --success: #0f8a52;
    --success-soft: #e7f7ef;
    --danger: #b42318;
    --danger-soft: #fff0ed;
    --radius: 8px;
    --font: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
}

body,
.gradio-container {
    background: var(--bg) !important;
    color: var(--text) !important;
    font-family: var(--font) !important;
}

footer { display: none !important; }
.gradio-container { max-width: 1440px !important; margin: 0 auto !important; }

#app-shell {
    min-height: 100vh;
}

#sidebar {
    background: var(--surface) !important;
    border-right: 1px solid var(--line-soft) !important;
    min-height: 100vh;
    padding: 24px 18px !important;
}

#main {
    padding: 24px 28px 32px !important;
}

.brand {
    display: flex;
    align-items: center;
    gap: 12px;
    margin-bottom: 24px;
}

.brand-mark {
    align-items: center;
    background: var(--surface);
    border: 1px solid var(--line-soft);
    border-radius: 8px;
    display: inline-flex;
    flex: 0 0 54px;
    height: 54px;
    justify-content: center;
    overflow: hidden;
    width: 54px;
}

.brand-logo {
    display: block;
    height: 42px;
    max-width: 42px !important;
    object-fit: contain;
    width: 42px;
}

.brand-title {
    color: var(--text);
    font-size: 18px;
    font-weight: 800;
    line-height: 1.1;
}

.brand-subtitle {
    color: var(--muted);
    font-size: 12px;
    margin-top: 3px;
}

.side-label,
.eyebrow {
    color: var(--muted);
    font-size: 11px;
    font-weight: 700;
    letter-spacing: .08em;
    margin: 18px 0 8px;
    text-transform: uppercase;
}

.hero {
    background: var(--surface);
    border: 1px solid var(--line-soft);
    border-radius: var(--radius);
    display: grid;
    gap: 22px;
    grid-template-columns: minmax(0, 1fr) minmax(320px, 420px);
    margin-bottom: 18px;
    padding: 24px;
}

.hero-kicker {
    align-items: center;
    background: #dcfce7;
    border-radius: 999px;
    color: #008847;
    display: inline-flex;
    font-size: 12px;
    font-weight: 800;
    margin-bottom: 12px;
    padding: 8px 12px;
}

.hero h1 {
    color: var(--text);
    font-size: 28px;
    line-height: 1.2;
    margin: 0 0 8px;
}

.hero p {
    color: var(--muted);
    font-size: 14px;
    line-height: 1.6;
    margin: 0;
    max-width: 720px;
}

.hero-status-grid {
    display: grid;
    gap: 10px;
    grid-template-columns: repeat(2, minmax(0, 1fr));
}

.hero-status-card {
    background: var(--surface-soft);
    border: 1px solid var(--line-soft);
    border-radius: var(--radius);
    padding: 13px 14px;
}

.hero-status-card.primary {
    background: #f8fbff;
    border-color: #cfe0ff;
    grid-column: 1 / -1;
}

.hero-status-card strong {
    color: var(--text);
    display: block;
    font-size: 15px;
    line-height: 1.25;
}

.hero-status-card span {
    color: var(--muted);
    display: block;
    font-size: 12px;
    line-height: 1.35;
    margin-top: 5px;
}

.hero-pill-row {
    display: flex;
    flex-wrap: wrap;
    gap: 6px;
    margin-top: 10px;
}

.hero-pill {
    border-radius: 999px;
    font-size: 11px;
    font-weight: 800;
    padding: 6px 9px;
}

.hero-pill.sol { background: #dcfce7; color: #008847; }
.hero-pill.doc { background: #e8f0ff; color: #2563eb; }
.hero-pill.data { background: #fef3c7; color: #a16207; }
.hero-pill.trace { background: #f3e8ff; color: #7e22ce; }
.hero-pill.img { background: #ffe4e6; color: #be123c; }
}

.empty-state {
    align-items: center;
    background: var(--surface);
    border: 1px dashed var(--line);
    border-radius: var(--radius);
    display: flex;
    flex-direction: column;
    justify-content: center;
    min-height: 210px;
    padding: 28px;
    text-align: center;
}

.empty-icon {
    align-items: center;
    background: var(--accent-soft);
    border-radius: 8px;
    color: var(--accent);
    display: flex;
    font-size: 24px;
    font-weight: 400;
    height: 42px;
    justify-content: center;
    margin-bottom: 12px;
    width: 42px;
}

.empty-title,
.file-name,
.tool-title {
    color: var(--text);
    font-weight: 700;
}

.empty-copy,
.tool-copy {
    color: var(--muted);
    font-size: 13px;
    line-height: 1.45;
    margin-top: 4px;
}

.file-panel {
    background: var(--surface);
    border: 1px solid var(--line-soft);
    border-radius: var(--radius);
    padding: 18px;
}

.overview-grid {
    display: grid;
    gap: 14px;
    grid-template-columns: minmax(0, 1.15fr) minmax(280px, .85fr);
}

.action-span {
    grid-column: 1 / -1;
}

.active-summary {
    min-height: 174px;
}

.file-panel-head {
    align-items: flex-start;
    border-bottom: 1px solid var(--line-soft);
    display: flex;
    justify-content: space-between;
    gap: 16px;
    margin-bottom: 14px;
    padding-bottom: 14px;
}

.file-focus {
    color: var(--muted);
    font-size: 13px;
    line-height: 1.45;
    margin-top: 7px;
    max-width: 620px;
}

.mini-grid {
    display: grid;
    gap: 10px;
    grid-template-columns: repeat(3, minmax(0, 1fr));
}

.mini-card {
    background: var(--surface-soft);
    border: 1px solid var(--line-soft);
    border-radius: var(--radius);
    padding: 12px;
}

.mini-label {
    color: var(--muted);
    font-size: 11px;
    font-weight: 700;
    text-transform: uppercase;
}

.mini-value {
    color: var(--text);
    font-size: 16px;
    font-weight: 800;
    margin-top: 5px;
}

.workflow-steps {
    display: grid;
    gap: 10px;
}

.workflow-step {
    align-items: center;
    background: var(--surface-soft);
    border: 1px solid var(--line-soft);
    border-radius: var(--radius);
    color: var(--text);
    display: flex;
    font-size: 13px;
    gap: 10px;
    line-height: 1.35;
    padding: 11px 12px;
}

.step-index {
    align-items: center;
    background: var(--accent-soft);
    border-radius: 7px;
    color: var(--accent);
    display: flex;
    flex: 0 0 26px;
    font-size: 12px;
    font-weight: 800;
    height: 26px;
    justify-content: center;
}

.tool-grid {
    display: grid;
    gap: 10px;
    grid-template-columns: repeat(2, minmax(0, 1fr));
}

.tool-card {
    align-items: flex-start;
    background: var(--surface-soft);
    border: 1px solid var(--line-soft);
    border-radius: var(--radius);
    display: flex;
    gap: 12px;
    padding: 12px;
}

.tool-icon {
    align-items: center;
    background: var(--text);
    border-radius: 7px;
    color: white;
    display: flex;
    flex: 0 0 28px;
    font-size: 12px;
    font-weight: 800;
    height: 28px;
    justify-content: center;
}

.badge {
    border-radius: 999px;
    display: inline-flex;
    font-size: 12px;
    font-weight: 700;
    padding: 4px 10px;
    white-space: nowrap;
}

.badge.neutral { background: var(--surface-soft); color: var(--muted); }
.badge.info,
.badge.global,
.badge.documents { background: var(--accent-soft); color: var(--accent); }
.badge.success,
.badge.solidity { background: #dcfce7; color: #008847; }
.badge.csv { background: #fef3c7; color: #a16207; }
.badge.json { background: #f3e8ff; color: #7e22ce; }
.badge.images { background: #ffe4e6; color: #be123c; }

.investigation-cards {
    display: grid;
    gap: 18px;
    margin-top: 16px;
}

.investigation-card-block {
    border: 1px solid var(--line-soft);
    border-radius: var(--radius);
    background: var(--surface);
    padding: 16px;
}

.investigation-card-block.empty {
    background: var(--surface-soft);
}

.card-block-head {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 12px;
    margin-bottom: 14px;
}

.card-block-kicker {
    color: var(--muted);
    font-size: 0.78rem;
    font-weight: 800;
    letter-spacing: 0;
    text-transform: uppercase;
}

.card-block-title {
    color: var(--text);
    font-size: 1rem;
    font-weight: 850;
}

.card-empty {
    color: var(--muted);
    font-size: 0.92rem;
    margin-top: 6px;
}

.finding-card-grid,
.attack-card-grid {
    display: grid;
    gap: 12px;
}

.finding-card-grid {
    grid-template-columns: repeat(auto-fit, minmax(230px, 1fr));
}

.attack-card-grid {
    grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
}

.finding-card,
.attack-card {
    border: 1px solid var(--line-soft);
    border-left: 4px solid #94a3b8;
    border-radius: var(--radius);
    background: #fff;
    padding: 14px;
    min-width: 0;
}

.finding-card.severity-critical,
.attack-card.severity-critical,
.finding-card.severity-high,
.attack-card.severity-high {
    border-left-color: var(--danger);
}

.finding-card.severity-medium,
.attack-card.severity-medium {
    border-left-color: #d97706;
}

.finding-card.severity-low,
.attack-card.severity-low {
    border-left-color: var(--success);
}

.finding-card-head,
.attack-card-top {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 8px;
    margin-bottom: 10px;
}

.severity-pill,
.confidence-pill {
    display: inline-flex;
    align-items: center;
    min-height: 24px;
    border-radius: 999px;
    padding: 3px 9px;
    font-size: 0.75rem;
    font-weight: 800;
    line-height: 1;
    white-space: nowrap;
}

.severity-pill {
    background: var(--danger-soft);
    color: var(--danger);
}

.severity-medium .severity-pill {
    background: #fff7ed;
    color: #b45309;
}

.severity-low .severity-pill,
.severity-informational .severity-pill {
    background: var(--success-soft);
    color: var(--success);
}

.confidence-pill {
    background: #eef2ff;
    color: #3730a3;
}

.finding-card h4,
.attack-card h4 {
    color: var(--text);
    font-size: 0.98rem;
    line-height: 1.35;
    margin: 0 0 8px;
}

.finding-meta,
.attack-file {
    display: flex;
    flex-wrap: wrap;
    gap: 6px;
    color: var(--muted);
    font-size: 0.78rem;
    font-weight: 700;
    margin-bottom: 8px;
}

.finding-card p,
.attack-card p,
.attack-card li {
    color: #334155;
    font-size: 0.86rem;
    line-height: 1.45;
}

.attack-finding {
    border-radius: var(--radius);
    background: var(--surface-soft);
    padding: 8px;
    margin: 8px 0 12px;
}

.attack-section {
    border-top: 1px solid var(--line-soft);
    padding-top: 10px;
    margin-top: 10px;
}

.attack-section strong {
    display: block;
    color: var(--text);
    font-size: 0.82rem;
    margin-bottom: 6px;
}

.attack-section ol,
.attack-section ul {
    margin: 0;
    padding-left: 18px;
}

.break-path {
    background: #f8fafc;
    border: 1px solid var(--line-soft);
    border-radius: var(--radius);
    padding: 10px;
}

.notice {
    border-radius: var(--radius);
    display: flex;
    flex-direction: column;
    gap: 4px;
    padding: 14px 16px;
}

.notice.danger {
    background: var(--danger-soft);
    border: 1px solid #ffd5cf;
    color: var(--danger);
}

.panel {
    background: var(--surface);
    border: 1px solid var(--line-soft);
    border-radius: var(--radius);
    max-width: 100%;
    overflow: auto;
    padding: 18px;
}

.panel h3,
.panel h4 {
    letter-spacing: 0 !important;
    line-height: 1.3 !important;
}

.panel table {
    display: block;
    max-width: 100%;
    overflow-x: auto;
    table-layout: auto;
    width: max-content;
}

.panel th,
.panel td {
    min-width: 90px;
    vertical-align: top;
    white-space: normal;
    word-break: normal;
}

.csv-explanation-panel {
    max-height: 760px;
    overflow-y: auto;
}

.csv-plot,
.csv-plot .wrap,
.csv-plot .image-container,
.csv-plot [data-testid="image"],
.csv-plot [data-testid="image"] > div {
    min-height: 0 !important;
}

.csv-plot img {
    background: #ffffff !important;
    display: block !important;
    max-height: 430px !important;
    object-fit: contain !important;
    object-position: center !important;
    width: 100% !important;
}

.csv-plot-tall img {
    max-height: 620px !important;
}

.fix-callout {
    align-items: center;
    background: #fff8e6;
    border: 1px solid #f2d58a;
    border-radius: var(--radius);
    color: #7a4b00;
    display: flex;
    font-size: 13px;
    min-height: 44px;
    padding: 12px 14px;
}

.chat-shell {
    background: var(--surface);
    border: 1px solid var(--line-soft);
    border-radius: var(--radius);
    overflow: hidden;
}

.chat-head {
    align-items: center;
    border-bottom: 1px solid var(--line-soft);
    display: flex;
    gap: 16px;
    justify-content: space-between;
    padding: 16px 18px;
}

.chat-title {
    color: var(--text);
    font-size: 16px;
    font-weight: 800;
}

.chat-subtitle {
    color: var(--muted);
    font-size: 13px;
    line-height: 1.45;
    margin-top: 3px;
}

.chat-hint {
    background: var(--accent-soft);
    border: 1px solid #d7e4ff;
    border-radius: var(--radius);
    color: var(--accent);
    font-size: 12px;
    font-weight: 700;
    padding: 7px 10px;
    white-space: nowrap;
}

.chat-body {
    padding: 14px;
}

.prompt-row {
    display: grid;
    gap: 10px;
    grid-template-columns: repeat(3, minmax(0, 1fr));
    margin-bottom: 12px;
}

.prompt-row button {
    min-height: 42px !important;
}

#chatbot {
    border: 1px solid var(--line-soft) !important;
    border-radius: var(--radius) !important;
}

#chat-input textarea {
    min-height: 52px !important;
}

.chat-actions {
    align-items: stretch;
}

.investigator-setup {
    background: var(--surface);
    border: 1px solid var(--line-soft);
    border-radius: var(--radius);
    display: grid;
    gap: 18px;
    padding: 20px;
}

#investigator-scope,
#investigator-files {
    background: var(--surface) !important;
    border: 1px solid var(--line-soft) !important;
    border-radius: var(--radius) !important;
    box-shadow: none !important;
    padding: 14px !important;
}

#investigator-scope .wrap,
#investigator-files .wrap,
#investigator-scope .block,
#investigator-files .block {
    background: var(--surface) !important;
    border: 0 !important;
    box-shadow: none !important;
    padding: 0 !important;
}

#investigator-scope .block-label,
#investigator-scope [data-testid="block-label"],
#investigator-files .block-label,
#investigator-files [data-testid="block-label"] {
    background: transparent !important;
    border: 0 !important;
    color: var(--muted) !important;
    font-size: 11px !important;
    font-weight: 800 !important;
    letter-spacing: .08em !important;
    margin: 0 0 10px !important;
    padding: 0 !important;
    text-transform: uppercase !important;
}

#investigator-scope .form,
#investigator-scope [role="radiogroup"] {
    background: var(--surface-soft) !important;
    border: 1px solid var(--line-soft) !important;
    border-radius: var(--radius) !important;
    display: flex !important;
    flex-wrap: wrap !important;
    gap: 6px !important;
    padding: 6px !important;
    width: fit-content !important;
}

#investigator-scope label {
    align-items: center !important;
    background: transparent !important;
    border: 1px solid transparent !important;
    border-radius: 6px !important;
    cursor: pointer !important;
    display: inline-flex !important;
    gap: 9px !important;
    min-height: 38px !important;
    padding: 8px 12px !important;
    transition: background .16s ease, border-color .16s ease, box-shadow .16s ease !important;
}

#investigator-scope label:has(input:checked) {
    background: var(--surface) !important;
    border-color: var(--accent) !important;
    box-shadow: 0 1px 3px rgba(17, 24, 39, .08) !important;
    color: var(--accent) !important;
}

#investigator-files {
    padding: 14px !important;
}

#investigator-files .form,
#investigator-files [role="group"] {
    background: var(--surface) !important;
    border: 1px solid var(--line-soft) !important;
    border-radius: var(--radius) !important;
    display: grid !important;
    gap: 0 !important;
    grid-template-columns: 1fr !important;
    max-height: 390px !important;
    overflow-y: auto !important;
    padding: 6px !important;
}

#investigator-files label {
    align-items: center !important;
    background: var(--surface) !important;
    border: 1px solid transparent !important;
    border-bottom-color: var(--line-soft) !important;
    border-radius: 6px !important;
    cursor: pointer !important;
    display: flex !important;
    gap: 12px !important;
    justify-content: flex-start !important;
    min-height: 40px !important;
    overflow: hidden !important;
    padding: 9px 12px !important;
    transition: background .16s ease, border-color .16s ease !important;
}

#investigator-files label:last-child {
    border-bottom-color: transparent !important;
}

#investigator-files label:hover {
    background: var(--surface-soft) !important;
}

#investigator-files label:has(input:checked) {
    background: var(--accent-soft) !important;
    border-color: #b9cffd !important;
    color: var(--accent) !important;
}

#investigator-files label span {
    color: inherit !important;
    line-height: 1.35 !important;
    overflow: hidden !important;
    text-overflow: ellipsis !important;
    white-space: nowrap !important;
    word-break: break-word !important;
}

#investigator-files label:has(input[value^="__group__"]) {
    align-items: center !important;
    background: transparent !important;
    border: 0 !important;
    cursor: default !important;
    justify-content: flex-start !important;
    margin: 12px 0 4px !important;
    min-height: 34px !important;
    padding: 4px 10px !important;
    pointer-events: none !important;
}

#investigator-files label:has(input[value^="__group__"]) input {
    display: none !important;
}

#investigator-files label:has(input[value^="__group__"]) span {
    border-radius: 999px !important;
    display: inline-flex !important;
    font-size: 13px !important;
    font-weight: 800 !important;
    letter-spacing: 0 !important;
    line-height: 1 !important;
    padding: 10px 14px !important;
    text-transform: none !important;
    width: fit-content !important;
}

#investigator-files label:has(input[value="__group__Solidity"]) span {
    background: #dcfce7 !important;
    color: #008847 !important;
}

#investigator-files label:has(input[value="__group__Documents"]) span {
    background: #e8f0ff !important;
    color: #2563eb !important;
}

#investigator-files label:has(input[value="__group__CSV"]) span {
    background: #fef3c7 !important;
    color: #a16207 !important;
}

#investigator-files label:has(input[value="__group__JSON"]) span {
    background: #f3e8ff !important;
    color: #7e22ce !important;
}

#investigator-files label:has(input[value="__group__Images"]) span {
    background: #ffe4e6 !important;
    color: #be123c !important;
}

#investigator-files label:has(input[value="__group__Other"]) span {
    background: #f1f5f9 !important;
    color: #475569 !important;
}

#investigator-files input[type="checkbox"],
#investigator-scope input[type="radio"] {
    accent-color: var(--accent) !important;
    flex: 0 0 auto !important;
    height: 18px !important;
    width: 18px !important;
}

#investigator-files[aria-disabled="true"],
#investigator-files:has(input:disabled) {
    opacity: .82;
}

#investigator-files:has(input:disabled) label {
    cursor: default !important;
}

#investigator-file-sections,
#investigator-file-sections .wrap,
#investigator-file-sections .block,
#investigator-file-sections .form,
#investigator-file-sections [data-testid],
#investigator-file-sections [data-testid] > div {
    background: var(--surface) !important;
    border: 0 !important;
    box-shadow: none !important;
    color: var(--text) !important;
}

#investigator-file-sections {
    background: var(--surface) !important;
    border: 1px solid var(--line-soft) !important;
    border-radius: var(--radius) !important;
    padding: 0 !important;
    overflow: hidden !important;
}

#investigator-file-sections .block-label,
#investigator-file-sections [data-testid="block-label"],
#investigator-file-sections [data-testid="block-title"] {
    display: none !important;
}

.file-type-section {
    background: var(--surface) !important;
    border: 1px solid var(--line-soft) !important;
    border-radius: var(--radius) !important;
    box-shadow: none !important;
    margin-bottom: 10px !important;
    overflow: hidden !important;
}

.file-type-section summary,
.file-type-section [role="button"],
.file-type-section button,
.file-type-section .label-wrap {
    align-items: center !important;
    border-radius: var(--radius) !important;
    cursor: pointer !important;
    display: flex !important;
    font-size: 14px !important;
    font-weight: 800 !important;
    min-height: 46px !important;
    padding: 12px 14px !important;
}

.section-solidity summary,
.section-solidity [role="button"],
.section-solidity button,
.section-solidity .label-wrap,
.section-solidity > div:first-child,
.section-solidity > div:first-child * {
    background: #dcfce7 !important;
    color: #008847 !important;
}

.section-documents summary,
.section-documents [role="button"],
.section-documents button,
.section-documents .label-wrap,
.section-documents > div:first-child,
.section-documents > div:first-child * {
    background: #e8f0ff !important;
    color: #2563eb !important;
}

.section-csv summary,
.section-csv [role="button"],
.section-csv button,
.section-csv .label-wrap,
.section-csv > div:first-child,
.section-csv > div:first-child * {
    background: #fef3c7 !important;
    color: #a16207 !important;
}

.section-json summary,
.section-json [role="button"],
.section-json button,
.section-json .label-wrap,
.section-json > div:first-child,
.section-json > div:first-child * {
    background: #f3e8ff !important;
    color: #7e22ce !important;
}

.section-images summary,
.section-images [role="button"],
.section-images button,
.section-images .label-wrap,
.section-images > div:first-child,
.section-images > div:first-child * {
    background: #ffe4e6 !important;
    color: #be123c !important;
}

.section-other summary,
.section-other [role="button"],
.section-other button,
.section-other .label-wrap,
.section-other > div:first-child,
.section-other > div:first-child * {
    background: #f1f5f9 !important;
    color: #475569 !important;
}

#investigator-all-files,
#investigator-solidity-files,
#investigator-document-files,
#investigator-csv-files,
#investigator-json-files,
#investigator-image-files,
#investigator-other-files {
    background: var(--surface) !important;
    border: 0 !important;
    box-shadow: none !important;
    padding: 10px 12px 12px !important;
}

#investigator-all-files .form,
#investigator-solidity-files .form,
#investigator-document-files .form,
#investigator-csv-files .form,
#investigator-json-files .form,
#investigator-image-files .form,
#investigator-other-files .form,
#investigator-all-files [role="group"],
#investigator-solidity-files [role="group"],
#investigator-document-files [role="group"],
#investigator-csv-files [role="group"],
#investigator-json-files [role="group"],
#investigator-image-files [role="group"],
#investigator-other-files [role="group"] {
    display: grid !important;
    gap: 8px !important;
    grid-template-columns: repeat(auto-fit, minmax(240px, 1fr)) !important;
}

#investigator-all-files label,
#investigator-solidity-files label,
#investigator-document-files label,
#investigator-csv-files label,
#investigator-json-files label,
#investigator-image-files label,
#investigator-other-files label {
    align-items: center !important;
    background: var(--surface) !important;
    border: 1px solid var(--line-soft) !important;
    border-radius: 7px !important;
    cursor: pointer !important;
    display: flex !important;
    gap: 10px !important;
    min-height: 40px !important;
    overflow: hidden !important;
    padding: 9px 11px !important;
}

#investigator-all-files label:hover,
#investigator-solidity-files label:hover,
#investigator-document-files label:hover,
#investigator-csv-files label:hover,
#investigator-json-files label:hover,
#investigator-image-files label:hover,
#investigator-other-files label:hover {
    background: var(--surface-soft) !important;
}

#investigator-all-files label:has(input:checked),
#investigator-solidity-files label:has(input:checked),
#investigator-document-files label:has(input:checked),
#investigator-csv-files label:has(input:checked),
#investigator-json-files label:has(input:checked),
#investigator-image-files label:has(input:checked),
#investigator-other-files label:has(input:checked) {
    background: var(--accent-soft) !important;
    border-color: #b9cffd !important;
}

.workspace-picker,
.workspace-picker .wrap,
.workspace-picker .block,
.workspace-picker .form {
    background: var(--surface) !important;
    border: 0 !important;
    box-shadow: none !important;
    padding: 0 !important;
}

.workspace-section {
    margin-bottom: 8px !important;
}

.workspace-section summary,
.workspace-section [role="button"],
.workspace-section button,
.workspace-section .label-wrap {
    min-height: 40px !important;
    padding: 10px 12px !important;
}

#workspace-all-files,
#workspace-solidity-files,
#workspace-document-files,
#workspace-csv-files,
#workspace-json-files,
#workspace-image-files,
#workspace-other-files {
    background: var(--surface) !important;
    border: 0 !important;
    box-shadow: none !important;
    padding: 8px 0 !important;
}

#workspace-all-files .form,
#workspace-solidity-files .form,
#workspace-document-files .form,
#workspace-csv-files .form,
#workspace-json-files .form,
#workspace-image-files .form,
#workspace-other-files .form,
#workspace-all-files [role="radiogroup"],
#workspace-solidity-files [role="radiogroup"],
#workspace-document-files [role="radiogroup"],
#workspace-csv-files [role="radiogroup"],
#workspace-json-files [role="radiogroup"],
#workspace-image-files [role="radiogroup"],
#workspace-other-files [role="radiogroup"] {
    display: grid !important;
    gap: 7px !important;
    grid-template-columns: 1fr !important;
}

#workspace-all-files label,
#workspace-solidity-files label,
#workspace-document-files label,
#workspace-csv-files label,
#workspace-json-files label,
#workspace-image-files label,
#workspace-other-files label {
    align-items: center !important;
    background: var(--surface) !important;
    border: 1px solid var(--line-soft) !important;
    border-radius: 7px !important;
    cursor: pointer !important;
    display: flex !important;
    gap: 9px !important;
    min-height: 38px !important;
    overflow: hidden !important;
    padding: 8px 10px !important;
}

#workspace-all-files label:hover,
#workspace-solidity-files label:hover,
#workspace-document-files label:hover,
#workspace-csv-files label:hover,
#workspace-json-files label:hover,
#workspace-image-files label:hover,
#workspace-other-files label:hover {
    background: var(--surface-soft) !important;
}

#workspace-all-files label:has(input:checked),
#workspace-solidity-files label:has(input:checked),
#workspace-document-files label:has(input:checked),
#workspace-csv-files label:has(input:checked),
#workspace-json-files label:has(input:checked),
#workspace-image-files label:has(input:checked),
#workspace-other-files label:has(input:checked) {
    background: var(--accent-soft) !important;
    border-color: #b9cffd !important;
}

#workspace-all-files label span,
#workspace-solidity-files label span,
#workspace-document-files label span,
#workspace-csv-files label span,
#workspace-json-files label span,
#workspace-image-files label span,
#workspace-other-files label span {
    overflow: hidden !important;
    text-overflow: ellipsis !important;
    white-space: normal !important;
    word-break: break-word !important;
}

.selection-summary {
    align-items: center;
    background: var(--surface-soft);
    border: 1px solid var(--line-soft);
    border-radius: var(--radius);
    display: flex;
    gap: 10px;
    justify-content: space-between;
    padding: 12px 14px;
}

.selection-summary strong {
    color: var(--text);
    font-size: 13px;
}

.selection-summary span {
    color: var(--muted);
    font-size: 13px;
}

.selection-summary.muted {
    border-style: dashed;
}

.selection-summary-wrap,
.selection-summary-wrap * {
    background: transparent !important;
    border: 0 !important;
    box-shadow: none !important;
}

.investigator-start {
    justify-self: start;
    min-height: 44px !important;
    padding-inline: 18px !important;
}

button.primary {
    background: var(--accent) !important;
    border: 1px solid var(--accent) !important;
    border-radius: var(--radius) !important;
    color: white !important;
    font-weight: 700 !important;
}

button.secondary {
    background: var(--surface) !important;
    border: 1px solid var(--line) !important;
    border-radius: var(--radius) !important;
    color: var(--text) !important;
    font-weight: 700 !important;
}

button:hover {
    filter: brightness(.98);
}

textarea,
input,
select {
    border-radius: var(--radius) !important;
}

.gradio-container label,
.gradio-container .label-wrap,
.gradio-container .block-title,
.gradio-container .block-label,
.gradio-container .form,
.gradio-container .tabitem,
.gradio-container .markdown,
.gradio-container .markdown *,
.gradio-container .prose,
.gradio-container .prose *,
.gradio-container [data-testid="block-info"],
.gradio-container [data-testid="markdown"] {
    color: var(--text) !important;
}

.gradio-container label span,
.gradio-container .secondary-wrap,
.gradio-container .helper-text,
.gradio-container .info,
.gradio-container .meta-text {
    color: var(--muted) !important;
}

.gradio-container input,
.gradio-container textarea,
.gradio-container select,
.gradio-container .wrap,
.gradio-container .block,
.gradio-container .input-container {
    background: var(--surface) !important;
    color: var(--text) !important;
}

.gradio-container input::placeholder,
.gradio-container textarea::placeholder {
    color: #7a8495 !important;
    opacity: 1 !important;
}

.tab-nav button,
.tab-nav button span,
.tabs button,
.tabs button span {
    color: var(--text) !important;
}

.tab-nav button.selected,
.tabs button.selected {
    color: var(--accent) !important;
}

button.primary,
button.primary *,
.gradio-container button.primary,
.gradio-container button.primary * {
    color: white !important;
}

button.secondary,
button.secondary *,
.gradio-container button.secondary,
.gradio-container button.secondary * {
    color: var(--text) !important;
}

.chatbot,
.chatbot *,
#chatbot,
#chatbot * {
    color: var(--text) !important;
}

.prose,
.prose p,
.prose li {
    color: var(--text) !important;
    font-size: 14px !important;
    line-height: 1.65 !important;
}

.prose pre {
    border-radius: var(--radius) !important;
}

.gradio-container,
.gradio-container div,
.gradio-container p,
.gradio-container span,
.gradio-container li,
.gradio-container td,
.gradio-container th,
.gradio-container summary,
.gradio-container label,
.gradio-container output,
.gradio-container .value,
.gradio-container .file-preview,
.gradio-container .file-preview *,
.gradio-container .empty,
.gradio-container .output-markdown,
.gradio-container .output-markdown *,
.gradio-container [data-testid],
.gradio-container [data-testid] * {
    color: var(--text) !important;
}

.gradio-container small,
.gradio-container .helper-text,
.gradio-container .secondary-wrap,
.gradio-container .meta-text,
.gradio-container .description,
.gradio-container .caption {
    color: var(--muted) !important;
}

.gradio-container a,
.gradio-container a *,
.gradio-container .download-fixed,
.gradio-container .download-fixed * {
    color: var(--accent) !important;
    font-weight: 700 !important;
}

.gradio-container button.primary,
.gradio-container button.primary *,
.gradio-container .download-fixed.primary,
.gradio-container .download-fixed.primary * {
    color: #ffffff !important;
}

.brand-mark,
.brand-mark *,
.tool-icon,
.tool-icon *,
.message.user,
.message.user * {
    color: #ffffff !important;
}

.empty-icon,
.step-index,
.chat-hint,
.badge.info {
    color: var(--accent) !important;
}

.badge.success,
.badge.solidity { color: #008847 !important; }
.badge.csv { color: #a16207 !important; }
.badge.json { color: #7e22ce !important; }
.badge.images { color: #be123c !important; }
.badge.documents,
.badge.global { color: var(--accent) !important; }

.badge.neutral {
    color: var(--muted) !important;
}

.notice.danger,
.notice.danger *,
.fix-callout,
.fix-callout * {
    color: inherit !important;
}

.gradio-container .file-preview,
.gradio-container .file-preview *,
.gradio-container .upload-container,
.gradio-container .upload-container *,
.gradio-container [data-testid="file"],
.gradio-container [data-testid="file"] * {
    background: var(--surface-soft) !important;
    color: var(--text) !important;
}

.gradio-container .file-preview button,
.gradio-container .upload-container button,
.gradio-container [data-testid="file"] button {
    background: var(--surface) !important;
    border-color: var(--line) !important;
    color: var(--text) !important;
}

.tab-nav button,
.tabs button,
.gradio-container [role="tab"] {
    background: transparent !important;
    color: var(--text) !important;
}

.tab-nav button.selected,
.tabs button.selected,
.gradio-container [role="tab"][aria-selected="true"] {
    background: var(--accent-soft) !important;
    color: var(--accent) !important;
}

.tab-nav button *,
.tabs button *,
.gradio-container [role="tab"] * {
    color: inherit !important;
}

.gradio-container pre,
.gradio-container pre *,
.gradio-container .prose pre,
.gradio-container .prose pre *,
.gradio-container .markdown pre,
.gradio-container .markdown pre * {
    background: #1f2937 !important;
    color: #f8fafc !important;
}

.gradio-container pre {
    border: 1px solid #374151 !important;
    max-width: 100% !important;
    overflow-x: auto !important;
    white-space: pre !important;
}

.gradio-container pre code,
.gradio-container pre code *,
.gradio-container .prose pre code,
.gradio-container .prose pre code *,
.gradio-container .markdown pre code,
.gradio-container .markdown pre code * {
    color: #f8fafc !important;
    white-space: pre !important;
}

.gradio-container :not(pre) > code,
.gradio-container :not(pre) > code * {
    background: #eef2ff !important;
    border-radius: 4px !important;
    color: #1e3a8a !important;
    padding: 1px 4px !important;
}

#upload-file,
#upload-file *,
#upload-file .wrap,
#upload-file .block,
#upload-file .file-preview,
#upload-file .file-preview *,
#upload-file .upload-container,
#upload-file .upload-container *,
#upload-file [data-testid],
#upload-file [data-testid] * {
    background: var(--surface) !important;
    color: var(--text) !important;
}

#upload-file .upload-container,
#upload-file .file-preview {
    border: 1px solid var(--line) !important;
    border-radius: var(--radius) !important;
}

#upload-file button,
#upload-file button *,
#upload-file [role="button"],
#upload-file [role="button"] * {
    background: var(--surface-soft) !important;
    color: var(--text) !important;
}

#upload-file svg,
#upload-file svg * {
    color: var(--text) !important;
    fill: currentColor !important;
    stroke: currentColor !important;
}

#active-file,
#active-file *,
#active-file input,
#active-file select,
#active-file button,
#active-file [role="combobox"],
#active-file [role="combobox"] * {
    background: var(--surface) !important;
    color: var(--text) !important;
}

#active-file {
    border-color: var(--line) !important;
}

#active-file svg,
#active-file svg * {
    color: var(--text) !important;
    fill: currentColor !important;
    stroke: currentColor !important;
}

.gradio-container [role="listbox"],
.gradio-container [role="listbox"] *,
.gradio-container [role="option"],
.gradio-container [role="option"] *,
.gradio-container .options,
.gradio-container .options *,
.gradio-container .dropdown-options,
.gradio-container .dropdown-options *,
.gradio-container .select-dropdown,
.gradio-container .select-dropdown *,
.gradio-container .dropdown-menu,
.gradio-container .dropdown-menu * {
    background: var(--surface) !important;
    color: var(--text) !important;
}

.gradio-container [role="listbox"],
.gradio-container .options,
.gradio-container .dropdown-options,
.gradio-container .select-dropdown,
.gradio-container .dropdown-menu {
    border: 1px solid var(--line) !important;
    box-shadow: 0 14px 32px rgba(17, 24, 39, .14) !important;
}

.gradio-container [role="option"]:hover,
.gradio-container [role="option"][aria-selected="true"],
.gradio-container .options li:hover,
.gradio-container .dropdown-options li:hover {
    background: var(--accent-soft) !important;
    color: var(--accent) !important;
}

.chat-shell,
.chat-shell *,
#chatbot,
#chatbot *,
#chatbot .wrap,
#chatbot .block,
#chatbot .chatbot,
#chatbot [data-testid],
#chatbot [data-testid] * {
    background-color: var(--surface) !important;
    color: var(--text) !important;
}

.prompt-row button,
.prompt-row button *,
.chat-actions button.secondary,
.chat-actions button.secondary * {
    background: var(--surface) !important;
    border-color: var(--line) !important;
    color: var(--text) !important;
}

.chat-actions button.primary,
.chat-actions button.primary * {
    background: var(--accent) !important;
    border-color: var(--accent) !important;
    color: #ffffff !important;
}

#chatbot {
    background: var(--surface) !important;
}

#chatbot .message.bot,
#chatbot .message.bot *,
#chatbot .bot,
#chatbot .bot *,
#chatbot [data-testid="bot"],
#chatbot [data-testid="bot"] * {
    background: #ffffff !important;
    color: var(--text) !important;
}

#chatbot .message.user,
#chatbot .message.user *,
#chatbot .user,
#chatbot .user *,
#chatbot [data-testid="user"],
#chatbot [data-testid="user"] * {
    background: var(--accent) !important;
    color: #ffffff !important;
}

#chatbot button,
#chatbot button *,
#chatbot svg,
#chatbot svg * {
    background: var(--surface-soft) !important;
    color: var(--text) !important;
    stroke: currentColor !important;
}

#chat-input,
#chat-input *,
#chat-input textarea {
    background: var(--surface) !important;
    color: var(--text) !important;
}

.gradio-container .block-label,
.gradio-container .block-label *,
.gradio-container .block-title,
.gradio-container .block-title *,
.gradio-container [data-testid="block-label"],
.gradio-container [data-testid="block-label"] *,
.gradio-container [data-testid="block-title"],
.gradio-container [data-testid="block-title"] * {
    background: #111827 !important;
    border-color: #111827 !important;
    color: #ffffff !important;
    font-weight: 700 !important;
}

#investigator-file-sections,
#investigator-file-sections > *,
#investigator-file-sections .wrap,
#investigator-file-sections .block,
#investigator-file-sections .form,
.investigator-setup,
.investigator-setup > .wrap,
.investigator-setup > .block,
.investigator-setup > .form {
    background-color: var(--surface) !important;
    color: var(--text) !important;
}

#investigator-file-sections .block-label,
#investigator-file-sections [data-testid="block-label"],
#investigator-file-sections [data-testid="block-title"],
#investigator-file-sections .label-wrap:empty {
    display: none !important;
}

.file-type-section,
.file-type-section > .wrap,
.file-type-section > .block,
.file-type-section > .form {
    background-color: var(--surface) !important;
    border-color: var(--line-soft) !important;
}

.section-solidity summary,
.section-solidity [role="button"],
.section-solidity button,
.section-solidity .label-wrap {
    background: #dcfce7 !important;
    color: #008847 !important;
}

.section-documents summary,
.section-documents [role="button"],
.section-documents button,
.section-documents .label-wrap {
    background: #e8f0ff !important;
    color: #2563eb !important;
}

.section-csv summary,
.section-csv [role="button"],
.section-csv button,
.section-csv .label-wrap {
    background: #fef3c7 !important;
    color: #a16207 !important;
}

.section-json summary,
.section-json [role="button"],
.section-json button,
.section-json .label-wrap {
    background: #f3e8ff !important;
    color: #7e22ce !important;
}

.section-images summary,
.section-images [role="button"],
.section-images button,
.section-images .label-wrap {
    background: #ffe4e6 !important;
    color: #be123c !important;
}

.section-other summary,
.section-other [role="button"],
.section-other button,
.section-other .label-wrap {
    background: #f1f5f9 !important;
    color: #475569 !important;
}

.selection-summary-wrap,
.selection-summary-wrap *,
.selection-summary {
    background-color: var(--surface) !important;
}

.selection-summary {
    background: var(--surface-soft) !important;
    border: 1px solid var(--line-soft) !important;
}

.tab-nav {
    background: transparent !important;
    border-bottom: 1px solid var(--line-soft) !important;
}

.message.bot {
    background: var(--surface) !important;
    border: 1px solid var(--line-soft) !important;
}

.message.user {
    background: var(--accent) !important;
    color: white !important;
}

.message.user,
.message.user * {
    color: white !important;
}

.motion-card {
    opacity: 0;
    transform: translateY(10px);
    transition:
        opacity .42s ease,
        transform .42s ease,
        box-shadow .22s ease,
        border-color .22s ease;
    transition-delay: var(--stagger, 0ms);
}

.motion-card.in-view {
    opacity: 1;
    transform: translateY(0);
}

.motion-card:hover {
    border-color: #cbd7ea;
    box-shadow: 0 10px 28px rgba(22, 32, 51, .08);
}

.motion-button {
    transition:
        transform .16s ease,
        box-shadow .16s ease,
        filter .16s ease;
}

.motion-button:hover {
    box-shadow: 0 8px 18px rgba(22, 32, 51, .10);
    transform: translateY(-1px);
}

.motion-button:active {
    transform: translateY(0);
}

.brand-mark,
.tool-icon,
.step-index,
.empty-icon {
    animation: soft-pop .5s ease both;
}

.chat-hint,
.badge {
    animation: quiet-pulse 2.6s ease-in-out infinite;
}

@keyframes soft-pop {
    from {
        opacity: 0;
        transform: scale(.92);
    }
    to {
        opacity: 1;
        transform: scale(1);
    }
}

@keyframes quiet-pulse {
    0%, 100% {
        box-shadow: 0 0 0 rgba(37, 99, 235, 0);
    }
    50% {
        box-shadow: 0 0 0 4px rgba(37, 99, 235, .08);
    }
}

@media (prefers-reduced-motion: reduce) {
    *,
    *::before,
    *::after {
        animation: none !important;
        scroll-behavior: auto !important;
        transition: none !important;
    }

    .motion-card {
        opacity: 1;
        transform: none;
    }
}

@media (max-width: 900px) {
    #sidebar {
        border-right: none !important;
        min-height: auto;
    }

    #main {
        padding: 18px !important;
    }

    .hero {
        grid-template-columns: 1fr;
    }

    .hero-status-grid {
        grid-template-columns: 1fr;
    }

    .tool-grid {
        grid-template-columns: 1fr;
    }

    .overview-grid,
    .mini-grid,
    .prompt-row {
        grid-template-columns: 1fr;
    }

    .chat-head {
        align-items: flex-start;
        flex-direction: column;
    }

    .chat-hint {
        white-space: normal;
    }
}
"""

APP_JS = """
() => {
    const reduceMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    let refreshQueued = false;
    const animatedSelectors = [
        ".hero",
        ".file-panel",
        ".tool-card",
        ".mini-card",
        ".workflow-step",
        ".chat-shell",
        ".panel",
        ".fix-callout",
        ".empty-state"
    ].join(",");

    const observer = reduceMotion ? null : new IntersectionObserver((entries) => {
        entries.forEach((entry) => {
            if (entry.isIntersecting) {
                entry.target.classList.add("in-view");
                observer.unobserve(entry.target);
            }
        });
    }, { threshold: 0.12 });

    const hydrate = () => {
        document.querySelectorAll(animatedSelectors).forEach((element, index) => {
            if (element.dataset.motionReady) {
                return;
            }
            element.dataset.motionReady = "true";
            element.style.setProperty("--stagger", `${Math.min(index * 35, 240)}ms`);
            element.classList.add("motion-card");
            if (reduceMotion) {
                element.classList.add("in-view");
            }
        });

        document.querySelectorAll("button").forEach((button) => {
            button.classList.add("motion-button");
        });
    };

    const reveal = () => {
        if (reduceMotion) {
            document.querySelectorAll(".motion-card").forEach((element) => element.classList.add("in-view"));
            return;
        }

        document.querySelectorAll(".motion-card:not(.in-view)").forEach((element) => observer.observe(element));
    };

    const refresh = () => {
        hydrate();
        reveal();
    };

    refresh();
    const mutationObserver = new MutationObserver(() => {
        if (refreshQueued) {
            return;
        }
        refreshQueued = true;
        window.requestAnimationFrame(() => {
            refreshQueued = false;
            refresh();
        });
    });
    mutationObserver.observe(document.body, { childList: true, subtree: true });
}
"""


# ---------------------------------------------------------------------------
# Build UI
# ---------------------------------------------------------------------------

logo_mark_data_uri = get_image_data_uri(LOGO_MARK_PATH)

with gr.Blocks(title="ChainSentinel AI") as demo:
    last_solidity_audit_state = gr.State("")
    last_solidity_line_map_state = gr.State("")
    last_solidity_file_state = gr.State("")

    with gr.Row(equal_height=False, elem_id="app-shell"):
        with gr.Column(scale=0, min_width=300, elem_id="sidebar"):
            gr.HTML(
                f"""
<div class="brand">
  <div class="brand-mark"><img class="brand-logo" src="{logo_mark_data_uri}" alt="ChainSentinel AI logo"></div>
  <div>
    <div class="brand-title">ChainSentinel AI</div>
    <div class="brand-subtitle">AI smart contract security</div>
  </div>
</div>
"""
            )

            gr.HTML('<div class="side-label">Workspace</div>')
            active_file = gr.Dropdown(
                label="Active file",
                choices=get_workspace_file_choices(),
                interactive=True,
                show_label=False,
                visible=False,
                container=False,
                elem_id="active-file",
            )
            with gr.Group(elem_classes=["workspace-picker"]):
                workspace_all_files = gr.Radio(
                    choices=[(ALL_FILES_LABEL, ALL_FILES_LABEL)],
                    value=ALL_FILES_LABEL if ALL_FILES_LABEL in get_workspace_file_choices() else None,
                    show_label=False,
                    elem_id="workspace-all-files",
                )
                with gr.Accordion("Solidity", open=False, elem_classes=["file-type-section", "section-solidity", "workspace-section"]):
                    workspace_solidity_files = gr.Radio(
                        choices=get_workspace_choices_for_types(("sol",)),
                        show_label=False,
                        elem_id="workspace-solidity-files",
                    )
                with gr.Accordion("Documents", open=False, elem_classes=["file-type-section", "section-documents", "workspace-section"]):
                    workspace_document_files = gr.Radio(
                        choices=get_workspace_choices_for_types(("pdf", "doc", "txt")),
                        show_label=False,
                        elem_id="workspace-document-files",
                    )
                with gr.Accordion("CSV", open=False, elem_classes=["file-type-section", "section-csv", "workspace-section"]):
                    workspace_csv_files = gr.Radio(
                        choices=get_workspace_choices_for_types(("csv",)),
                        show_label=False,
                        elem_id="workspace-csv-files",
                    )
                with gr.Accordion("JSON", open=False, elem_classes=["file-type-section", "section-json", "workspace-section"]):
                    workspace_json_files = gr.Radio(
                        choices=get_workspace_choices_for_types(("json",)),
                        show_label=False,
                        elem_id="workspace-json-files",
                    )
                with gr.Accordion("Images", open=False, elem_classes=["file-type-section", "section-images", "workspace-section"]):
                    workspace_image_files = gr.Radio(
                        choices=get_workspace_choices_for_types(("image",)),
                        show_label=False,
                        elem_id="workspace-image-files",
                    )
                with gr.Accordion("Other", open=False, elem_classes=["file-type-section", "section-other", "workspace-section"]):
                    workspace_other_files = gr.Radio(
                        choices=get_workspace_choices_for_types(("unknown",)),
                        show_label=False,
                        elem_id="workspace-other-files",
                    )

            gr.HTML('<div class="side-label">Upload</div>')
            file_input = gr.File(
                label="Drop a contract, document, CSV, trace, or screenshot",
                file_types=[".sol", ".pdf", ".docx", ".doc", ".txt", ".csv", ".json", ".png", ".jpg", ".jpeg", ".webp"],
                elem_id="upload-file",
            )
            upload_btn = gr.Button("Analyze", variant="primary")
            status_box = gr.Textbox(
                label="Status",
                placeholder="Ready",
                interactive=False,
                lines=3,
                max_lines=4,
            )

        with gr.Column(scale=1, elem_id="main"):
            gr.HTML(
                """
<div class="hero">
  <div>
    <div class="hero-kicker">ChainSentinel AI workspace</div>
    <h1>Investigate smart contract risk with source-backed evidence.</h1>
    <p>Upload contracts, documents, traces, datasets, or screenshots, then move through audit, chat, summary, remediation, and reporting from one focused workspace.</p>
  </div>
  <div class="hero-status-grid">
    <div class="hero-status-card primary">
      <strong>Multi-file investigation ready</strong>
      <span>Use the Advanced tab to run coordinated review across selected workspace files.</span>
      <div class="hero-pill-row">
        <span class="hero-pill sol">SOL</span>
        <span class="hero-pill doc">DOC</span>
        <span class="hero-pill data">CSV</span>
        <span class="hero-pill trace">JSON</span>
        <span class="hero-pill img">IMG</span>
      </div>
    </div>
    <div class="hero-status-card">
      <strong>Hybrid audit</strong>
      <span>Classifier plus Slither confirmation.</span>
    </div>
    <div class="hero-status-card">
      <strong>Evidence reports</strong>
      <span>Risk, line map, fixes, and exports.</span>
    </div>
  </div>
</div>
"""
            )

            with gr.Tabs():
                with gr.Tab("Overview"):
                    actions_panel = gr.HTML(value=EMPTY_PANEL)

                with gr.Tab("Audit"):
                    gr.HTML('<div class="side-label">Risk dashboard</div>')
                    risk_dashboard_box = gr.Markdown(
                        "### Contract Risk Dashboard\n\nSelect a Solidity file to calculate risk.",
                        elem_classes=["panel"],
                    )
                    with gr.Row(equal_height=False):
                        with gr.Column(scale=1):
                            gr.HTML('<div class="side-label">Audit report</div>')
                            audit_report_box = gr.Markdown(
                                "Upload a Solidity file to run the vulnerability audit.",
                                elem_classes=["panel"],
                            )
                        with gr.Column(scale=1):
                            gr.HTML('<div class="side-label">Suggested fix</div>')
                            fix_output = gr.Markdown(
                                "Generate a fix after an audit finds a vulnerability.",
                                elem_classes=["panel"],
                            )
                            fixed_file_download = gr.DownloadButton(
                                label="Download fixed file",
                                visible=False,
                                variant="primary",
                                elem_classes=["download-fixed"],
                            )

                    with gr.Row(equal_height=False):
                        with gr.Column(scale=1):
                            gr.HTML('<div class="side-label">Line-level finding map</div>')
                            line_map_box = gr.Markdown(
                                "### Line-Level Map\n\nSelect a Solidity file to map findings to source lines.",
                                elem_classes=["panel"],
                            )
                        with gr.Column(scale=1):
                            gr.HTML('<div class="side-label">Patch diff</div>')
                            patch_diff_box = gr.Markdown(
                                "### Patch Diff\n\nGenerate a fix to compare original and patched code.",
                                elem_classes=["panel"],
                            )

                    with gr.Row(visible=False) as audit_controls:
                        with gr.Column(scale=3):
                            gr.HTML('<div class="fix-callout">A Solidity file is active. Generate a security patch when the audit indicates risk.</div>')
                        with gr.Column(scale=1, min_width=190):
                            fix_btn = gr.Button("Generate fix", variant="secondary")

                with gr.Tab("Chat"):
                    with gr.Group(elem_classes=["chat-shell"]):
                        chat_context = gr.HTML(value=get_chat_header_html())
                        with gr.Column(elem_classes=["chat-body"]):
                            with gr.Row(elem_classes=["prompt-row"]):
                                prompt_risks = gr.Button("Find risks", variant="secondary")
                                prompt_flow = gr.Button("Explain flow", variant="secondary")
                                prompt_sources = gr.Button("Show evidence", variant="secondary")

                            chat_bot = gr.Chatbot(
                                label="Conversation",
                                elem_id="chatbot",
                                height=430,
                                layout="bubble",
                                placeholder="Ask about functions, clauses, risks, obligations, or source evidence from the active file.",
                            )

                            with gr.Row(elem_classes=["chat-actions"]):
                                chat_input = gr.Textbox(
                                    placeholder="Ask about the active file...",
                                    show_label=False,
                                    container=False,
                                    scale=8,
                                    elem_id="chat-input",
                                )
                                chat_send = gr.Button("Send", variant="primary", scale=1, min_width=110)
                                chat_clear = gr.Button("Clear", variant="secondary", scale=1, min_width=110)

                            prompt_risks.click(
                                fn=set_chat_prompt,
                                inputs=[gr.State("What are the highest-risk issues in this file, and where do they appear?")],
                                outputs=[chat_input],
                            )
                            prompt_flow.click(
                                fn=set_chat_prompt,
                                inputs=[gr.State("Explain the main control flow and the most important functions or clauses.")],
                                outputs=[chat_input],
                            )
                            prompt_sources.click(
                                fn=set_chat_prompt,
                                inputs=[gr.State("Answer with the strongest source evidence from the retrieved context.")],
                                outputs=[chat_input],
                            )
                            chat_input.submit(
                                fn=chat_submit,
                                inputs=[chat_input, chat_bot, active_file],
                                outputs=[chat_input, chat_bot],
                            )
                            chat_send.click(
                                fn=chat_submit,
                                inputs=[chat_input, chat_bot, active_file],
                                outputs=[chat_input, chat_bot],
                            )
                            chat_clear.click(fn=clear_chat, outputs=[chat_input, chat_bot])

                with gr.Tab("Summary"):
                    summarize_button = gr.Button("Generate summary", variant="primary")
                    summary_output = gr.Markdown(elem_classes=["panel"])
                    summarize_button.click(fn=generate_summary, inputs=[active_file], outputs=[summary_output])

                with gr.Tab("Advanced"):
                    with gr.Accordion("Multi-Agent Auto-Investigator", open=True):
                        with gr.Group(elem_classes=["investigator-setup"]):
                            auto_investigator_scope = gr.Radio(
                                choices=["Active file only", "Select files"],
                                value="Active file only",
                                label="Investigation scope",
                                elem_id="investigator-scope",
                            )
                            with gr.Group(visible=False, elem_id="investigator-file-sections") as auto_investigator_file_sections:
                                auto_investigator_all_files = gr.CheckboxGroup(
                                    choices=[(SELECT_ALL_FILES_LABEL, SELECT_ALL_FILES_LABEL)],
                                    label="Files to include",
                                    value=[],
                                    interactive=True,
                                    elem_id="investigator-all-files",
                                )
                                with gr.Accordion("Solidity", open=False, elem_classes=["file-type-section", "section-solidity"]):
                                    auto_investigator_solidity_files = gr.CheckboxGroup(
                                        choices=get_investigation_choices_for_types(("sol",)),
                                        show_label=False,
                                        value=[],
                                        interactive=True,
                                        elem_id="investigator-solidity-files",
                                    )
                                with gr.Accordion("Documents", open=False, elem_classes=["file-type-section", "section-documents"]):
                                    auto_investigator_document_files = gr.CheckboxGroup(
                                        choices=get_investigation_choices_for_types(("pdf", "doc", "txt")),
                                        show_label=False,
                                        value=[],
                                        interactive=True,
                                        elem_id="investigator-document-files",
                                    )
                                with gr.Accordion("CSV", open=False, elem_classes=["file-type-section", "section-csv"]):
                                    auto_investigator_csv_files = gr.CheckboxGroup(
                                        choices=get_investigation_choices_for_types(("csv",)),
                                        show_label=False,
                                        value=[],
                                        interactive=True,
                                        elem_id="investigator-csv-files",
                                    )
                                with gr.Accordion("JSON", open=False, elem_classes=["file-type-section", "section-json"]):
                                    auto_investigator_json_files = gr.CheckboxGroup(
                                        choices=get_investigation_choices_for_types(("json",)),
                                        show_label=False,
                                        value=[],
                                        interactive=True,
                                        elem_id="investigator-json-files",
                                    )
                                with gr.Accordion("Images", open=False, elem_classes=["file-type-section", "section-images"]):
                                    auto_investigator_image_files = gr.CheckboxGroup(
                                        choices=get_investigation_choices_for_types(("image",)),
                                        show_label=False,
                                        value=[],
                                        interactive=True,
                                        elem_id="investigator-image-files",
                                    )
                                with gr.Accordion("Other", open=False, elem_classes=["file-type-section", "section-other"]):
                                    auto_investigator_other_files = gr.CheckboxGroup(
                                        choices=get_investigation_choices_for_types(("unknown",)),
                                        show_label=False,
                                        value=[],
                                        interactive=True,
                                        elem_id="investigator-other-files",
                                    )
                            auto_investigator_selection_summary = gr.HTML(
                                value="",
                                visible=False,
                                elem_classes=["selection-summary-wrap"],
                            )
                            auto_investigator_button = gr.Button(
                                "Start Multi-Agent Investigation",
                                variant="primary",
                                elem_classes=["investigator-start"],
                            )
                        auto_investigator_output = gr.Markdown(elem_classes=["panel"])
                        auto_investigator_cards = gr.HTML(
                            value="",
                            elem_classes=["investigation-cards-wrap"],
                        )
                        auto_investigator_report = gr.DownloadButton(
                            label="Download investigation report",
                            visible=False,
                            variant="secondary",
                        )
                        auto_investigator_button.click(
                            fn=run_auto_investigator_ui,
                            inputs=[
                                auto_investigator_scope,
                                active_file,
                                auto_investigator_all_files,
                                auto_investigator_solidity_files,
                                auto_investigator_document_files,
                                auto_investigator_csv_files,
                                auto_investigator_json_files,
                                auto_investigator_image_files,
                                auto_investigator_other_files,
                            ],
                            outputs=[
                                auto_investigator_output,
                                auto_investigator_cards,
                                auto_investigator_report,
                            ],
                        )
                        auto_investigator_scope.change(
                            fn=update_auto_investigator_file_picker,
                            inputs=[auto_investigator_scope],
                            outputs=[
                                auto_investigator_file_sections,
                                auto_investigator_all_files,
                                auto_investigator_solidity_files,
                                auto_investigator_document_files,
                                auto_investigator_csv_files,
                                auto_investigator_json_files,
                                auto_investigator_image_files,
                                auto_investigator_other_files,
                                auto_investigator_selection_summary,
                            ],
                        )
                        selection_summary_inputs = [
                            auto_investigator_all_files,
                            auto_investigator_solidity_files,
                            auto_investigator_document_files,
                            auto_investigator_csv_files,
                            auto_investigator_json_files,
                            auto_investigator_image_files,
                            auto_investigator_other_files,
                        ]
                        for file_selector in selection_summary_inputs:
                            file_selector.change(
                                fn=file_selection_summary_html,
                                inputs=selection_summary_inputs,
                                outputs=[auto_investigator_selection_summary],
                            )

                    with gr.Accordion("RAG evaluation", open=True):
                        eval_input = gr.Textbox(
                            label="Test questions",
                            lines=5,
                            placeholder=(
                                "What is the main risk in this contract?\n"
                                "Which function transfers funds?\n"
                                "What access controls are used?"
                            ),
                        )
                        eval_button = gr.Button("Run evaluation", variant="primary")
                        eval_output = gr.Markdown(elem_classes=["panel"])
                        eval_button.click(fn=run_eval, inputs=[eval_input, active_file], outputs=[eval_output])

                    with gr.Accordion("CSV anomaly detection", open=False):
                        csv_anomaly_button = gr.Button("Run CSV anomaly detection", variant="primary")
                        csv_anomaly_output = gr.Markdown(elem_classes=["panel"])
                        with gr.Row():
                            csv_error_distribution_plot = gr.Image(
                                label="Reconstruction error histogram",
                                type="filepath",
                                interactive=False,
                                height=360,
                                elem_classes=["csv-plot"],
                            )
                            csv_error_by_row_plot = gr.Image(
                                label="Reconstruction error by row",
                                type="filepath",
                                interactive=False,
                                height=360,
                                elem_classes=["csv-plot"],
                            )
                        with gr.Row():
                            csv_top_scores_plot = gr.Image(
                                label="Top anomaly scores bar plot",
                                type="filepath",
                                interactive=False,
                                height=360,
                                elem_classes=["csv-plot"],
                            )
                            csv_histograms_plot = gr.Image(
                                label="Numeric column histograms",
                                type="filepath",
                                interactive=False,
                                height=620,
                                elem_classes=["csv-plot", "csv-plot-tall"],
                            )
                        with gr.Row():
                            csv_boxplot = gr.Image(
                                label="Numeric column boxplot",
                                type="filepath",
                                interactive=False,
                                height=520,
                                elem_classes=["csv-plot", "csv-plot-tall"],
                            )
                            csv_means_barplot = gr.Image(
                                label="Column means bar plot",
                                type="filepath",
                                interactive=False,
                                height=520,
                                elem_classes=["csv-plot", "csv-plot-tall"],
                            )
                        csv_correlation_plot = gr.Image(
                            label="Correlation heatmap",
                            type="filepath",
                            interactive=False,
                            height=620,
                            elem_classes=["csv-plot", "csv-plot-tall"],
                        )
                        csv_model_download = gr.DownloadButton(
                            label="Download trained autoencoder",
                            visible=False,
                            variant="secondary",
                        )
                        csv_explanation_output = gr.Markdown(elem_classes=["panel", "csv-explanation-panel"])
                        with gr.Row():
                            csv_contract_row = gr.Textbox(
                                label="CSV row to correlate with last Solidity audit",
                                placeholder="Example: 145",
                                scale=2,
                            )
                            csv_contract_button = gr.Button("Correlate CSV row with contract audit", variant="secondary", scale=1)
                        csv_contract_output = gr.Markdown(elem_classes=["panel"])
                        csv_anomaly_button.click(
                            fn=run_csv_anomaly_analysis,
                            inputs=[active_file],
                            outputs=[
                                csv_anomaly_output,
                                csv_error_distribution_plot,
                                csv_error_by_row_plot,
                                csv_top_scores_plot,
                                csv_histograms_plot,
                                csv_boxplot,
                                csv_means_barplot,
                                csv_correlation_plot,
                                csv_model_download,
                                csv_explanation_output,
                            ],
                        )
                        csv_contract_button.click(
                            fn=correlate_csv_with_contract,
                            inputs=[
                                last_solidity_file_state,
                                last_solidity_audit_state,
                                last_solidity_line_map_state,
                                csv_anomaly_output,
                                csv_contract_row,
                            ],
                            outputs=[csv_contract_output],
                        )

                    with gr.Accordion("JSON transaction trace analysis", open=False):
                        trace_analysis_button = gr.Button("Run JSON trace analysis", variant="primary")
                        trace_analysis_output = gr.Markdown(elem_classes=["panel"])
                        trace_correlation_button = gr.Button("Correlate trace with contract audit", variant="secondary")
                        trace_correlation_output = gr.Markdown(elem_classes=["panel"])
                        trace_analysis_button.click(
                            fn=run_json_trace_analysis,
                            inputs=[active_file],
                            outputs=[trace_analysis_output],
                        )
                        trace_correlation_button.click(
                            fn=run_trace_contract_correlation_from_state,
                            inputs=[
                                last_solidity_file_state,
                                last_solidity_audit_state,
                                last_solidity_line_map_state,
                                trace_analysis_output,
                            ],
                            outputs=[trace_correlation_output],
                        )

                    with gr.Accordion("Image security analysis", open=False):
                        image_analysis_button = gr.Button("Run image security analysis", variant="primary")
                        image_analysis_output = gr.Markdown(elem_classes=["panel"])
                        image_analysis_button.click(
                            fn=run_image_security_analysis,
                            inputs=[active_file],
                            outputs=[image_analysis_output],
                        )

                    with gr.Accordion("Executive report", open=False):
                        report_button = gr.Button("Export executive report", variant="primary")
                        report_output = gr.Markdown(elem_classes=["panel"])
                        report_download = gr.DownloadButton(
                            label="Download executive report",
                            visible=False,
                            variant="secondary",
                        )
                        report_button.click(
                            fn=export_executive_report,
                            inputs=[
                                active_file,
                                risk_dashboard_box,
                                audit_report_box,
                                fix_output,
                                csv_anomaly_output,
                                csv_explanation_output,
                            ],
                            outputs=[report_output, report_download],
                        )

                    with gr.Accordion("Audit history & full report", open=False):
                        with gr.Row():
                            save_audit_history_button = gr.Button("Save audit snapshot", variant="primary")
                            refresh_audit_history_button = gr.Button("Refresh history", variant="secondary")
                            full_report_button = gr.Button("Export full audit report", variant="secondary")
                        audit_history_status = gr.Markdown(elem_classes=["panel"])
                        audit_history_output = gr.Markdown(
                            value=format_audit_history_markdown(),
                            elem_classes=["panel"],
                        )
                        full_report_download = gr.DownloadButton(
                            label="Download full audit report",
                            visible=False,
                            variant="secondary",
                        )
                        save_audit_history_button.click(
                            fn=save_audit_snapshot,
                            inputs=[
                                active_file,
                                risk_dashboard_box,
                                audit_report_box,
                                fix_output,
                                patch_diff_box,
                            ],
                            outputs=[audit_history_status, audit_history_output],
                        )
                        refresh_audit_history_button.click(
                            fn=refresh_audit_history,
                            outputs=[audit_history_output],
                        )
                        full_report_button.click(
                            fn=export_full_audit_report,
                            inputs=[
                                active_file,
                                risk_dashboard_box,
                                audit_report_box,
                                fix_output,
                                line_map_box,
                                patch_diff_box,
                                csv_anomaly_output,
                                csv_explanation_output,
                            ],
                            outputs=[audit_history_status, full_report_download],
                        )

            upload_btn.click(
                fn=smart_upload,
                inputs=[file_input],
                outputs=[
                    status_box,
                    actions_panel,
                    audit_report_box,
                    audit_controls,
                    active_file,
                    chat_context,
                    fixed_file_download,
                    risk_dashboard_box,
                    fix_output,
                    line_map_box,
                    patch_diff_box,
                    last_solidity_audit_state,
                    last_solidity_line_map_state,
                    last_solidity_file_state,
                    auto_investigator_all_files,
                    auto_investigator_solidity_files,
                    auto_investigator_document_files,
                    auto_investigator_csv_files,
                    auto_investigator_json_files,
                    auto_investigator_image_files,
                    auto_investigator_other_files,
                    workspace_all_files,
                    workspace_solidity_files,
                    workspace_document_files,
                    workspace_csv_files,
                    workspace_json_files,
                    workspace_image_files,
                    workspace_other_files,
                ],
            )
            active_file.change(
                fn=show_selected_file,
                inputs=[active_file],
                outputs=[
                    actions_panel,
                    audit_report_box,
                    audit_controls,
                    chat_context,
                    fixed_file_download,
                    risk_dashboard_box,
                    fix_output,
                    line_map_box,
                    patch_diff_box,
                    last_solidity_audit_state,
                    last_solidity_line_map_state,
                    last_solidity_file_state,
                    auto_investigator_all_files,
                    auto_investigator_solidity_files,
                    auto_investigator_document_files,
                    auto_investigator_csv_files,
                    auto_investigator_json_files,
                    auto_investigator_image_files,
                    auto_investigator_other_files,
                    workspace_all_files,
                    workspace_solidity_files,
                    workspace_document_files,
                    workspace_csv_files,
                    workspace_json_files,
                    workspace_image_files,
                    workspace_other_files,
                ],
            )
            workspace_picker_inputs = [
                workspace_all_files,
                workspace_solidity_files,
                workspace_document_files,
                workspace_csv_files,
                workspace_json_files,
                workspace_image_files,
                workspace_other_files,
            ]
            workspace_picker_outputs = [
                active_file,
                actions_panel,
                audit_report_box,
                audit_controls,
                chat_context,
                fixed_file_download,
                risk_dashboard_box,
                fix_output,
                line_map_box,
                patch_diff_box,
                last_solidity_audit_state,
                last_solidity_line_map_state,
                last_solidity_file_state,
                auto_investigator_all_files,
                auto_investigator_solidity_files,
                auto_investigator_document_files,
                auto_investigator_csv_files,
                auto_investigator_json_files,
                auto_investigator_image_files,
                auto_investigator_other_files,
                workspace_all_files,
                workspace_solidity_files,
                workspace_document_files,
                workspace_csv_files,
                workspace_json_files,
                workspace_image_files,
                workspace_other_files,
            ]
            for workspace_selector in workspace_picker_inputs:
                workspace_selector.change(
                    fn=choose_workspace_file,
                    inputs=[workspace_selector],
                    outputs=workspace_picker_outputs,
                )
            fix_btn.click(
                fn=suggest_security_fix,
                inputs=[active_file, audit_report_box, risk_dashboard_box],
                outputs=[fix_output, fixed_file_download, patch_diff_box],
            )


if __name__ == "__main__":
    os.makedirs("./vector_db", exist_ok=True)
    demo.launch(
        show_api=False,
        share=True,
        css=CSS,
        js=APP_JS,
        theme=gr.themes.Base(),
        allowed_paths=[ASSETS_DIR],
    )
