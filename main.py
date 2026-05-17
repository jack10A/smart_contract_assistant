import os
import re
import json
import shutil
import sys
import time
import urllib.request
from dataclasses import asdict, is_dataclass

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.responses import FileResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from langserve import add_routes
from pydantic import BaseModel
import uvicorn
from app.ui import (
    APP_JS,
    CSS,
    UPLOAD_DIR,
    chat_response,
    demo,
    detect_file_type,
    correlate_csv_with_contract,
    run_csv_anomaly_analysis,
    run_image_security_analysis,
    run_json_trace_analysis,
    run_trace_contract_correlation_from_state,
    suggest_security_fix,
)
from app.image_analysis import analyze_security_image, format_image_analysis_markdown
from app.chain import get_smart_contract_chain
import webbrowser
from threading import Thread
from app.classifier.predict import vulnerability_auditor
from app.function_analysis import analyze_functions_with_classifier, format_function_analysis_markdown
from app.ingestion import get_retriever, process_document
from app.security_analysis import format_line_map_markdown, format_risk_dashboard_markdown
from app.slither_analysis import format_slither_report, run_slither_analysis
from app.reporting import AUDIT_HISTORY_PATH, record_audit_snapshot
from app.reporting import generate_full_audit_report

for stream in (sys.stdout, sys.stderr):
    if hasattr(stream, "reconfigure"):
        stream.reconfigure(encoding="utf-8")

app = FastAPI(title="Smart Contract Assistant API")
SERVER_URL = "http://127.0.0.1:7860"

default_retriever = get_retriever()

app.add_middleware(
    CORSMiddleware,
    allow_origin_regex=r"https?://((localhost|127\.0\.0\.1)(:\d+)?|.*\.vercel\.app)",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.mount("/uploads", StaticFiles(directory=UPLOAD_DIR), name="uploads")


class FilenameRequest(BaseModel):
    filename: str


class FixRequest(BaseModel):
    filename: str
    audit_text: str
    risk_text: str = ""


class ChatRequest(BaseModel):
    message: str
    selected_file: str | None = None
    selected_files: list[str] | None = None
    history: list[dict] = []


class InvestigateRequest(BaseModel):
    files: list[str] | None = None


class CsvContractCorrelationRequest(BaseModel):
    solidity_file: str | None = None
    audit_text: str = ""
    line_map_text: str = ""
    csv_text: str = ""
    row_number: str = ""


class TraceContractCorrelationRequest(BaseModel):
    solidity_file: str | None = None
    audit_text: str = ""
    line_map_text: str = ""
    trace_text: str = ""


class ExportReportRequest(BaseModel):
    selected_file: str | None = None
    risk_text: str = ""
    audit_text: str = ""
    fix_text: str = ""
    line_map_text: str = ""
    patch_diff_text: str = ""
    csv_text: str = ""
    csv_explanation: str = ""
    trace_text: str = ""
    image_text: str = ""
    investigation_summary: str = ""
    attack_replay_text: str = ""


def _safe_workspace_path(filename: str) -> str:
    safe_name = os.path.basename(filename or "")
    if not safe_name or safe_name != filename:
        raise HTTPException(status_code=400, detail="Invalid filename.")
    path = os.path.join(UPLOAD_DIR, safe_name)
    if not os.path.exists(path):
        raise HTTPException(status_code=404, detail=f"File '{safe_name}' was not found. Upload it first.")
    return path


def _jsonable(value):
    if is_dataclass(value):
        return asdict(value)
    if isinstance(value, dict):
        return {key: _jsonable(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_jsonable(item) for item in value]
    return value


def _audit_solidity_file(filename: str) -> dict:
    local_path = _safe_workspace_path(filename)
    if detect_file_type(filename) != "sol":
        raise HTTPException(status_code=400, detail="Select a .sol file to run a smart contract audit.")

    try:
        with open(local_path, "r", encoding="utf-8", errors="ignore") as f:
            code = f.read()
        prediction = vulnerability_auditor.predict(code)
        audit_text = vulnerability_auditor.format_report(prediction)
        function_analysis = format_function_analysis_markdown(
            analyze_functions_with_classifier(code, vulnerability_auditor)
        )
        slither_report = format_slither_report(run_slither_analysis(local_path))
        full_audit = f"{audit_text}\n\n---\n\n{function_analysis}\n\n---\n\n{slither_report}"
        risk_text = format_risk_dashboard_markdown(filename, full_audit, code)
        line_map = format_line_map_markdown(code, full_audit)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Audit error: {exc}") from exc

    return {
        "filename": filename,
        "source_code": code,
        "audit_text": full_audit,
        "risk_text": risk_text,
        "function_analysis": function_analysis,
        "slither_report": slither_report,
        "line_map": line_map,
        "prediction": prediction,
    }


def _update_value(update):
    if isinstance(update, dict):
        return update.get("value")
    return getattr(update, "value", None)


def _workspace_url(path: str | None) -> str | None:
    if not path:
        return None
    normalized = path.replace("\\", "/")
    marker = "workspace_uploads/"
    if marker in normalized:
        normalized = normalized.split(marker, 1)[1]
    return f"/uploads/{normalized.lstrip('/')}"


def _extract_csv_metric(pattern: str, text: str, default=None):
    match = re.search(pattern, text, flags=re.IGNORECASE)
    return match.group(1).strip() if match else default


def _report_type(filename: str) -> str:
    lower = filename.lower()
    if "multi_agent" in lower:
        return "Multi-Agent Executive"
    if "full_audit" in lower:
        return "Full Audit"
    if "executive" in lower:
        return "Executive Summary"
    return "PDF Report"


def _parse_risk_score(value: str | None) -> int:
    if not value:
        return 0
    match = re.search(r"(\d+)", value)
    return int(match.group(1)) if match else 0


def _load_history_entries() -> list[dict]:
    if not os.path.exists(AUDIT_HISTORY_PATH):
        return []
    try:
        with open(AUDIT_HISTORY_PATH, "r", encoding="utf-8") as history_file:
            data = json.load(history_file)
        return data if isinstance(data, list) else []
    except (OSError, json.JSONDecodeError):
        return []


def _format_history_entry(entry: dict, index: int) -> dict:
    risk_score_label = entry.get("risk_score") or "0/100"
    risk_level = entry.get("risk_level") or "Unknown"
    return {
        "id": f"AUD-{index + 1:04d}",
        "timestamp": entry.get("timestamp") or "",
        "file": entry.get("file") or "Unknown",
        "risk_score": _parse_risk_score(risk_score_label),
        "risk_score_label": risk_score_label,
        "risk_level": risk_level,
        "ml_prediction": entry.get("ml_prediction") or "Unknown",
        "ml_interpretation": entry.get("ml_interpretation") or "Unknown",
        "static_status": entry.get("static_status") or "Unknown",
        "slither_findings": int(entry.get("slither_findings") or 0),
        "fix_included": bool(entry.get("fix_included")),
        "patch_included": bool(entry.get("patch_included")),
        "status": "COMPLETE",
    }


@app.get("/api/health")
def health():
    return {"status": "ok"}


@app.get("/api/files")
def list_files():
    files = []
    if os.path.exists(UPLOAD_DIR):
        files = [
            name
            for name in os.listdir(UPLOAD_DIR)
            if os.path.isfile(os.path.join(UPLOAD_DIR, name))
            and detect_file_type(name) in ("sol", "pdf", "doc", "txt", "csv", "json", "image")
        ]
    return {"files": sorted(files)}


@app.get("/api/source/{filename}")
def get_source_file(filename: str):
    path = _safe_workspace_path(filename)
    if detect_file_type(filename) != "sol":
        raise HTTPException(status_code=400, detail="Source viewer only supports Solidity files.")
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as source_file:
            return {"filename": filename, "source_code": source_file.read()}
    except OSError as exc:
        raise HTTPException(status_code=500, detail=f"Could not read source file: {exc}") from exc


@app.get("/api/reports")
def list_reports():
    report_dir = os.path.join(UPLOAD_DIR, "reports")
    reports = []
    if os.path.exists(report_dir):
        for name in os.listdir(report_dir):
            if not name.lower().endswith(".pdf"):
                continue
            path = os.path.join(report_dir, name)
            if not os.path.isfile(path):
                continue
            reports.append(
                {
                    "filename": name,
                    "type": _report_type(name),
                    "size": os.path.getsize(path),
                    "modified": os.path.getmtime(path),
                    "download_url": f"/api/download/report/{name}",
                }
            )
    reports.sort(key=lambda item: item["modified"], reverse=True)
    return {"reports": reports}


@app.get("/api/audit-history")
def list_audit_history():
    raw_history = _load_history_entries()
    entries = [
        _format_history_entry(entry, index)
        for index, entry in enumerate(reversed(raw_history))
    ]
    total = len(entries)
    average_risk = round(sum(entry["risk_score"] for entry in entries) / total) if total else 0
    high_risk = len([entry for entry in entries if entry["risk_score"] >= 60])
    fixed = len([entry for entry in entries if entry["fix_included"]])
    return {
        "entries": entries,
        "summary": {
            "total": total,
            "average_risk": average_risk,
            "high_risk": high_risk,
            "fixed": fixed,
        },
    }


@app.post("/api/upload")
async def upload_file(file: UploadFile = File(...)):
    filename = os.path.basename(file.filename or "")
    if not filename:
        raise HTTPException(status_code=400, detail="No file was selected.")
    if detect_file_type(filename) == "unknown":
        raise HTTPException(
            status_code=400,
            detail="Unsupported file type. Use .sol, .pdf, .doc, .docx, .txt, .csv, .json, .png, .jpg, .jpeg, or .webp.",
        )

    os.makedirs(UPLOAD_DIR, exist_ok=True)
    local_path = os.path.join(UPLOAD_DIR, filename)
    try:
        with open(local_path, "wb") as out:
            shutil.copyfileobj(file.file, out)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Upload failed: {exc}") from exc
    finally:
        await file.close()

    try:
        index_status = process_document(local_path)
    except Exception as exc:
        index_status = f"File saved, but indexing skipped: {exc}"

    return {
        "filename": filename,
        "size": os.path.getsize(local_path),
        "status": f"Uploaded {filename}. {index_status}",
    }


@app.post("/api/audit")
def run_audit(request: FilenameRequest):
    result = _audit_solidity_file(request.filename)
    try:
        record_audit_snapshot(
            result["filename"],
            result["risk_text"],
            result["audit_text"],
            None,
            None,
        )
    except Exception:
        pass
    return result


@app.post("/api/fix")
def generate_fix(request: FixRequest):
    _safe_workspace_path(request.filename)
    fix_text, download_update, diff_markdown = suggest_security_fix(
        request.filename,
        request.audit_text,
        request.risk_text,
    )
    fixed_path = _update_value(download_update)
    fixed_filename = os.path.basename(fixed_path) if fixed_path else None
    fix_explanation, _, reaudit = fix_text.partition("\n\n---\n\n")
    try:
        record_audit_snapshot(
            request.filename,
            request.risk_text,
            request.audit_text,
            fix_text,
            diff_markdown,
        )
    except Exception:
        pass
    return {
        "fix_explanation": fix_explanation,
        "reaudit": reaudit,
        "diff_markdown": diff_markdown,
        "fixed_filename": fixed_filename,
    }


@app.get("/api/download/fixed/{filename}")
def download_fixed_file(filename: str):
    safe_name = os.path.basename(filename or "")
    if not safe_name or safe_name != filename:
        raise HTTPException(status_code=400, detail="Invalid filename.")
    path = os.path.join(UPLOAD_DIR, "fixed", safe_name)
    if not os.path.exists(path):
        raise HTTPException(status_code=404, detail=f"Fixed file '{safe_name}' was not found.")
    return FileResponse(path, media_type="text/plain", filename=safe_name)


@app.get("/api/download/report/{filename}")
def download_report_file(filename: str):
    safe_name = os.path.basename(filename or "")
    if not safe_name or safe_name != filename or not safe_name.lower().endswith(".pdf"):
        raise HTTPException(status_code=400, detail="Invalid report filename.")
    path = os.path.join(UPLOAD_DIR, "reports", safe_name)
    if not os.path.exists(path):
        raise HTTPException(status_code=404, detail=f"Report '{safe_name}' was not found.")
    return FileResponse(path, media_type="application/pdf", filename=safe_name)


@app.post("/api/export-report")
def export_report(request: ExportReportRequest):
    extra_sections = [
        ("JSON Trace Analysis", request.trace_text),
        ("Image Security Analysis", request.image_text),
        ("Multi-Agent Investigation", request.investigation_summary),
        ("Attack Replay", request.attack_replay_text),
    ]
    extra_text = "\n\n".join(
        f"## {title}\n\n{text}"
        for title, text in extra_sections
        if text and text.strip()
    )
    csv_explanation = "\n\n".join(
        part
        for part in [request.csv_explanation, extra_text]
        if part and part.strip()
    )
    try:
        report_path = generate_full_audit_report(
            selected_file=request.selected_file,
            risk_dashboard_text=request.risk_text,
            audit_text=request.audit_text,
            fix_text=request.fix_text,
            line_map_text=request.line_map_text,
            patch_diff_text=request.patch_diff_text,
            csv_analysis_text=request.csv_text,
            csv_explanation_text=csv_explanation,
        )
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Report export error: {exc}") from exc

    filename = os.path.basename(report_path)
    return {
        "report_path": report_path,
        "filename": filename,
        "download_url": f"/api/download/report/{filename}",
    }


@app.post("/api/csv-anomaly")
def csv_anomaly(request: FilenameRequest):
    output = run_csv_anomaly_analysis(request.filename)
    risk_score = _extract_csv_metric(r"- Score:\s*\*\*(\d+)\s*/\s*100\*\*", output[0], 0)
    risk_level = _extract_csv_metric(r"- Level:\s*\*\*([^*]+)\*\*", output[0], "Unknown")
    anomalies = _extract_csv_metric(r"- Consensus anomaly rows:\s*`?\[([^\]]*)\]`?", output[0], "")
    anomaly_count = 0 if not anomalies else len([item for item in anomalies.split(",") if item.strip()])
    return {
        "analysis_text": output[0],
        "explanation": output[9],
        "risk_score": int(risk_score),
        "risk_level": risk_level,
        "anomaly_count": anomaly_count,
        "model_path": _workspace_url(_update_value(output[8])),
        "plots": {
            "error_distribution": _workspace_url(output[1]),
            "error_by_row": _workspace_url(output[2]),
            "top_scores": _workspace_url(output[3]),
            "numeric_histograms": _workspace_url(output[4]),
            "numeric_boxplot": _workspace_url(output[5]),
            "column_means_barplot": _workspace_url(output[6]),
            "correlation_heatmap": _workspace_url(output[7]),
        },
    }


@app.post("/api/json-trace")
def json_trace(request: FilenameRequest):
    return {"trace_text": run_json_trace_analysis(request.filename)}


@app.post("/api/correlate/csv-contract")
def correlate_csv_contract(request: CsvContractCorrelationRequest):
    return {
        "correlation_text": correlate_csv_with_contract(
            request.solidity_file,
            request.audit_text,
            request.line_map_text,
            request.csv_text,
            request.row_number,
        )
    }


@app.post("/api/correlate/trace-contract")
def correlate_trace_contract(request: TraceContractCorrelationRequest):
    return {
        "correlation_text": run_trace_contract_correlation_from_state(
            request.solidity_file,
            request.audit_text,
            request.line_map_text,
            request.trace_text,
        )
    }


@app.post("/api/image-security")
def image_security(request: FilenameRequest):
    local_path = _safe_workspace_path(request.filename)
    if detect_file_type(request.filename) != "image":
        raise HTTPException(status_code=400, detail="Select a .png, .jpg, .jpeg, or .webp image.")
    try:
        analysis = analyze_security_image(local_path)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Image analysis error: {exc}") from exc
    metadata = analysis["metadata"]
    classifier = analysis.get("classifier", {})
    return {
        "image_text": format_image_analysis_markdown(analysis),
        "filename": request.filename,
        "image_url": _workspace_url(local_path),
        "risk_score": analysis["risk_score"],
        "risk_level": analysis["risk_level"],
        "classifier_label": classifier.get("label") if classifier.get("available") else "unavailable",
        "classifier_confidence": classifier.get("confidence") if classifier.get("available") else None,
        "ocr_engine": analysis["ocr_engine"],
        "dimensions": f"{metadata['width']}x{metadata['height']}",
    }


@app.post("/api/chat")
def chat(request: ChatRequest):
    selected = request.selected_files if request.selected_files is not None else request.selected_file
    return {"answer": chat_response(request.message, request.history, selected)}


@app.post("/api/investigate")
def investigate(request: InvestigateRequest):
    try:
        from app.auto_investigator import run_auto_investigation

        result = run_auto_investigation(selected_files=request.files)
        return _jsonable(result)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Auto-Investigator error: {exc}") from exc

# LangServe microservice endpoint
add_routes(
    app,
    get_smart_contract_chain(default_retriever),
    path="/assistant",
)

def open_browser_when_ready():
    for _ in range(60):
        try:
            with urllib.request.urlopen(SERVER_URL, timeout=1):
                webbrowser.open_new(SERVER_URL)
                return
        except Exception:
            time.sleep(0.5)
    print(f"Open {SERVER_URL} in your browser.")

# Mount Gradio UI
import gradio as gr
app = gr.mount_gradio_app(app, demo, path="/", css=CSS, js=APP_JS, theme=gr.themes.Base())

if __name__ == "__main__":
    print("--- Server is launching ---")
    if not os.environ.get("DOCKER_CONTAINER"):
        Thread(target=open_browser_when_ready, daemon=True).start()
    uvicorn.run(app, host="0.0.0.0", port=7860)
