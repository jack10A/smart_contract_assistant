import os
import re
from dataclasses import asdict, dataclass, field
from typing import Any

from langchain_core.output_parsers import StrOutputParser
from langchain_core.prompts import ChatPromptTemplate
from langchain_groq import ChatGroq

from app.security_analysis import (
    calculate_risk_score,
    extract_deep_learning_prediction,
    extract_slither_detector_rows,
    format_line_map_markdown,
    format_risk_dashboard_markdown,
)


UPLOAD_DIR = "./workspace_uploads"


@dataclass
class EvidenceItem:
    source: str
    summary: str
    file: str | None = None
    line: int | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class StructuredFinding:
    id: str
    title: str
    severity: str
    confidence: float
    source_agent: str
    file: str | None = None
    category: str | None = None
    status: str = "open"
    evidence: list[EvidenceItem] = field(default_factory=list)
    recommendation: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class AgentResult:
    name: str
    role: str
    status: str
    output: str
    artifacts: dict[str, Any] = field(default_factory=dict)
    findings: list[StructuredFinding] = field(default_factory=list)
    evidence: list[EvidenceItem] = field(default_factory=list)
    metrics: dict[str, Any] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)


@dataclass
class InvestigationState:
    workspace_dir: str = UPLOAD_DIR
    files: list[str] = field(default_factory=list)
    requested_files: list[str] | None = None
    plan: list[str] = field(default_factory=list)
    results: dict[str, AgentResult] = field(default_factory=dict)
    report_path: str | None = None
    execution_log: list[dict[str, Any]] = field(default_factory=list)

    def add_result(self, result: AgentResult) -> None:
        self.results[result.name] = result
        self.execution_log.append(
            {
                "agent": result.name,
                "status": result.status,
                "finding_count": len(result.findings),
                "evidence_count": len(result.evidence),
                "error_count": len(result.errors),
            }
        )

    def all_findings(self) -> list[StructuredFinding]:
        findings: list[StructuredFinding] = []
        for result in self.results.values():
            findings.extend(result.findings)
        return findings

    def all_evidence(self) -> list[EvidenceItem]:
        evidence: list[EvidenceItem] = []
        for result in self.results.values():
            evidence.extend(result.evidence)
            for finding in result.findings:
                evidence.extend(finding.evidence)
        return evidence


def detect_file_type(filename: str) -> str:
    lower = filename.lower()
    if lower.endswith(".sol"):
        return "sol"
    if lower.endswith(".csv"):
        return "csv"
    if lower.endswith(".json"):
        return "json"
    if lower.endswith((".png", ".jpg", ".jpeg", ".webp")):
        return "image"
    if lower.endswith(".pdf"):
        return "pdf"
    if lower.endswith(".doc") or lower.endswith(".docx"):
        return "doc"
    if lower.endswith(".txt"):
        return "txt"
    return "unknown"


def detect_json_type(file_path: str) -> str:
    if not file_path.lower().endswith(".json") or not os.path.exists(file_path):
        return "unknown"

    try:
        import json

        with open(file_path, "r", encoding="utf-8") as json_file:
            payload = json.load(json_file)
    except Exception:
        return "json"

    abi_payload = payload.get("abi") if isinstance(payload, dict) else payload
    if isinstance(abi_payload, list) and any(
        isinstance(item, dict) and item.get("type") in {"function", "event", "constructor"}
        for item in abi_payload
    ):
        return "abi"

    def has_trace_shape(value: Any) -> bool:
        if isinstance(value, list):
            return any(has_trace_shape(item) for item in value[:5])
        if not isinstance(value, dict):
            return False
        trace_keys = {"calls", "children", "subtraces", "type", "callType", "op", "to", "from", "value", "gas"}
        return bool(trace_keys & set(value)) or any(
            has_trace_shape(value.get(key)) for key in ("calls", "children", "subtraces")
        )

    return "trace" if has_trace_shape(payload) else "json"


def workspace_files(workspace_dir: str = UPLOAD_DIR) -> list[str]:
    if not os.path.exists(workspace_dir):
        return []

    files: list[str] = []
    for name in sorted(os.listdir(workspace_dir)):
        path = os.path.join(workspace_dir, name)
        if not os.path.isfile(path):
            continue
        if _is_generated_workspace_artifact(name):
            continue
        if detect_file_type(name) in {"sol", "csv", "json", "image", "pdf", "doc", "txt"}:
            files.append(path)
    return files


def _is_generated_workspace_artifact(name: str) -> bool:
    lower = name.lower()
    stem, _ = os.path.splitext(lower)
    generated_markers = (
        "_fixed",
        "_anomaly_report",
        "_executive_report",
        "_full_audit_report",
        "_autoencoder",
        "_reconstruction_errors",
        "_error_by_row",
        "_top_anomaly_scores",
        "_numeric_histograms",
        "_numeric_boxplot",
        "_column_means_barplot",
        "_correlation_heatmap",
    )
    return (
        lower == "audit_history.json"
        or lower.endswith(".log")
        or any(marker in stem for marker in generated_markers)
    )


def resolve_selected_files(selected_files: list[str] | None, workspace_dir: str = UPLOAD_DIR) -> list[str]:
    resolved: list[str] = []
    for item in selected_files or []:
        path = item if os.path.isabs(item) else os.path.join(workspace_dir, item)
        if os.path.isfile(path):
            resolved.append(path)
    return resolved


def _section(title: str, body: str) -> str:
    return f"### {title}\n\n{body.strip() if body else 'No output.'}"


def _clip_text(text: str | None, limit: int = 5000) -> str:
    if not text:
        return ""
    cleaned = re.sub(r"\n{3,}", "\n\n", text.strip())
    if len(cleaned) <= limit:
        return cleaned
    return cleaned[:limit].rstrip() + "\n\n[Truncated for model token safety.]"


def _extract_bullets(text: str | None, patterns: list[str], limit: int = 12) -> list[str]:
    if not text:
        return []
    hits: list[str] = []
    for line in text.splitlines():
        lower = line.lower()
        if any(pattern in lower for pattern in patterns):
            cleaned = line.strip()
            if cleaned and cleaned not in hits:
                hits.append(cleaned[:240])
        if len(hits) >= limit:
            break
    return hits


def _sanitize_remediation_guidance(text: str) -> str:
    """Remove remediation advice that is unsafe for value-bearing smart-contract randomness."""
    replacement = (
        "Use commit-reveal or a trusted VRF-style randomness source for value-bearing randomness; "
        "do not derive randomness from block.timestamp, block.number, or blockhash."
    )
    replaced = False
    cleaned_lines: list[str] = []
    for line in text.splitlines():
        lower = line.lower()
        mentions_block_entropy = any(token in lower for token in ("block.timestamp", "block.number", "blockhash"))
        recommends_hash_randomness = "keccak256" in lower or ("hash" in lower and "random" in lower)
        recommends_block_randomness = mentions_block_entropy and any(
            token in lower for token in ("random", "randomness", "rng", "generator", "unpredictable", "secure")
        )
        if mentions_block_entropy and (recommends_hash_randomness or recommends_block_randomness):
            replaced = True
            cleaned_lines.append(replacement)
        else:
            cleaned_lines.append(line)
    cleaned = "\n".join(cleaned_lines)
    return re.sub(r"\n{3,}", "\n\n", cleaned).strip()


def _severity_score(severity: str) -> int:
    return {"Critical": 100, "High": 85, "Medium": 55, "Low": 25, "Informational": 5, "Unknown": 0}.get(
        severity,
        0,
    )


def _risk_level_from_score(score: int | float) -> str:
    if score >= 70:
        return "High"
    if score >= 35:
        return "Medium"
    if score > 0:
        return "Low"
    return "Unknown"


def _dedupe_findings(findings: list[StructuredFinding]) -> list[StructuredFinding]:
    deduped: list[StructuredFinding] = []
    seen: set[tuple[str | None, str, str | None]] = set()
    for finding in findings:
        key = (finding.file, finding.title.lower(), finding.category)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(finding)
    return deduped


def _extract_score(pattern: str, text: str | None) -> int | None:
    if not text:
        return None
    match = re.search(pattern, text, flags=re.IGNORECASE)
    if not match:
        return None
    try:
        return int(match.group(1))
    except ValueError:
        return None


def _format_structured_signal(finding: StructuredFinding) -> str:
    file_part = ""
    if finding.file and finding.file.lower() not in finding.title.lower():
        file_part = f" in `{finding.file}`"
    confidence = f"{finding.confidence:.0%}" if finding.confidence else "N/A"
    return f"- **{finding.severity}** {finding.title}{file_part} ({finding.source_agent}, {confidence})"


ATTACK_REPLAY_TEMPLATES: tuple[dict[str, Any], ...] = (
    {
        "keys": ("reentrancy", "reentrancy-eth"),
        "title": "Reentrancy Drain Path",
        "attacker_goal": "Withdraw the same balance more than once before accounting is finalized.",
        "preconditions": [
            "A public or external withdrawal function sends native value to the caller.",
            "The balance update happens after, or is separable from, the external call.",
            "The attacker can receive funds through a fallback or receive function.",
        ],
        "steps": [
            "Attacker deposits enough ETH to create a withdrawable balance.",
            "Attacker calls the vulnerable withdrawal function.",
            "The contract sends ETH to the attacker before the state is fully protected.",
            "The attacker's fallback re-enters the withdrawal function.",
            "The loop repeats until the contract balance or gas limit stops the drain.",
        ],
        "impact": "Contract funds can be drained or user balances can become inconsistent.",
        "fix": "Apply Checks-Effects-Interactions, update balances before the external call, and add a reentrancy guard.",
    },
    {
        "keys": ("controlled-delegatecall", "delegatecall", "dangerous delegatecall"),
        "title": "Delegatecall Takeover Path",
        "attacker_goal": "Execute attacker-controlled code inside the victim contract storage context.",
        "preconditions": [
            "The contract accepts a plugin, target, or implementation address from an untrusted caller.",
            "The contract uses delegatecall with attacker-controlled calldata.",
            "Sensitive storage variables can be modified by delegated code.",
        ],
        "steps": [
            "Attacker deploys a malicious contract with storage-writing logic.",
            "Attacker calls the victim function with the malicious plugin address.",
            "The victim performs delegatecall into attacker code.",
            "The malicious code writes to the victim contract storage layout.",
            "Ownership, balances, approvals, or control flags can be overwritten.",
        ],
        "impact": "The attacker may seize ownership, corrupt accounting, or execute privileged behavior.",
        "fix": "Remove untrusted delegatecall, restrict implementations with allowlists, and prefer normal call boundaries when storage sharing is not required.",
    },
    {
        "keys": ("weak-prng", "timestamp", "timestamp dependency", "incorrect-equality"),
        "title": "Lottery Manipulation Path",
        "attacker_goal": "Influence or time execution around predictable randomness.",
        "preconditions": [
            "Critical logic depends on block.timestamp, block variables, or strict timestamp equality.",
            "The attacker can choose when to submit a transaction.",
            "The payout or privileged path depends on the predictable condition.",
        ],
        "steps": [
            "Attacker observes the condition used by the contract for randomness or eligibility.",
            "Attacker submits transactions only when the timestamp-derived condition is favorable.",
            "A validator or block producer may have limited influence over timestamp selection.",
            "The supposedly random branch becomes predictable enough to exploit.",
        ],
        "impact": "Games, lotteries, auctions, or time-gated permissions can be biased or won unfairly.",
        "fix": "Use a commit-reveal scheme or a trusted randomness source such as VRF for value-bearing randomness.",
    },
    {
        "keys": ("unchecked-lowlevel", "unchecked-send", "low-level"),
        "title": "Silent Call Failure Path",
        "attacker_goal": "Trigger failed external calls while the contract continues as if they succeeded.",
        "preconditions": [
            "The contract uses call, send, delegatecall, or staticcall.",
            "The return value is ignored or not handled correctly.",
            "State changes or business logic continue after a failed call.",
        ],
        "steps": [
            "Attacker makes the low-level call fail through revert behavior, gas behavior, or bad target setup.",
            "The victim contract ignores the false return value.",
            "Accounting, permissions, or workflow state moves forward anyway.",
            "Funds or records become inconsistent with the real external-call outcome.",
        ],
        "impact": "The contract can record success after failure, causing stuck funds or broken accounting.",
        "fix": "Check every low-level call return value, bubble failure when needed, and prefer typed interfaces where possible.",
    },
    {
        "keys": ("integer overflow", "integer-overflow", "integer-underflow", "overflow", "underflow"),
        "title": "Arithmetic Wraparound Path",
        "attacker_goal": "Push arithmetic beyond expected bounds to corrupt balances or limits.",
        "preconditions": [
            "The contract uses Solidity before 0.8 or unchecked arithmetic.",
            "User-controlled values participate in addition, subtraction, or multiplication.",
            "The result controls balances, caps, shares, or permissions.",
        ],
        "steps": [
            "Attacker supplies a value near the numeric boundary.",
            "The contract performs arithmetic without a protective check.",
            "The result wraps around or underflows.",
            "The corrupted value bypasses limits or changes accounting in the attacker's favor.",
        ],
        "impact": "Balances, supply, or authorization limits can become incorrect.",
        "fix": "Use Solidity 0.8+ checked arithmetic or SafeMath for legacy contracts, and validate user-controlled bounds.",
    },
)


def _attack_template_for_finding(finding: StructuredFinding) -> dict[str, Any] | None:
    haystack = " ".join(
        [
            finding.title,
            finding.category or "",
            str(finding.metadata.get("detector", "")),
            " ".join(item.summary for item in finding.evidence),
        ]
    ).lower()
    for template in ATTACK_REPLAY_TEMPLATES:
        if any(key in haystack for key in template["keys"]):
            return template
    return None


def _format_attack_replay_card(index: int, finding: StructuredFinding, template: dict[str, Any]) -> str:
    evidence_rows = []
    for item in finding.evidence[:3]:
        location = f" `{item.file}`" if item.file else ""
        if item.line:
            location += f":{item.line}"
        evidence_rows.append(f"- {item.source}{location}: {item.summary}")
    if not evidence_rows:
        evidence_rows.append(f"- {finding.source_agent}: {finding.title}")

    confidence = f"{finding.confidence:.0%}" if finding.confidence else "N/A"
    return "\n".join(
        [
            f"### {index}. {template['title']}",
            "",
            f"**Finding:** {finding.title}",
            f"**Severity:** {finding.severity}",
            f"**Confidence:** {confidence}",
            f"**File:** `{finding.file or 'Workspace-level'}`",
            "",
            "#### Attacker Goal",
            template["attacker_goal"],
            "",
            "#### Preconditions",
            *[f"- {item}" for item in template["preconditions"]],
            "",
            "#### Replay Steps",
            *[f"{step_index}. {step}" for step_index, step in enumerate(template["steps"], start=1)],
            "",
            "#### Evidence",
            *evidence_rows,
            "",
            "#### Impact",
            template["impact"],
            "",
            "#### Break The Path",
            template["fix"],
        ]
    )


def _attack_replay_card_data(index: int, finding: StructuredFinding, template: dict[str, Any]) -> dict[str, Any]:
    evidence = []
    for item in finding.evidence[:3]:
        evidence.append(
            {
                "source": item.source,
                "file": item.file,
                "line": item.line,
                "summary": item.summary,
            }
        )
    if not evidence:
        evidence.append(
            {
                "source": finding.source_agent,
                "file": finding.file,
                "line": None,
                "summary": finding.title,
            }
        )

    return {
        "index": index,
        "title": template["title"],
        "finding_id": finding.id,
        "finding": finding.title,
        "severity": finding.severity,
        "confidence": finding.confidence,
        "file": finding.file,
        "attacker_goal": template["attacker_goal"],
        "preconditions": template["preconditions"],
        "steps": template["steps"],
        "evidence": evidence,
        "impact": template["impact"],
        "fix": template["fix"],
    }


class CoordinatorAgent:
    name = "coordinator"
    role = "Routes workspace files to specialist security agents."

    def run(self, state: InvestigationState) -> AgentResult:
        selected = resolve_selected_files(state.requested_files, state.workspace_dir)
        state.files = selected or workspace_files(state.workspace_dir)
        file_types = {detect_file_type(path) for path in state.files}
        json_types = {detect_json_type(path) for path in state.files if detect_file_type(path) == "json"}
        plan = ["document_indexer"]
        if "sol" in file_types:
            plan.append("solidity_auditor")
        if "csv" in file_types:
            plan.append("csv_anomaly_agent")
        if "trace" in json_types:
            plan.append("trace_analysis_agent")
        if "image" in file_types:
            plan.append("image_security_agent")
        plan.extend(["correlation_agent", "attack_replay_agent", "remediation_agent", "report_writer"])
        state.plan = plan

        file_summary = ", ".join(
            f"{detect_json_type(path) if detect_file_type(path) == 'json' else detect_file_type(path)}:{os.path.basename(path)}"
            for path in state.files
        )
        scope = "selected files" if selected else "full workspace"
        return AgentResult(
            name=self.name,
            role=self.role,
            status="complete" if state.files else "skipped",
            output=(
                "No workspace files were found."
                if not state.files
                else f"Scope: {scope}\n\nPlanned agents: {', '.join(plan)}\n\nFiles: {file_summary}"
            ),
            artifacts={"file_count": len(state.files), "plan": plan, "scope": scope},
        )


class DocumentIndexerAgent:
    name = "document_indexer"
    role = "Indexes supporting documents and source files for RAG evidence retrieval."

    def run(self, state: InvestigationState) -> AgentResult:
        from app.ingestion import process_document

        statuses: list[str] = []
        for path in state.files:
            if detect_file_type(path) in {"sol", "pdf", "doc", "txt"}:
                try:
                    statuses.append(process_document(path))
                except Exception as exc:
                    statuses.append(f"Indexing skipped for {os.path.basename(path)}: {exc}")

        return AgentResult(
            name=self.name,
            role=self.role,
            status="complete",
            output="\n".join(f"- {status}" for status in statuses) or "No supporting documents needed indexing.",
            artifacts={"indexed_count": len(statuses)},
        )


class SolidityAuditorAgent:
    name = "solidity_auditor"
    role = "Combines CodeBERT, function-level analysis, Slither, and line mapping for Solidity contracts."

    def run(self, state: InvestigationState) -> AgentResult:
        from app.classifier.predict import vulnerability_auditor
        from app.function_analysis import analyze_functions_with_classifier, format_function_analysis_markdown
        from app.slither_analysis import format_slither_report, run_slither_analysis

        reports: list[str] = []
        risk_maps: list[str] = []
        findings: list[StructuredFinding] = []
        evidence: list[EvidenceItem] = []
        errors: list[str] = []

        for path in state.files:
            if detect_file_type(path) != "sol":
                continue
            filename = os.path.basename(path)
            try:
                with open(path, "r", encoding="utf-8", errors="ignore") as source_file:
                    code = source_file.read()
                result = vulnerability_auditor.predict(code)
                audit_md = vulnerability_auditor.format_report(result)
                function_md = format_function_analysis_markdown(
                    analyze_functions_with_classifier(code, vulnerability_auditor)
                )
                slither_md = format_slither_report(run_slither_analysis(path))
                full_audit = f"{audit_md}\n\n---\n\n{function_md}\n\n---\n\n{slither_md}"
                risk_map = "\n\n".join(
                    [
                        format_risk_dashboard_markdown(filename, full_audit, code),
                        format_line_map_markdown(code, full_audit),
                    ]
                )
                risk = calculate_risk_score(full_audit, code)
                signals = risk.get("signals", [])
                primary_signal_categories = {
                    "Reentrancy": {"External value call", "Ether transfer", "State decrement"},
                    "Integer Overflow": {"Unchecked addition", "Unchecked subtraction", "Legacy pragma"},
                    "Timestamp Dependency": {"Timestamp use"},
                    "Dangerous Delegatecall": {"Delegatecall"},
                }.get(risk.get("label", "Unknown"), set())
                ordered_signals = sorted(
                    signals,
                    key=lambda signal: 0 if signal.category in primary_signal_categories else 1,
                )
                signal_evidence = [
                    EvidenceItem(
                        source="source_line",
                        file=filename,
                        line=signal.line,
                        summary=f"{signal.category}: {signal.reason}",
                        metadata={"snippet": signal.snippet},
                    )
                    for signal in ordered_signals[:8]
                ]
                evidence.extend(signal_evidence)
                ml_label = risk.get("label", "Unknown")
                ml_confidence = float(risk.get("confidence", 0.0) or 0.0)
                if ml_label != "Unknown" or risk["slither_counts"]["High"] or risk["slither_counts"]["Medium"]:
                    findings.append(
                        StructuredFinding(
                            id=f"sol-{len(findings) + 1:03d}",
                            title=f"{ml_label} risk in {filename}",
                            severity=risk.get("level", "Unknown"),
                            confidence=ml_confidence,
                            source_agent=self.name,
                            file=filename,
                            category=ml_label,
                            evidence=signal_evidence[:5],
                            recommendation="Review the line-level map, confirm exploitability, then validate generated fixes with Slither and tests.",
                            metadata={
                                "risk_score": risk.get("score"),
                                "deep_learning_prediction": extract_deep_learning_prediction(full_audit),
                                "hybrid_confirmation": risk.get("hybrid_confirmation", {}),
                                "slither_counts": risk.get("slither_counts", {}),
                            },
                        )
                    )
                for row in extract_slither_detector_rows(full_audit):
                    if row["impact"] not in {"High", "Medium"}:
                        continue
                    findings.append(
                        StructuredFinding(
                            id=f"sol-{len(findings) + 1:03d}",
                            title=f"Slither {row['impact']} finding: {row['detector']}",
                            severity=row["impact"],
                            confidence=0.9,
                            source_agent=self.name,
                            file=filename,
                            category=row["detector"],
                            evidence=[
                                EvidenceItem(
                                    source="slither",
                                    file=filename,
                                    summary=f"{row['impact']} impact detector `{row['detector']}` was reported by Slither.",
                                )
                            ],
                            recommendation="Prioritize High and Medium Slither findings before accepting any generated patch.",
                            metadata={"detector": row["detector"], "impact": row["impact"]},
                        )
                    )
                reports.append(_section(f"Solidity audit: {filename}", full_audit))
                risk_maps.append(_section(f"Source risk map: {filename}", risk_map))
            except Exception as exc:
                errors.append(f"{filename}: {exc}")
                reports.append(_section(f"Solidity audit: {filename}", f"Audit error: {exc}"))

        return AgentResult(
            name=self.name,
            role=self.role,
            status="complete" if reports else "skipped",
            output="\n\n".join(reports) if reports else "No Solidity files were found.",
            artifacts={"risk_map_text": "\n\n".join(risk_maps), "audited_files": len(reports)},
            findings=_dedupe_findings(findings),
            evidence=evidence,
            metrics={"audited_files": len(reports), "structured_findings": len(_dedupe_findings(findings))},
            errors=errors,
        )


class CsvAnomalyAgent:
    name = "csv_anomaly_agent"
    role = "Detects anomalous transaction rows with an autoencoder and Isolation Forest consensus."

    def run(self, state: InvestigationState) -> AgentResult:
        from app.csv_anomaly import (
            analyze_csv_dl,
            explain_anomalies_with_llama,
            format_local_anomaly_explanations,
            save_analysis_report_to_workspace,
        )
        from app.ingestion import process_document

        summaries: list[str] = []
        explanations: list[str] = []
        findings: list[StructuredFinding] = []
        evidence: list[EvidenceItem] = []
        errors: list[str] = []

        for path in state.files:
            if detect_file_type(path) != "csv":
                continue
            filename = os.path.basename(path)
            try:
                analysis = analyze_csv_dl(path)
                report_path = save_analysis_report_to_workspace(path, analysis, workspace_dir=state.workspace_dir)
                index_status = process_document(report_path)
                summary = analysis["summary"]
                risk = analysis["risk_score"]
                anomaly_rows = analysis.get("anomalies", [])
                csv_evidence = [
                    EvidenceItem(
                        source="csv_anomaly",
                        file=filename,
                        summary=f"Consensus anomaly rows: {anomaly_rows}",
                        metadata={
                            "autoencoder_anomalies": analysis.get("autoencoder_anomalies", []),
                            "isolation_forest_anomalies": analysis.get("isolation_forest_anomalies", []),
                        },
                    )
                ]
                evidence.extend(csv_evidence)
                if risk["score"] >= 35 or anomaly_rows:
                    findings.append(
                        StructuredFinding(
                            id=f"csv-{len(findings) + 1:03d}",
                            title=f"Transaction anomaly signal in {filename}",
                            severity=risk["level"],
                            confidence=min(0.95, max(0.35, risk["score"] / 100)),
                            source_agent=self.name,
                            file=filename,
                            category="CSV anomaly",
                            evidence=csv_evidence,
                            recommendation="Inspect consensus anomaly rows and correlate them with contract functions, traces, or transaction hashes where available.",
                            metadata={"risk_score": risk["score"], "rows": summary["rows"], "numeric_columns": summary["numeric_columns"]},
                        )
                    )
                summaries.append(
                    _section(
                        f"CSV anomaly analysis: {filename}",
                        "\n".join(
                            [
                                f"- Rows: {summary['rows']}",
                                f"- Numeric columns: {', '.join(summary['numeric_columns'])}",
                                f"- Risk score: {risk['score']}/100 ({risk['level']})",
                                f"- Consensus anomaly rows: {analysis['anomalies']}",
                                f"- Autoencoder flagged rows: {analysis['autoencoder_anomalies']}",
                                f"- Isolation Forest flagged rows: {analysis['isolation_forest_anomalies']}",
                                f"- Searchable report indexed: {os.path.basename(report_path)}",
                                f"- Index status: {index_status}",
                            ]
                        ),
                    )
                )
                local_explanation = format_local_anomaly_explanations(analysis)
                try:
                    llm_explanation = explain_anomalies_with_llama(path, analysis)
                except Exception as exc:
                    llm_explanation = f"Llama explanation unavailable: {exc}"
                explanations.append(_section(filename, f"{local_explanation}\n\n{llm_explanation}"))
            except Exception as exc:
                errors.append(f"{filename}: {exc}")
                summaries.append(_section(f"CSV anomaly analysis: {filename}", f"CSV analysis error: {exc}"))

        return AgentResult(
            name=self.name,
            role=self.role,
            status="complete" if summaries else "skipped",
            output="\n\n".join(summaries) if summaries else "No CSV files were found.",
            artifacts={"csv_explanation": "\n\n".join(explanations)},
            findings=findings,
            evidence=evidence,
            metrics={"analyzed_csv_files": len(summaries), "structured_findings": len(findings)},
            errors=errors,
        )


class TraceAnalysisAgent:
    name = "trace_analysis_agent"
    role = "Analyzes JSON transaction traces and extracts runtime risk behavior."

    def run(self, state: InvestigationState) -> AgentResult:
        from app.trace_analysis import analyze_trace_json, format_trace_analysis_markdown

        reports: list[str] = []
        findings: list[StructuredFinding] = []
        errors: list[str] = []
        for path in state.files:
            if detect_file_type(path) != "json" or detect_json_type(path) != "trace":
                continue
            filename = os.path.basename(path)
            try:
                trace_md = format_trace_analysis_markdown(analyze_trace_json(path, abi_dir=state.workspace_dir))
                risk_score = _extract_score(r"Trace risk score:\s*\*\*(\d+)/100", trace_md)
                if risk_score is not None and risk_score >= 35:
                    findings.append(
                        StructuredFinding(
                            id=f"trace-{len(findings) + 1:03d}",
                            title=f"Runtime trace risk in {filename}",
                            severity=_risk_level_from_score(risk_score),
                            confidence=min(0.9, max(0.35, risk_score / 100)),
                            source_agent=self.name,
                            file=filename,
                            category="Runtime trace",
                            evidence=[
                                EvidenceItem(
                                    source="trace_analysis",
                                    file=filename,
                                    summary=f"Trace risk score: {risk_score}/100",
                                )
                            ],
                            recommendation="Correlate risky runtime behavior with static contract findings and decoded function selectors.",
                            metadata={"risk_score": risk_score},
                        )
                    )
                reports.append(_section(filename, trace_md))
            except Exception as exc:
                errors.append(f"{filename}: {exc}")
                reports.append(_section(filename, f"JSON trace analysis error: {exc}"))

        return AgentResult(
            name=self.name,
            role=self.role,
            status="complete" if reports else "skipped",
            output="\n\n".join(reports) if reports else "No transaction-trace JSON files were found. ABI JSON files were treated as support files.",
            findings=findings,
            metrics={"analyzed_trace_files": len(reports), "structured_findings": len(findings)},
            errors=errors,
        )


class ImageSecurityAgent:
    name = "image_security_agent"
    role = "Classifies security screenshots and extracts phishing indicators with OCR rules."

    def run(self, state: InvestigationState) -> AgentResult:
        from app.image_analysis import analyze_security_image, format_image_analysis_markdown

        reports: list[str] = []
        findings: list[StructuredFinding] = []
        errors: list[str] = []
        for path in state.files:
            if detect_file_type(path) != "image":
                continue
            filename = os.path.basename(path)
            try:
                analysis = analyze_security_image(path)
                image_md = format_image_analysis_markdown(analysis)
                risk_score = int(analysis.get("risk_score") or 0)
                indicators = analysis.get("indicators") or []
                has_entities = bool(analysis.get("addresses") or analysis.get("tx_hashes"))
                classifier = analysis.get("classifier") or {}
                phishing_confidence = (
                    float(classifier.get("confidence", 0.0))
                    if classifier.get("label") == "phishing_page"
                    else 0.0
                )
                has_phishing_signal = (
                    risk_score >= 35
                    or bool(indicators)
                    or has_entities
                    or phishing_confidence >= 0.65
                )
                if has_phishing_signal:
                    severity = _risk_level_from_score(risk_score or 40)
                    findings.append(
                        StructuredFinding(
                            id=f"img-{len(findings) + 1:03d}",
                            title=f"Screenshot security signal in {filename}",
                            severity=severity,
                            confidence=min(0.9, max(0.35, (risk_score or 40) / 100)),
                            source_agent=self.name,
                            file=filename,
                            category="Image security",
                            evidence=[
                                EvidenceItem(
                                    source="image_analysis",
                                    file=filename,
                                    summary=f"Image analysis reported {severity.lower()} security indicators.",
                                )
                            ],
                            recommendation="Use OCR-extracted addresses, transaction hashes, or wallet prompts to guide contract and trace review.",
                            metadata={
                                "risk_score": risk_score,
                                "phishing_signal": has_phishing_signal,
                                "indicators": indicators,
                                "phishing_confidence": phishing_confidence,
                            },
                        )
                    )
                reports.append(_section(filename, image_md))
            except Exception as exc:
                errors.append(f"{filename}: {exc}")
                reports.append(_section(filename, f"Image security analysis error: {exc}"))

        return AgentResult(
            name=self.name,
            role=self.role,
            status="complete" if reports else "skipped",
            output="\n\n".join(reports) if reports else "No image files were found.",
            findings=findings,
            metrics={"analyzed_image_files": len(reports), "structured_findings": len(findings)},
            errors=errors,
        )


class CorrelationAgent:
    name = "correlation_agent"
    role = "Connects static, runtime, CSV, image, and RAG evidence into cross-domain findings."

    def run(self, state: InvestigationState) -> AgentResult:
        solidity = state.results.get("solidity_auditor")
        csv = state.results.get("csv_anomaly_agent")
        trace = state.results.get("trace_analysis_agent")
        image = state.results.get("image_security_agent")
        structured_findings = [
            finding
            for finding in state.all_findings()
            if finding.source_agent != self.name and _severity_score(finding.severity) >= 35
        ]
        structured_by_agent: dict[str, list[StructuredFinding]] = {}
        for finding in structured_findings:
            structured_by_agent.setdefault(finding.source_agent, []).append(finding)

        rows = [
            "### Cross-Domain Evidence Correlation",
            "",
            "This agent connects the specialist outputs without sending the full workspace back to the LLM.",
            "",
        ]

        solidity_hits = [_format_structured_signal(finding) for finding in structured_by_agent.get("solidity_auditor", [])[:8]]
        csv_hits = [_format_structured_signal(finding) for finding in structured_by_agent.get("csv_anomaly_agent", [])[:8]]
        trace_hits = [_format_structured_signal(finding) for finding in structured_by_agent.get("trace_analysis_agent", [])[:8]]
        image_hits = [_format_structured_signal(finding) for finding in structured_by_agent.get("image_security_agent", [])[:8]]

        if not solidity_hits and solidity:
            solidity_hits = _extract_bullets(
                solidity.output,
                ["reentrancy", "delegatecall", "timestamp", "overflow", "access", "slither", "finding", "risk score"],
            )
        if not csv_hits and csv:
            csv_hits = _extract_bullets(
                csv.output,
                ["risk score", "consensus anomaly", "autoencoder", "isolation forest", "row"],
            )
        if not trace_hits and trace:
            trace_hits = _extract_bullets(
                trace.output,
                ["delegatecall", "value transfer", "external calls", "failed", "risk score", "decoded functions"],
            )
        if not image_hits and image and image.findings:
            image_hits = _extract_bullets(
                image.output,
                ["**phishing language**", "**wallet approval**", "addresses: `['0x", "transaction hashes: `['0x"],
            )

        if solidity_hits:
            rows.extend(["#### Solidity signals", *solidity_hits, ""])
        if csv_hits:
            rows.extend(["#### CSV anomaly signals", *csv_hits, ""])
        if trace_hits:
            rows.extend(["#### Runtime trace signals", *trace_hits, ""])
        if image_hits:
            rows.extend(["#### Image security signals", *image_hits, ""])

        if not any([solidity_hits, csv_hits, trace_hits, image_hits]):
            rows.append("No strong cross-domain signals were available yet. Upload multiple file types and rerun the investigation.")

        domains = sorted({finding.source_agent for finding in structured_findings})
        correlation_findings: list[StructuredFinding] = []
        if len(domains) >= 2:
            rows.extend(
                [
                    "#### Structured correlation",
                    f"- Correlated finding domains: {', '.join(domains)}",
                    f"- Medium-or-higher structured findings: {len(structured_findings)}",
                    "",
                ]
            )
            top_findings = sorted(structured_findings, key=lambda finding: _severity_score(finding.severity), reverse=True)[:5]
            correlation_findings.append(
                StructuredFinding(
                    id="corr-001",
                    title="Cross-domain security signal",
                    severity=max((finding.severity for finding in top_findings), key=_severity_score, default="Medium"),
                    confidence=min(0.95, 0.45 + len(domains) * 0.15),
                    source_agent=self.name,
                    category="Cross-domain correlation",
                    evidence=[
                        EvidenceItem(
                            source=finding.source_agent,
                            file=finding.file,
                            summary=f"{finding.severity}: {finding.title}",
                            metadata={"finding_id": finding.id, "category": finding.category},
                        )
                        for finding in top_findings
                    ],
                    recommendation="Review the linked static, runtime, tabular, and image signals together before closing the investigation.",
                    metadata={"domains": domains, "correlated_finding_count": len(structured_findings)},
                )
            )

        trace_correlation = ""
        if solidity and trace:
            try:
                from app.trace_analysis import correlate_trace_with_audit

                trace_correlation = correlate_trace_with_audit(
                    _clip_text(solidity.output, 6000),
                    _clip_text(solidity.artifacts.get("risk_map_text", ""), 5000),
                    _clip_text(trace.output, 4000),
                )
            except Exception as exc:
                trace_correlation = f"Trace correlation unavailable: {exc}"

        return AgentResult(
            name=self.name,
            role=self.role,
            status="complete",
            output="\n\n".join(part for part in ["\n".join(rows), trace_correlation] if part),
            findings=correlation_findings,
            metrics={
                "correlated_domains": domains,
                "input_structured_findings": len(structured_findings),
                "structured_findings": len(correlation_findings),
            },
        )


class AttackReplayAgent:
    name = "attack_replay_agent"
    role = "Turns structured findings into attacker-style exploit path walkthroughs."

    def run(self, state: InvestigationState) -> AgentResult:
        candidate_findings = [
            finding
            for finding in state.all_findings()
            if finding.source_agent not in {self.name, "correlation_agent"}
            and (
                _severity_score(finding.severity) >= 35
                or int(finding.metadata.get("risk_score") or 0) >= 35
                or _attack_template_for_finding(finding) is not None
            )
        ]
        replay_cards: list[str] = []
        replay_card_data: list[dict[str, Any]] = []
        replay_evidence: list[EvidenceItem] = []
        covered_paths: set[tuple[str, str | None]] = set()

        for finding in sorted(candidate_findings, key=lambda item: _severity_score(item.severity), reverse=True):
            template = _attack_template_for_finding(finding)
            if not template:
                continue
            key = (template["title"], finding.file)
            if key in covered_paths:
                continue
            covered_paths.add(key)
            replay_index = len(replay_cards) + 1
            replay_cards.append(_format_attack_replay_card(replay_index, finding, template))
            replay_card_data.append(_attack_replay_card_data(replay_index, finding, template))
            replay_evidence.append(
                EvidenceItem(
                    source=self.name,
                    file=finding.file,
                    summary=f"{template['title']} generated from {finding.id}: {finding.title}",
                    metadata={
                        "finding_id": finding.id,
                        "attack_path": template["title"],
                        "source_agent": finding.source_agent,
                    },
                )
            )

        if not replay_cards:
            return AgentResult(
                name=self.name,
                role=self.role,
                status="skipped",
                output="No attack replay was generated because no supported exploit pattern was found.",
                metrics={"replay_count": 0},
            )

        output = "\n\n".join(
            [
                "## Attack Replay",
                "These paths are educational exploit narratives derived from structured findings. They are not proof-of-exploit and must be validated manually.",
                *replay_cards,
            ]
        )
        return AgentResult(
            name=self.name,
            role=self.role,
            status="complete",
            output=output,
            evidence=replay_evidence,
            metrics={"replay_count": len(replay_cards), "input_findings": len(candidate_findings)},
            artifacts={"attack_replay_text": output, "attack_replay_cards": replay_card_data},
        )


class RemediationAgent:
    name = "remediation_agent"
    role = "Generates concise remediation guidance from the specialist audit outputs."

    def run(self, state: InvestigationState) -> AgentResult:
        solidity = state.results.get("solidity_auditor")
        if not solidity or solidity.status == "skipped":
            return AgentResult(
                name=self.name,
                role=self.role,
                status="skipped",
                output="No automated fix guidance was generated because no usable Solidity audit was available.",
            )

        if not os.getenv("GROQ_API_KEY"):
            return AgentResult(
                name=self.name,
                role=self.role,
                status="skipped",
                output="No automated fix guidance was generated because GROQ_API_KEY is not configured.",
            )

        prompt = ChatPromptTemplate.from_template(
            """
ROLE: Senior Solidity Security Engineer.
Given these multi-agent security findings, write concise remediation guidance.
Do not invent line numbers. Focus on secure patterns and manual review priorities.
Do not recommend hashing block.timestamp, block.number, or blockhash as secure randomness.
Do not recommend transfer or send as the primary reentrancy fix; prefer Checks-Effects-Interactions, ReentrancyGuard, pull payments, and checked call return values.
For delegatecall, prefer removing untrusted delegatecall, using allowlisted implementations, and validating storage-layout risk.
For low-level calls, require success checks and failure handling.
For legacy Solidity, recommend migration to Solidity 0.8+ with targeted compatibility review.

SOLIDITY AUDIT:
{audit_text}

CROSS-DOMAIN EVIDENCE:
{evidence_text}
"""
        )
        llm = ChatGroq(
            groq_api_key=os.getenv("GROQ_API_KEY"),
            model_name="llama-3.1-8b-instant",
            temperature=0,
            max_tokens=700,
        )
        evidence = state.results.get("correlation_agent")
        attack_replay = state.results.get("attack_replay_agent")
        try:
            output = (prompt | llm | StrOutputParser()).invoke(
                {
                    "audit_text": _clip_text(solidity.output, 5500),
                    "evidence_text": _clip_text(
                        "\n\n".join(
                            part
                            for part in [
                                evidence.output if evidence else "No cross-domain evidence.",
                                attack_replay.output if attack_replay and attack_replay.status != "skipped" else "",
                            ]
                            if part
                        ),
                        3500,
                    ),
                }
            )
        except Exception as exc:
            output = (
                "LLM remediation guidance was skipped because the provider rejected the request. "
                f"Provider error: {exc}\n\n"
                "Deterministic next steps:\n"
                "- Review High and Medium Slither findings first.\n"
                "- Prioritize reentrancy, untrusted delegatecall, unchecked external calls, timestamp dependence, and access-control issues.\n"
                "- Fix reentrancy with Checks-Effects-Interactions, ReentrancyGuard, or pull-payment patterns.\n"
                "- Replace timestamp-based randomness with commit-reveal or VRF-style randomness for value-bearing flows.\n"
                "- Check low-level call success values and handle failures explicitly.\n"
                "- Generate fixes per contract, then rerun Slither and the function-level classifier."
            )
        return AgentResult(name=self.name, role=self.role, status="complete", output=_sanitize_remediation_guidance(output))


class ReportWriterAgent:
    name = "report_writer"
    role = "Synthesizes all specialist outputs and exports the executive report."

    def run(self, state: InvestigationState) -> AgentResult:
        from app.reporting import generate_executive_report

        coordinator = state.results.get("coordinator")
        solidity = state.results.get("solidity_auditor")
        csv = state.results.get("csv_anomaly_agent")
        attack_replay = state.results.get("attack_replay_agent")
        remediation = state.results.get("remediation_agent")

        risk_dashboard_text = ""
        if solidity:
            risk_dashboard_text = solidity.artifacts.get("risk_map_text", "")

        risk = compute_overall_risk(state)
        investigation_summary = "\n".join(
            [
                f"Overall investigation risk: {risk['score']}/100 ({risk['level']})",
                f"Files inspected: {coordinator.artifacts.get('file_count', 0) if coordinator else 0}",
                f"Scope: {coordinator.artifacts.get('scope', 'unknown') if coordinator else 'unknown'}",
                f"Primary drivers: {', '.join(risk['drivers']) if risk['drivers'] else 'No high-confidence risk drivers found.'}",
                f"Agents executed: {', '.join(state.plan)}",
            ]
        )

        report_path = generate_executive_report(
            selected_file="multi_agent_workspace",
            risk_dashboard_text=risk_dashboard_text or "No Solidity risk dashboard was generated.",
            audit_text=solidity.output if solidity else "No Solidity audit was run.",
            fix_text="\n\n".join(
                part
                for part in [
                    attack_replay.output if attack_replay and attack_replay.status != "skipped" else "",
                    remediation.output if remediation else "No remediation guidance was generated.",
                ]
                if part
            ),
            csv_analysis_text=csv.output if csv else "No CSV anomaly analysis was run.",
            csv_explanation_text=csv.artifacts.get("csv_explanation", "") if csv else "",
            investigation_summary_text=investigation_summary,
        )
        state.report_path = report_path

        manifest = [
            "### Multi-Agent Investigation Manifest",
            "",
            f"- Files inspected: {coordinator.artifacts.get('file_count', 0) if coordinator else 0}",
            f"- Agents executed: {', '.join(state.plan)}",
            f"- Structured findings recorded: {len(state.all_findings())}",
            f"- Evidence items recorded: {len(state.all_evidence())}",
            f"- Executive report: `{report_path}`",
        ]
        return AgentResult(
            name=self.name,
            role=self.role,
            status="complete",
            output="\n".join(manifest),
            artifacts={"report_path": report_path},
        )


class MultiAgentInvestigator:
    def __init__(self, workspace_dir: str = UPLOAD_DIR, selected_files: list[str] | None = None):
        self.workspace_dir = workspace_dir
        self.selected_files = selected_files
        self.agents = {
            "coordinator": CoordinatorAgent(),
            "document_indexer": DocumentIndexerAgent(),
            "solidity_auditor": SolidityAuditorAgent(),
            "csv_anomaly_agent": CsvAnomalyAgent(),
            "trace_analysis_agent": TraceAnalysisAgent(),
            "image_security_agent": ImageSecurityAgent(),
            "correlation_agent": CorrelationAgent(),
            "attack_replay_agent": AttackReplayAgent(),
            "remediation_agent": RemediationAgent(),
            "report_writer": ReportWriterAgent(),
        }

    def run(self) -> dict[str, Any]:
        state = InvestigationState(workspace_dir=self.workspace_dir, requested_files=self.selected_files)
        coordinator_result = self.agents["coordinator"].run(state)
        state.add_result(coordinator_result)
        if not state.files:
            return {
                "summary": coordinator_result.output,
                "report_path": None,
                "agents": state.results,
                "findings": [],
                "evidence": [],
                "execution_log": state.execution_log,
            }

        for agent_name in state.plan:
            if agent_name == "coordinator":
                continue
            result = self.agents[agent_name].run(state)
            state.add_result(result)

        return {
            "summary": format_multi_agent_summary(state),
            "report_path": state.report_path,
            "agents": state.results,
            "findings": [asdict(finding) for finding in state.all_findings()],
            "evidence": [asdict(item) for item in state.all_evidence()],
            "execution_log": state.execution_log,
            "metrics": {
                "agent_count": len(state.results),
                "finding_count": len(state.all_findings()),
                "evidence_count": len(state.all_evidence()),
            },
            "audit_text": state.results.get("solidity_auditor", AgentResult("", "", "", "")).output,
            "csv_text": state.results.get("csv_anomaly_agent", AgentResult("", "", "", "")).output,
            "csv_explanation": state.results.get("csv_anomaly_agent", AgentResult("", "", "", "")).artifacts.get(
                "csv_explanation", ""
            ),
            "fix_text": state.results.get("remediation_agent", AgentResult("", "", "", "")).output,
            "evidence_text": state.results.get("correlation_agent", AgentResult("", "", "", "")).output,
            "attack_replay_text": state.results.get("attack_replay_agent", AgentResult("", "", "", "")).output,
            "attack_replay_cards": state.results.get("attack_replay_agent", AgentResult("", "", "", "")).artifacts.get(
                "attack_replay_cards",
                [],
            ),
            "risk_map_text": state.results.get("solidity_auditor", AgentResult("", "", "", "")).artifacts.get(
                "risk_map_text", ""
            ),
        }


def format_multi_agent_summary(state: InvestigationState) -> str:
    risk = compute_overall_risk(state)
    findings = sorted(state.all_findings(), key=lambda finding: _severity_score(finding.severity), reverse=True)
    rows = [
        "## Multi-Agent Auto-Investigation Complete",
        "",
        "### Executive Summary",
        "",
        f"- Overall investigation risk: **{risk['score']}/100 ({risk['level']})**",
        f"- Files inspected: **{len(state.files)}**",
        f"- Structured findings: **{len(findings)}**",
        f"- Scope: **{state.results.get('coordinator', AgentResult('', '', '', '')).artifacts.get('scope', 'unknown')}**",
        f"- Primary drivers: {', '.join(risk['drivers']) if risk['drivers'] else 'No high-confidence risk drivers found.'}",
        f"- Report path: `{state.report_path or 'No report generated yet'}`",
        "",
        "| Agent | Role | Status |",
        "|---|---|---|",
    ]
    for agent_name in ["coordinator", *state.plan]:
        result = state.results.get(agent_name)
        if not result:
            continue
        status = result.status if not result.errors else f"{result.status} ({len(result.errors)} error(s))"
        rows.append(f"| `{result.name}` | {result.role} | **{status}** |")

    if findings:
        rows.extend(
            [
                "",
                "### Structured Finding Ledger",
                "",
                "| ID | Severity | Confidence | Source | File | Finding |",
                "|---|---|---:|---|---|---|",
            ]
        )
        for finding in findings[:12]:
            confidence = f"{finding.confidence:.0%}" if finding.confidence else "N/A"
            rows.append(
                "| "
                f"`{finding.id}` | "
                f"{finding.severity} | "
                f"{confidence} | "
                f"`{finding.source_agent}` | "
                f"`{finding.file or '-'}` | "
                f"{finding.title} |"
            )

    rows.append("")
    report_writer = state.results.get("report_writer")
    if report_writer:
        rows.append(report_writer.output)
        rows.append("")

    ordered_outputs = [
        "coordinator",
        "solidity_auditor",
        "csv_anomaly_agent",
        "trace_analysis_agent",
        "image_security_agent",
        "correlation_agent",
        "attack_replay_agent",
        "remediation_agent",
    ]
    for agent_name in ordered_outputs:
        result = state.results.get(agent_name)
        if not result or result.status == "skipped":
            continue
        title = result.name.replace("_", " ").title()
        rows.extend([f"## {title}", "", result.output, ""])

    finding_count = len(re.findall(r"Finding:", state.results.get("solidity_auditor", AgentResult("", "", "", "")).output, flags=re.IGNORECASE))
    rows.extend(
        [
            "## Investigation Snapshot",
            "",
            f"- Files inspected: **{len(state.files)}**",
            f"- Overall risk score: **{risk['score']}/100 ({risk['level']})**",
            f"- Structured findings recorded: **{len(findings)}**",
            f"- Solidity finding markers detected: **{finding_count}**",
            f"- Evidence items recorded: **{len(state.all_evidence())}**",
            f"- Report path: `{state.report_path or 'No report generated'}`",
        ]
    )
    return "\n".join(rows)


def compute_overall_risk(state: InvestigationState) -> dict[str, Any]:
    drivers: list[str] = []
    score = 0
    findings = state.all_findings()

    if findings:
        top_findings = sorted(findings, key=lambda finding: _severity_score(finding.severity), reverse=True)[:8]
        for finding in top_findings:
            weighted_score = _severity_score(finding.severity) * max(0.25, min(1.0, finding.confidence or 0.5))
            score += round(weighted_score * 0.18)
        score = min(70, score)

        high_count = sum(1 for finding in findings if finding.severity in {"Critical", "High"})
        medium_count = sum(1 for finding in findings if finding.severity == "Medium")
        if high_count:
            drivers.append(f"{high_count} high-impact structured finding(s)")
        if medium_count:
            drivers.append(f"{medium_count} medium-impact structured finding(s)")
        if high_count >= 3:
            score = max(score, 75)
        elif high_count:
            score = max(score, 70)
        elif medium_count >= 3:
            score = max(score, 55)

        domains = sorted({finding.source_agent for finding in findings if _severity_score(finding.severity) >= 35})
        if len(domains) >= 2:
            score += min(20, len(domains) * 6)
            drivers.append(f"cross-domain evidence from {len(domains)} agent(s)")

    combined = "\n".join(result.output for result in state.results.values())
    high_slither = len(re.findall(r"\|\s*High\s*\|", combined, flags=re.IGNORECASE))
    medium_slither = len(re.findall(r"\|\s*Medium\s*\|", combined, flags=re.IGNORECASE))
    if not findings:
        score += min(45, high_slither * 12 + medium_slither * 5)
        if high_slither:
            drivers.append(f"{high_slither} high-impact Slither finding(s)")
        elif medium_slither:
            drivers.append(f"{medium_slither} medium-impact Slither finding(s)")

    csv_scores = [int(match.group(1)) for match in re.finditer(r"Risk score:\s*(\d+)/100", combined, flags=re.IGNORECASE)]
    if csv_scores:
        max_csv = max(csv_scores)
        score += min(20, round(max_csv * 0.2))
        if max_csv >= 70:
            score = max(score, 60)
            drivers.append("high CSV/image/trace risk score")

    trace_score_match = re.search(r"Trace risk score:\s*\*\*(\d+)/100", combined, flags=re.IGNORECASE)
    if trace_score_match:
        trace_score = int(trace_score_match.group(1))
        score += min(15, round(trace_score * 0.15))
        if trace_score >= 70:
            score = max(score, 55)
            drivers.append("high-risk transaction trace")

    image_findings = [
        finding
        for finding in findings
        if finding.source_agent == "image_security_agent" and _severity_score(finding.severity) >= 35
    ]
    if image_findings:
        score += 12
        if any(_severity_score(finding.severity) >= 70 for finding in image_findings):
            score = max(score, 65)
        else:
            score = max(score, 40)
        drivers.append("phishing screenshot indicators")
    elif not findings:
        phishing_confidences = [
            float(match.group(1))
            for match in re.finditer(r"phishing_page\**\s*\((\d+(?:\.\d+)?)%\)", combined, flags=re.IGNORECASE)
        ]
        if re.search(r"Phishing language", combined, flags=re.IGNORECASE):
            score += 12
            if phishing_confidences and max(phishing_confidences) >= 90:
                score = max(score, 55)
            elif phishing_confidences and max(phishing_confidences) >= 70:
                score = max(score, 40)
            if re.search(r"Risk score:\s*\*\*(?:7\d|8\d|9\d|100)/100", combined, flags=re.IGNORECASE):
                score = max(score, 65)
            drivers.append("phishing screenshot indicators")

    if re.search(r"Strong match", combined, flags=re.IGNORECASE):
        score += 12
        drivers.append("cross-domain evidence match")

    score = max(0, min(100, score))
    if score >= 70:
        level = "High"
    elif score >= 35:
        level = "Medium"
    else:
        level = "Low"

    deduped_drivers = []
    for driver in drivers:
        if driver not in deduped_drivers:
            deduped_drivers.append(driver)

    return {"score": score, "level": level, "drivers": deduped_drivers[:5]}
