import difflib
import os
import re
from dataclasses import dataclass
from typing import Any


VULNERABILITY_PATTERNS: dict[str, list[tuple[str, re.Pattern[str], str]]] = {
    "Reentrancy": [
        ("External value call", re.compile(r"\.call(\s*\{|\.value|\s*\()", re.IGNORECASE), "Review for Checks-Effects-Interactions and reentrancy guards."),
        ("Ether transfer", re.compile(r"\.(send|transfer)\s*\(", re.IGNORECASE), "Confirm state changes happen before value transfer."),
        ("State decrement", re.compile(r"\b\w+\s*(?:\[.+?\])?\s*-=", re.IGNORECASE), "If this follows an external call, it may leave reentrancy exposure."),
    ],
    "Integer Overflow": [
        ("Unchecked addition", re.compile(r"\b(?:uint|uint256|int|int256)?\s*\w+\s*(?:=|\+=).*\+", re.IGNORECASE), "Use Solidity 0.8+ checked math or explicit bounds."),
        ("Unchecked subtraction", re.compile(r"\b(?:uint|uint256|int|int256)?\s*\w+\s*(?:=|-=).*-", re.IGNORECASE), "Check for underflow on user-controlled values."),
        ("Legacy pragma", re.compile(r"pragma\s+solidity\s+[^;]*(?:0\.[0-7]|>=\s*0\.[0-7]|\^\s*0\.[0-7])", re.IGNORECASE), "Solidity before 0.8 does not include built-in overflow checks."),
    ],
    "Timestamp Dependency": [
        ("Timestamp use", re.compile(r"\b(block\.timestamp|now)\b", re.IGNORECASE), "Avoid using miner-influenced time for randomness or critical authorization."),
    ],
    "Dangerous Delegatecall": [
        ("Delegatecall", re.compile(r"\.delegatecall\s*\(", re.IGNORECASE), "Delegatecall executes callee code in this contract storage context."),
    ],
}

ATTACK_SURFACE_PATTERNS: list[tuple[str, re.Pattern[str], str]] = [
    ("Public/external function", re.compile(r"\bfunction\s+\w+\s*\([^)]*\).*?\b(public|external)\b", re.IGNORECASE), "Public entrypoint."),
    ("Payable entrypoint", re.compile(r"\bfunction\s+\w+\s*\([^)]*\).*?\bpayable\b", re.IGNORECASE), "Receives native value."),
    ("Owner/admin gate", re.compile(r"\b(onlyOwner|owner|admin|hasRole|DEFAULT_ADMIN_ROLE)\b", re.IGNORECASE), "Access-control signal."),
    ("Low-level call", re.compile(r"\.call(\s*\{|\.value|\s*\()", re.IGNORECASE), "Low-level external interaction."),
]

SLITHER_CONFIRMATION_KEYWORDS: dict[str, tuple[str, ...]] = {
    "Reentrancy": ("reentrancy",),
    "Integer Overflow": ("overflow", "underflow", "divide-before-multiply"),
    "Timestamp Dependency": ("timestamp", "weak-prng"),
    "Dangerous Delegatecall": ("delegatecall", "controlled-delegatecall"),
}

SOURCE_CONFIRMATION_CATEGORIES: dict[str, tuple[str, ...]] = {
    "Reentrancy": ("External value call", "Ether transfer", "State decrement"),
    "Integer Overflow": ("Unchecked addition", "Unchecked subtraction", "Legacy pragma"),
    "Timestamp Dependency": ("Timestamp use",),
    "Dangerous Delegatecall": ("Delegatecall",),
}

DETECTOR_TO_ISSUE: dict[str, str] = {
    "controlled-delegatecall": "Dangerous Delegatecall",
    "reentrancy-eth": "Reentrancy",
    "reentrancy-no-eth": "Reentrancy",
    "weak-prng": "Timestamp Dependency",
    "timestamp": "Timestamp Dependency",
    "integer-overflow": "Integer Overflow",
    "integer-underflow": "Integer Overflow",
    "unchecked-lowlevel": "Unchecked Low-Level Call",
    "unchecked-send": "Unchecked Send",
    "incorrect-equality": "Dangerous Equality Check",
}


@dataclass(frozen=True)
class LineSignal:
    line: int
    category: str
    snippet: str
    reason: str


def extract_audit_label(audit_text: str | None) -> str | None:
    if not audit_text:
        return None
    match = re.search(r"\**Finding:\**\s*(?:[^\w\n|]+)?\s*([A-Za-z ]+)", audit_text)
    if match:
        label = match.group(1).strip().replace("*", "")
        for known in VULNERABILITY_PATTERNS:
            if known.lower() in label.lower():
                return known
        return label or None

    for known in VULNERABILITY_PATTERNS:
        if re.search(rf"\b{re.escape(known)}\b", audit_text, flags=re.IGNORECASE):
            return known
    return None


def extract_confidence(audit_text: str | None) -> float:
    if not audit_text:
        return 0.0
    match = re.search(r"Confidence:\*\*?\s*([0-9]+(?:\.[0-9]+)?)%", audit_text)
    if not match:
        match = re.search(r"Confidence:\s*([0-9]+(?:\.[0-9]+)?)%", audit_text)
    return float(match.group(1)) / 100 if match else 0.0


def extract_deep_learning_prediction(audit_text: str | None) -> str:
    if not audit_text:
        return "Unknown"

    match = re.search(r"\**Finding:\**\s*(.+)", audit_text)
    if not match:
        match = re.search(r"Finding:\s*(.+)", audit_text)
    if not match:
        return "Unknown"

    finding = match.group(1).strip().replace("*", "")
    for known in VULNERABILITY_PATTERNS:
        if known.lower() in finding.lower():
            return known
    return finding or "Unknown"


def extract_slither_high_impact_findings(audit_text: str | None) -> list[str]:
    if not audit_text or "Slither Static Analysis" not in audit_text:
        return []

    findings: list[str] = []
    for line in _slither_section_lines(audit_text):
        stripped = line.strip()
        if not stripped.startswith("| High |"):
            continue
        columns = [column.strip().strip("`") for column in stripped.strip("|").split("|")]
        if len(columns) >= 3 and columns[2] not in findings:
            findings.append(columns[2])
    return findings


def extract_slither_impact_counts(audit_text: str | None) -> dict[str, int]:
    counts = {"High": 0, "Medium": 0, "Low": 0, "Informational": 0, "Optimization": 0}
    if not audit_text or "Slither Static Analysis" not in audit_text:
        return counts

    for line in _slither_section_lines(audit_text):
        stripped = line.strip()
        if not stripped.startswith("|"):
            continue
        columns = [column.strip().strip("`") for column in stripped.strip("|").split("|")]
        if len(columns) < 3:
            continue
        impact = columns[0]
        if impact in counts:
            counts[impact] += 1
    return counts


def _slither_section_lines(audit_text: str | None) -> list[str]:
    if not audit_text:
        return []

    lines = audit_text.splitlines()
    start_index = None
    for index, line in enumerate(lines):
        if "Slither Static Analysis" in line:
            start_index = index + 1
            break
    if start_index is None:
        return []

    section: list[str] = []
    for line in lines[start_index:]:
        if line.startswith("### ") and "Slither Static Analysis" not in line:
            break
        section.append(line)
    return section


def extract_slither_detectors(audit_text: str | None) -> list[str]:
    return [row["detector"] for row in extract_slither_detector_rows(audit_text)]


def extract_slither_detector_rows(audit_text: str | None) -> list[dict[str, str]]:
    if not audit_text or "Slither Static Analysis" not in audit_text:
        return []

    detectors: list[dict[str, str]] = []
    for line in _slither_section_lines(audit_text):
        stripped = line.strip()
        if not stripped.startswith("|") or stripped.startswith("|---"):
            continue
        columns = [column.strip().strip("`") for column in stripped.strip("|").split("|")]
        if len(columns) < 3 or columns[0] == "Impact":
            continue
        detector = columns[2]
        if detector and detector not in {row["detector"] for row in detectors}:
            detectors.append({"impact": columns[0], "detector": detector})
    return detectors


def hybrid_confirmation_summary(label: str | None, audit_text: str | None, signals: list[LineSignal]) -> dict[str, str]:
    if label not in SLITHER_CONFIRMATION_KEYWORDS:
        return {
            "level": "Unknown",
            "summary": "No recognized ML class is available for hybrid confirmation.",
        }

    detector_rows = extract_slither_detector_rows(audit_text)
    detectors = [row["detector"] for row in detector_rows]
    detector_text = " ".join(detectors).lower()
    slither_keywords = SLITHER_CONFIRMATION_KEYWORDS[label]
    matched_detector_rows = [
        row
        for row in detector_rows
        if any(keyword in row["detector"].lower() for keyword in slither_keywords)
    ]
    strong_matched_detectors = [
        row["detector"]
        for row in matched_detector_rows
        if row["impact"] in {"High", "Medium"}
    ]
    weak_matched_detectors = [
        row["detector"]
        for row in matched_detector_rows
        if row["impact"] not in {"High", "Medium"}
    ]

    source_categories = SOURCE_CONFIRMATION_CATEGORIES.get(label, ())
    matched_source = [
        signal.category
        for signal in signals
        if signal.category in source_categories
    ]
    unique_source = sorted(set(matched_source))

    if strong_matched_detectors:
        return {
            "level": "Confirmed",
            "summary": f"High/medium Slither detector(s) support the ML prediction: {', '.join(strong_matched_detectors)}.",
        }
    if weak_matched_detectors:
        return {
            "level": "Weakly supported",
            "summary": f"Only low/informational Slither detector(s) match the ML class: {', '.join(weak_matched_detectors)}.",
        }
    if unique_source:
        return {
            "level": "Supported",
            "summary": f"Source patterns support the ML prediction: {', '.join(unique_source)}.",
        }
    if detector_text:
        return {
            "level": "Not directly confirmed",
            "summary": "Slither found issues, but not detectors that directly match the ML class.",
        }
    return {
        "level": "Unconfirmed",
        "summary": "No matching Slither detector or source pattern was found for the ML class.",
    }


def summarize_detected_issues(audit_text: str | None, ml_label: str | None) -> list[str]:
    issues: dict[str, str] = {}
    normalized_ml_label = (ml_label or "").strip().lower()
    if normalized_ml_label and normalized_ml_label != "unknown":
        issues[ml_label.strip()] = "ML focus"

    for detector in extract_slither_detectors(audit_text):
        issue_name = DETECTOR_TO_ISSUE.get(detector.strip().lower())
        if not issue_name:
            continue
        current = issues.get(issue_name)
        issue_matches_ml = issue_name.lower() == normalized_ml_label
        if current == "ML focus" or issue_matches_ml:
            issues[issue_name] = "ML focus + static finding"
        else:
            issues[issue_name] = "Static finding"

    return [f"{issue}: {source}" for issue, source in issues.items()]


def find_line_signals(code: str, label: str | None = None) -> list[LineSignal]:
    signals: list[LineSignal] = []
    active_patterns = list(ATTACK_SURFACE_PATTERNS)
    if label in VULNERABILITY_PATTERNS:
        active_patterns = VULNERABILITY_PATTERNS[label] + active_patterns

    seen: set[tuple[int, str]] = set()
    for line_number, raw_line in enumerate(code.splitlines(), start=1):
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("//"):
            continue
        for category, pattern, reason in active_patterns:
            if pattern.search(stripped):
                key = (line_number, category)
                if key in seen:
                    continue
                seen.add(key)
                signals.append(LineSignal(line_number, category, stripped[:180], reason))
    return signals


def calculate_risk_score(
    audit_text: str | None,
    code: str,
    csv_risk_score: int | float | None = None,
) -> dict[str, Any]:
    label = extract_audit_label(audit_text)
    confidence = extract_confidence(audit_text)
    slither_counts = extract_slither_impact_counts(audit_text)
    signals = find_line_signals(code, label)
    hybrid_confirmation = hybrid_confirmation_summary(label, audit_text, signals)
    primary_categories = set(SOURCE_CONFIRMATION_CATEGORIES.get(label or "", ()))
    primary_signal_count = sum(1 for signal in signals if signal.category in primary_categories)
    has_high_or_medium_slither = slither_counts["High"] > 0 or slither_counts["Medium"] > 0
    low_signal_override = (
        confidence < 0.55
        and not has_high_or_medium_slither
        and primary_signal_count == 0
    )

    ml_confidence_score = int(round(confidence * 35))
    class_severity_score = 0
    if label in {"Reentrancy", "Dangerous Delegatecall"}:
        class_severity_score = 10
    elif label in {"Integer Overflow", "Timestamp Dependency"}:
        class_severity_score = 8
    base = ml_confidence_score + class_severity_score

    external_calls = sum(1 for signal in signals if signal.category in {"External value call", "Low-level call", "Delegatecall"})
    public_entries = sum(1 for signal in signals if signal.category == "Public/external function")
    payable_entries = sum(1 for signal in signals if signal.category == "Payable entrypoint")

    slither_high_score = min(45, slither_counts["High"] * 15)
    slither_medium_score = min(25, slither_counts["Medium"] * 8)
    slither_low_score = min(8, slither_counts["Low"] * 2)
    slither_info_score = min(4, (slither_counts["Informational"] + slither_counts["Optimization"]) * 1)
    slither_score = slither_high_score + slither_medium_score + slither_low_score + slither_info_score

    external_call_score = min(8, external_calls * 3)
    public_entry_score = min(5, public_entries)
    payable_score = min(4, payable_entries * 2)
    surface_score = external_call_score + public_entry_score + payable_score
    raw_score = base + slither_score + surface_score
    score = raw_score
    if csv_risk_score is not None:
        score = int(round(score * 0.75 + min(100, float(csv_risk_score)) * 0.25))

    if low_signal_override:
        score = min(score, 24)
    elif slither_counts["High"] == 0 and slither_counts["Medium"] == 0:
        score = min(score, 39)
    elif slither_counts["High"] == 0:
        score = min(score, 64)

    score = max(0, min(100, score))
    if score >= 75:
        level = "High"
    elif score >= 45:
        level = "Medium"
    elif score > 0:
        level = "Low"
    else:
        level = "Unknown"

    return {
        "score": score,
        "level": level,
        "label": label or "Unknown",
        "confidence": confidence,
        "signals": signals,
        "external_calls": external_calls,
        "public_entries": public_entries,
        "payable_entries": payable_entries,
        "primary_signal_count": primary_signal_count,
        "low_signal_override": low_signal_override,
        "slither_counts": slither_counts,
        "hybrid_confirmation": hybrid_confirmation,
        "score_breakdown": {
            "ml_confidence": ml_confidence_score,
            "class_severity": class_severity_score,
            "slither_high": slither_high_score,
            "slither_medium": slither_medium_score,
            "slither_low": slither_low_score,
            "slither_info": slither_info_score,
            "external_calls": external_call_score,
            "public_entries": public_entry_score,
            "payable_entries": payable_score,
            "raw_score": raw_score,
            "final_score": score,
        },
    }


def format_line_map_markdown(code: str, audit_text: str | None) -> str:
    label = extract_audit_label(audit_text)
    signals = find_line_signals(code, label)
    if not signals:
        return "### Line-Level Map\n\nNo suspicious source lines were matched for the current finding."

    primary_categories = set(SOURCE_CONFIRMATION_CATEGORIES.get(label or "", ()))
    attack_surface_categories = {"Public/external function", "Payable entrypoint", "Owner/admin gate"}

    primary_signals = [signal for signal in signals if signal.category in primary_categories]
    attack_surface_signals = [
        signal
        for signal in signals
        if signal.category in attack_surface_categories and signal not in primary_signals
    ]
    other_signals = [
        signal
        for signal in signals
        if signal not in primary_signals and signal not in attack_surface_signals
    ]

    def append_signal_group(rows: list[str], title: str, group: list[LineSignal], empty_message: str) -> None:
        rows.extend([f"#### {title}", ""])
        if not group:
            rows.extend([empty_message, ""])
            return
        for signal in group[:15]:
            rows.extend(
                [
                    f"**Line {signal.line}: {signal.category}**",
                    f"```solidity\n{signal.snippet}\n```",
                    f"Review note: {signal.reason}",
                    "",
                ]
            )
        if len(group) > 15:
            rows.append(f"Showing 15 of {len(group)} matched lines in this group.")
            rows.append("")

    rows = [
        "### Line-Level Map",
        "",
        f"Predicted focus: **{label or 'Unknown'}**",
        "",
    ]
    append_signal_group(
        rows,
        "Primary Evidence",
        primary_signals,
        "No direct source pattern was matched for the primary ML focus.",
    )
    append_signal_group(
        rows,
        "Related Attack Surface",
        attack_surface_signals,
        "No related public, payable, or access-control surface was matched.",
    )
    append_signal_group(
        rows,
        "Other Security-Relevant Lines",
        other_signals,
        "No additional security-relevant lines were matched.",
    )
    return "\n".join(rows)


def format_risk_dashboard_markdown(
    selected_file: str | None,
    audit_text: str | None,
    code: str,
    csv_risk_score: int | float | None = None,
) -> str:
    risk = calculate_risk_score(audit_text, code, csv_risk_score=csv_risk_score)
    confidence = f"{risk['confidence']:.1%}" if risk["confidence"] else "N/A"
    deep_learning_prediction = extract_deep_learning_prediction(audit_text)
    slither_high_findings = extract_slither_high_impact_findings(audit_text)
    slither_high_text = ", ".join(slither_high_findings) if slither_high_findings else "None"
    detected_issues = summarize_detected_issues(audit_text, risk["label"])
    detected_issue_rows = (
        [f"- {issue}" for issue in detected_issues]
        if detected_issues
        else ["- No recognized vulnerability categories were summarized."]
    )
    if risk["low_signal_override"]:
        verdict = (
            f"{risk['level']} risk contract. CodeBERT selected {risk['label']} with low confidence, "
            "and Slither/source evidence did not strongly confirm the prediction."
        )
    else:
        verdict = (
            f"{risk['level']} risk contract. CodeBERT selected {risk['label']} as the primary ML focus, "
            f"and the hybrid verdict is {risk['hybrid_confirmation']['level'].lower()}."
        )
        if slither_high_findings:
            verdict += f" Confirmed static findings include {slither_high_text}."

    score_breakdown = risk["score_breakdown"]
    score_rows = [
        f"- ML confidence contribution: **{score_breakdown['ml_confidence']}/35**",
        f"- ML class severity contribution: **{score_breakdown['class_severity']}/10**",
        f"- Slither high-impact contribution: **{score_breakdown['slither_high']}/45**",
        f"- Slither medium-impact contribution: **{score_breakdown['slither_medium']}/25**",
        f"- Slither low-impact contribution: **{score_breakdown['slither_low']}/8**",
        f"- Slither informational/optimization contribution: **{score_breakdown['slither_info']}/4**",
        f"- External-call surface contribution: **{score_breakdown['external_calls']}/8**",
        f"- Public-entrypoint contribution: **{score_breakdown['public_entries']}/5**",
        f"- Payable-entrypoint contribution: **{score_breakdown['payable_entries']}/4**",
        f"- Raw score before caps: **{score_breakdown['raw_score']}**",
        f"- Final score: **{score_breakdown['final_score']}/100**",
    ]
    has_confirmed_slither_risk = risk["slither_counts"]["High"] > 0 or risk["slither_counts"]["Medium"] > 0
    if risk["low_signal_override"]:
        ml_interpretation = "Low-confidence signal; no strong static confirmation"
    else:
        ml_interpretation = (
            "Confirmed-risk signal"
            if has_confirmed_slither_risk
            else "Pattern warning; not confirmed by high/medium Slither findings"
        )
    static_status = (
        "High/medium Slither findings present"
        if has_confirmed_slither_risk
        else "No high/medium Slither findings"
    )
    drivers = [
        f"- Primary ML focus: **{risk['label']}**",
        f"- Deep learning prediction: **{deep_learning_prediction}**",
        f"- Confirmed static findings: **{slither_high_text}**",
        f"- Hybrid verdict: **{risk['hybrid_confirmation']['level']}**",
        f"- Hybrid evidence: **{risk['hybrid_confirmation']['summary']}**",
        f"- ML interpretation: **{ml_interpretation}**",
        f"- Static analysis status: **{static_status}**",
        f"- Slither findings by impact: **High {risk['slither_counts']['High']}, Medium {risk['slither_counts']['Medium']}, Low {risk['slither_counts']['Low']}**",
        f"- Classifier confidence: **{confidence}**",
        f"- Direct primary source signals matched: **{risk['primary_signal_count']}**",
        f"- Low-signal override active: **{'Yes' if risk['low_signal_override'] else 'No'}**",
        f"- Public/external entrypoints matched: **{risk['public_entries']}**",
        f"- Value or low-level external calls matched: **{risk['external_calls']}**",
        f"- Payable signals matched: **{risk['payable_entries']}**",
    ]
    if csv_risk_score is not None:
        drivers.append(f"- CSV anomaly risk blended into score: **{csv_risk_score}/100**")

    return "\n".join(
        [
            "### Contract Risk Dashboard",
            "",
            f"**File:** `{selected_file or 'No file selected'}`",
            f"**Risk score:** **{risk['score']}/100**",
            f"**Risk level:** **{risk['level']}**",
            "",
            "#### Final Verdict",
            verdict,
            "",
            "#### Drivers",
            *drivers,
            "",
            "#### Multi-Vulnerability Summary",
            *detected_issue_rows,
            "",
            "#### Risk Score Breakdown",
            *score_rows,
            "",
            "#### Recommended next checks",
            "- Review every matched line in the line-level map.",
            "- Confirm whether external calls can be reached by untrusted users.",
            "- Validate generated patches with tests before deployment.",
        ]
    )


def render_diff_markdown(original_code: str, fixed_code: str, original_name: str = "original.sol", fixed_name: str = "fixed.sol") -> str:
    diff = difflib.unified_diff(
        original_code.splitlines(),
        fixed_code.splitlines(),
        fromfile=original_name,
        tofile=fixed_name,
        lineterm="",
    )
    diff_text = "\n".join(diff)
    if not diff_text.strip():
        return "### Patch Diff\n\nNo code differences were detected."
    return f"### Patch Diff\n\n```diff\n{diff_text[:12000]}\n```"


def load_contract_views(upload_dir: str, selected_file: str | None, audit_text: str | None) -> tuple[str, str]:
    if not selected_file:
        return (
            "### Contract Risk Dashboard\n\nSelect a Solidity file to calculate risk.",
            "### Line-Level Map\n\nSelect a Solidity file to map findings to source lines.",
        )
    path = os.path.join(upload_dir, selected_file)
    if not selected_file.lower().endswith(".sol") or not os.path.exists(path):
        return (
            "### Contract Risk Dashboard\n\nRisk scoring is available for Solidity files.",
            "### Line-Level Map\n\nLine mapping is available for Solidity files.",
        )
    with open(path, "r", encoding="utf-8", errors="ignore") as source:
        code = source.read()
    return (
        format_risk_dashboard_markdown(selected_file, audit_text, code),
        format_line_map_markdown(code, audit_text),
    )
