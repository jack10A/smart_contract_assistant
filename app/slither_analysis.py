import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from typing import Any


SLITHER_TIMEOUT_SECONDS = 45


def run_slither_analysis(file_path: str) -> dict[str, Any]:
    """Run Slither on a Solidity file and return a normalized result."""
    slither_cmd = _find_slither_command()
    if not slither_cmd:
        return {
            "available": False,
            "target_path": file_path,
            "error": "Slither is not installed or is not available on PATH.",
            "findings": [],
        }

    if not os.path.exists(file_path):
        return {
            "available": True,
            "target_path": file_path,
            "error": f"Solidity file not found: {file_path}",
            "findings": [],
        }

    json_path = None
    try:
        temp_fd, json_path = tempfile.mkstemp(suffix=".json")
        os.close(temp_fd)
        os.remove(json_path)

        command = [slither_cmd, file_path, "--json", json_path]
        solc_version = _extract_solidity_version(file_path)
        if solc_version:
            command.extend(["--solc-solcs-select", solc_version])

        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=SLITHER_TIMEOUT_SECONDS,
            check=False,
        )

        findings = _load_slither_findings(json_path)
        return {
            "available": True,
            "target_path": file_path,
            "returncode": completed.returncode,
            "stdout": completed.stdout,
            "stderr": completed.stderr,
            "error": None if findings or completed.returncode in (0, 255) else completed.stderr.strip(),
            "findings": findings,
        }
    except subprocess.TimeoutExpired:
        return {
            "available": True,
            "target_path": file_path,
            "error": f"Slither timed out after {SLITHER_TIMEOUT_SECONDS} seconds.",
            "findings": [],
        }
    except Exception as exc:
        return {
            "available": True,
            "target_path": file_path,
            "error": str(exc),
            "findings": [],
        }
    finally:
        if json_path and os.path.exists(json_path):
            try:
                os.remove(json_path)
            except OSError:
                pass


def _load_slither_findings(json_path: str) -> list[dict[str, Any]]:
    if not os.path.exists(json_path) or os.path.getsize(json_path) == 0:
        return []

    with open(json_path, "r", encoding="utf-8") as result_file:
        payload = json.load(result_file)

    detectors = payload.get("results", {}).get("detectors", [])
    findings = []
    for detector in detectors:
        findings.append(
            {
                "check": detector.get("check", "unknown-check"),
                "impact": detector.get("impact", "Unknown"),
                "confidence": detector.get("confidence", "Unknown"),
                "description": _clean_description(detector.get("description", "")),
                "lines": _extract_lines(detector),
            }
        )
    return findings


def _clean_description(description: str) -> str:
    return " ".join(str(description).split())


def _extract_lines(detector: dict[str, Any]) -> list[int]:
    lines: set[int] = set()
    for element in detector.get("elements", []):
        source_mapping = element.get("source_mapping", {})
        for line in source_mapping.get("lines", []) or []:
            if isinstance(line, int):
                lines.add(line)
    return sorted(lines)


def format_slither_report(result: dict[str, Any], max_findings: int = 12) -> str:
    """Format Slither output for the audit panel."""
    lines = [
        "### Slither Static Analysis",
        "",
    ]

    if not result.get("available"):
        lines.extend(
            [
                "**Status:** Slither is not installed.",
                "",
                "Install it with:",
                "",
                "```powershell",
                "python -m pip install slither-analyzer",
                "```",
                "",
                "Slither is optional and does not replace the deep learning audit.",
            ]
        )
        return "\n".join(lines)

    if result.get("error") and not result.get("findings"):
        lines.extend(
            [
                "**Status:** Slither could not complete.",
                "",
                f"```text\n{result['error']}\n```",
            ]
        )
        return "\n".join(lines)

    findings = result.get("findings", [])
    if not findings:
        lines.append("No Slither findings were reported for this contract.")
        return "\n".join(lines)

    lines.extend(
        [
            f"**Findings:** {len(findings)}",
            "",
            "| Impact | Confidence | Detector | Lines | Description |",
            "|---|---|---|---|---|",
        ]
    )
    for finding in findings[:max_findings]:
        line_text = ", ".join(str(line) for line in finding.get("lines", [])) or "-"
        description = finding.get("description", "").replace("|", "\\|")
        if len(description) > 180:
            description = f"{description[:177]}..."
        lines.append(
            "| "
            f"{finding.get('impact', 'Unknown')} | "
            f"{finding.get('confidence', 'Unknown')} | "
            f"`{finding.get('check', 'unknown-check')}` | "
            f"{line_text} | "
            f"{description} |"
        )

    if len(findings) > max_findings:
        lines.append("")
        lines.append(f"Showing first {max_findings} findings.")

    return "\n".join(lines)


def slither_detector_names(result: dict[str, Any]) -> set[str]:
    """Return unique detector check names from a Slither result."""
    return {
        str(finding.get("check"))
        for finding in result.get("findings", [])
        if finding.get("check")
    }


def _impact_counts(result: dict[str, Any]) -> dict[str, int]:
    counts = {"High": 0, "Medium": 0, "Low": 0, "Informational": 0, "Optimization": 0}
    for finding in result.get("findings", []):
        impact = finding.get("impact")
        if impact in counts:
            counts[impact] += 1
    return counts


def _changed_function_names(original_path: str, fixed_path: str) -> list[str]:
    try:
        with open(original_path, "r", encoding="utf-8", errors="ignore") as original_file:
            original_source = original_file.read()
        with open(fixed_path, "r", encoding="utf-8", errors="ignore") as fixed_file:
            fixed_source = fixed_file.read()
    except OSError:
        return []

    original_functions = set(re.findall(r"\bfunction\s+(\w+)\s*\(", original_source))
    fixed_functions = set(re.findall(r"\bfunction\s+(\w+)\s*\(", fixed_source))
    removed = {f"removed:{name}" for name in original_functions - fixed_functions}
    added = {f"added:{name}" for name in fixed_functions - original_functions}

    changed = set()
    for name in original_functions & fixed_functions:
        original_match = re.search(rf"\bfunction\s+{re.escape(name)}\s*\([^{{]*{{", original_source)
        fixed_match = re.search(rf"\bfunction\s+{re.escape(name)}\s*\([^{{]*{{", fixed_source)
        if original_match and fixed_match:
            original_start = original_match.start()
            fixed_start = fixed_match.start()
            original_end = original_source.find("\n    function ", original_start + 1)
            fixed_end = fixed_source.find("\n    function ", fixed_start + 1)
            original_body = original_source[original_start: original_end if original_end != -1 else len(original_source)]
            fixed_body = fixed_source[fixed_start: fixed_end if fixed_end != -1 else len(fixed_source)]
            if original_body.strip() != fixed_body.strip():
                changed.add(name)

    return sorted(changed | removed | added)


def format_slither_reaudit_report(original_result: dict[str, Any], fixed_result: dict[str, Any]) -> str:
    """Compare Slither detector names before and after a generated fix."""
    lines = [
        "### Slither Re-audit Result",
        "",
    ]

    if not original_result.get("available") or not fixed_result.get("available"):
        lines.append("Slither is not available, so the generated fix could not be re-audited.")
        return "\n".join(lines)

    if fixed_result.get("error") and not fixed_result.get("findings"):
        lines.extend(
            [
                "Slither could not analyze the generated fixed file.",
                "",
                f"```text\n{fixed_result['error']}\n```",
            ]
        )
        return "\n".join(lines)

    original_detectors = slither_detector_names(original_result)
    fixed_detectors = slither_detector_names(fixed_result)
    original_counts = _impact_counts(original_result)
    fixed_counts = _impact_counts(fixed_result)
    fixed_names = sorted(original_detectors - fixed_detectors)
    remaining_names = sorted(original_detectors & fixed_detectors)
    new_names = sorted(fixed_detectors - original_detectors)
    original_confirmed = original_counts["High"] + original_counts["Medium"]
    fixed_confirmed = fixed_counts["High"] + fixed_counts["Medium"]
    confirmed_fixed = max(0, original_confirmed - fixed_confirmed)
    new_issue_penalty = len(new_names) * 5
    quality = 100
    if original_confirmed:
        quality = int(round((confirmed_fixed / original_confirmed) * 100))
    elif fixed_confirmed:
        quality = 40
    quality = max(0, min(100, quality - new_issue_penalty))
    if fixed_confirmed == 0 and quality >= 90:
        validation_status = "Accepted"
        validation_reason = "No High or Medium Slither findings remain after the patch."
        recommended_action = "Download the fixed file and run project tests or manual review."
    elif fixed_confirmed < original_confirmed:
        validation_status = "Needs another pass"
        validation_reason = "The patch reduced High/Medium findings, but confirmed findings still remain."
        recommended_action = "Generate another fix or manually review the remaining findings."
    else:
        validation_status = "Rejected"
        validation_reason = "The patch did not reduce confirmed High/Medium Slither findings."
        recommended_action = "Do not use this patch without manual security review."

    original_path = original_result.get("target_path")
    fixed_path = fixed_result.get("target_path")
    changed_functions = (
        _changed_function_names(original_path, fixed_path)
        if isinstance(original_path, str) and isinstance(fixed_path, str)
        else []
    )

    lines.extend(
        [
            "#### Fix Validation",
            f"- Status: **{validation_status}**",
            f"- Reason: **{validation_reason}**",
            f"- Recommended action: **{recommended_action}**",
            "",
            f"#### Fix Quality Score: **{quality}%**",
            "",
            f"- High/Medium findings before: **{original_confirmed}**",
            f"- High/Medium findings after: **{fixed_confirmed}**",
            f"- High/Medium findings fixed: **{confirmed_fixed}**",
            f"- Original Slither detector types: **{len(original_detectors)}**",
            f"- Remaining detector types after fix: **{len(fixed_detectors)}**",
            f"- Fixed: **{', '.join(fixed_names) or 'None'}**",
            f"- Remaining: **{', '.join(remaining_names) or 'None'}**",
        ]
    )

    if new_names:
        lines.append(f"- Newly introduced: **{', '.join(new_names)}**")

    lines.extend(
        [
            "",
            "#### Contract Version Compare",
            f"- Functions changed: **{', '.join(changed_functions) or 'No function-level changes detected'}**",
            f"- Slither findings before: **High {original_counts['High']}, Medium {original_counts['Medium']}, Low {original_counts['Low']}, Info {original_counts['Informational']}, Optimization {original_counts['Optimization']}**",
            f"- Slither findings after: **High {fixed_counts['High']}, Medium {fixed_counts['Medium']}, Low {fixed_counts['Low']}, Info {fixed_counts['Informational']}, Optimization {fixed_counts['Optimization']}**",
        ]
    )

    return "\n".join(lines)


def _find_slither_command() -> str | None:
    slither_cmd = shutil.which("slither")
    if slither_cmd:
        return slither_cmd

    scripts_dir = os.path.dirname(sys.executable)
    for executable_name in ("slither.exe", "slither"):
        candidate = os.path.join(scripts_dir, executable_name)
        if os.path.exists(candidate):
            return candidate
    return None


def _extract_solidity_version(file_path: str) -> str | None:
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as contract_file:
            source = contract_file.read(4096)
    except OSError:
        return None

    match = re.search(r"pragma\s+solidity\s+([^;]+);", source)
    if not match:
        return None

    version_match = re.search(r"(\d+\.\d+\.\d+)", match.group(1))
    if not version_match:
        return None

    version = version_match.group(1)
    if version.startswith("0.8."):
        return None
    return version
