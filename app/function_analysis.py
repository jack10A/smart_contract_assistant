import re
from dataclasses import dataclass
from typing import Any

from app.security_analysis import SOURCE_CONFIRMATION_CATEGORIES, find_line_signals


@dataclass(frozen=True)
class SolidityFunction:
    name: str
    start_line: int
    end_line: int
    code: str


def extract_solidity_functions(source: str) -> list[SolidityFunction]:
    """Extract top-level Solidity function blocks with approximate line ranges."""
    functions: list[SolidityFunction] = []
    pattern = re.compile(r"\bfunction\s+(\w+)\s*\([^;{]*\{", re.MULTILINE)

    for match in pattern.finditer(source):
        open_brace = source.find("{", match.start())
        if open_brace == -1:
            continue

        close_brace = _find_matching_brace(source, open_brace)
        if close_brace == -1:
            continue

        start_line = source.count("\n", 0, match.start()) + 1
        end_line = source.count("\n", 0, close_brace) + 1
        functions.append(
            SolidityFunction(
                name=match.group(1),
                start_line=start_line,
                end_line=end_line,
                code=source[match.start(): close_brace + 1],
            )
        )

    return functions


def _find_matching_brace(source: str, open_brace: int) -> int:
    depth = 0
    i = open_brace
    while i < len(source):
        char = source[i]
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return -1


def analyze_functions_with_classifier(source: str, classifier: Any, max_functions: int = 20) -> list[dict[str, Any]]:
    """Run the existing vulnerability classifier against each extracted function."""
    results: list[dict[str, Any]] = []
    for function in extract_solidity_functions(source)[:max_functions]:
        prediction = classifier.predict(function.code)
        label = prediction.get("label", "Unknown")
        source_categories = set(SOURCE_CONFIRMATION_CATEGORIES.get(label, ()))
        signals = find_line_signals(function.code, label)
        source_confirmed = any(signal.category in source_categories for signal in signals)
        results.append(
            {
                "name": function.name,
                "start_line": function.start_line,
                "end_line": function.end_line,
                "label": label,
                "confidence": float(prediction.get("confidence", 0.0)),
                "risk": prediction.get("risk", "Unknown"),
                "scores": prediction.get("all_scores", {}),
                "source_confirmed": source_confirmed,
            }
        )
    return results


def format_function_analysis_markdown(results: list[dict[str, Any]]) -> str:
    if not results:
        return "### Function-Level Deep Learning Analysis\n\nNo Solidity functions were detected."

    rows = [
        "### Function-Level Deep Learning Analysis",
        "",
        "The same deep learning classifier is applied to each Solidity function to localize suspicious patterns.",
        "",
        "| Function | Lines | Prediction | Confidence | Interpretation |",
        "|---|---:|---|---:|---|",
    ]
    for item in results:
        confidence = item["confidence"]
        source_confirmed = bool(item.get("source_confirmed"))
        if confidence >= 0.75:
            interpretation = (
                "Strong ML signal; source pattern confirmed"
                if source_confirmed
                else "Strong ML signal; not statically confirmed"
            )
        elif confidence >= 0.60:
            interpretation = (
                "Weak ML signal; source pattern present"
                if source_confirmed
                else "Weak ML signal; review manually"
            )
        else:
            interpretation = "Low confidence; do not treat as confirmed"
        rows.append(
            "| "
            f"`{item['name']}` | "
            f"{item['start_line']}-{item['end_line']} | "
            f"{item['label']} | "
            f"{confidence:.1%} | "
            f"{interpretation} |"
        )
    return "\n".join(rows)
