import json
import os
from collections import Counter
from typing import Any

import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

try:
    from eth_utils import keccak
except ImportError:  # pragma: no cover - optional dependency comes with slither-analyzer
    keccak = None


CALL_KEYS = ("calls", "children", "subtraces")
CALL_TYPE_KEYS = ("type", "callType", "op")
ADDRESS_KEYS = ("to", "from", "address")
VALUE_KEYS = ("value", "amount")
GAS_KEYS = ("gas", "gasUsed", "gas_used")
TRACE_CONTAINER_KEYS = ("calls", "children", "subtraces", "structLogs", "result", "trace", "transactionHash")


def analyze_trace_json(file_path: str, abi_dir: str | None = None) -> dict[str, Any]:
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"Trace file not found: {file_path}")

    with open(file_path, "r", encoding="utf-8") as trace_file:
        payload = json.load(trace_file)

    if _looks_like_abi(payload):
        raise ValueError(
            "This JSON looks like an ABI, not an execution trace. Select a trace file such as *_trace.json."
        )
    if not _looks_like_trace(payload):
        raise ValueError(
            "No execution trace structure was found. Expected JSON with calls, children, subtraces, structLogs, result, trace, or transactionHash."
        )

    selector_map = load_abi_selectors(abi_dir or os.path.dirname(file_path), exclude_path=file_path)
    calls = _flatten_calls(payload)
    if not calls:
        raise ValueError("No trace calls were found. Expected JSON with calls, children, or subtraces.")

    features = [_call_features(call, depth, selector_map) for call, depth in calls]
    matrix = np.array([item["vector"] for item in features], dtype=np.float32)
    scores = _anomaly_scores(matrix)
    threshold = float(np.percentile(scores, 90)) if len(scores) > 1 else float(scores[0])
    anomalies = [idx for idx, score in enumerate(scores) if score >= threshold and score > 0]

    call_types = Counter(item["call_type"] for item in features)
    risk_flags = _risk_flags(features)
    behavior = _classify_behavior(features, risk_flags)

    return {
        "summary": {
            "file": os.path.basename(file_path),
            "calls": len(features),
            "max_depth": max(item["depth"] for item in features),
            "unique_addresses": len({address for item in features for address in item["addresses"] if address}),
            "call_types": dict(call_types),
            "decoded_functions": sorted(
                {
                    item["decoded_function"]
                    for item in features
                    if item.get("decoded_function")
                }
            ),
            "abi_selectors_loaded": len(selector_map),
        },
        "behavior": behavior,
        "risk_flags": risk_flags,
        "anomalies": [
            {
                "index": idx,
                "score": float(scores[idx]),
                "call_type": features[idx]["call_type"],
                "decoded_function": features[idx]["decoded_function"],
                "depth": features[idx]["depth"],
                "value": features[idx]["value"],
                "gas": features[idx]["gas"],
            }
            for idx in anomalies[:20]
        ],
    }


def _looks_like_abi(payload: Any) -> bool:
    abi = payload.get("abi") if isinstance(payload, dict) else payload
    return (
        isinstance(abi, list)
        and bool(abi)
        and all(isinstance(item, dict) and "type" in item and ("name" in item or item.get("type") in {"constructor", "receive", "fallback"}) for item in abi)
    )


def _looks_like_trace(payload: Any) -> bool:
    if isinstance(payload, list):
        return any(_looks_like_trace(item) for item in payload)
    if not isinstance(payload, dict):
        return False
    if any(key in payload for key in TRACE_CONTAINER_KEYS):
        return True
    if any(key in payload for key in ADDRESS_KEYS) and any(key in payload for key in CALL_TYPE_KEYS + GAS_KEYS + VALUE_KEYS):
        return True
    return any(_looks_like_trace(payload.get(key)) for key in TRACE_CONTAINER_KEYS if key in payload)


def _flatten_calls(payload: Any, depth: int = 0) -> list[tuple[dict[str, Any], int]]:
    calls: list[tuple[dict[str, Any], int]] = []
    if isinstance(payload, list):
        for item in payload:
            calls.extend(_flatten_calls(item, depth))
        return calls

    if not isinstance(payload, dict):
        return calls

    if any(key in payload for key in CALL_TYPE_KEYS + ADDRESS_KEYS + VALUE_KEYS):
        calls.append((payload, depth))

    for key in CALL_KEYS:
        children = payload.get(key)
        if isinstance(children, list):
            for child in children:
                calls.extend(_flatten_calls(child, depth + 1))
    return calls


def _call_features(call: dict[str, Any], depth: int, selector_map: dict[str, str]) -> dict[str, Any]:
    call_type = _first_value(call, CALL_TYPE_KEYS, "UNKNOWN")
    value = _numeric_value(_first_value(call, VALUE_KEYS, 0))
    gas = _numeric_value(_first_value(call, GAS_KEYS, 0))
    addresses = [str(call.get(key, "")) for key in ADDRESS_KEYS if call.get(key)]
    input_data = str(call.get("input", call.get("data", "")))
    selector = input_data[:10].lower() if input_data.startswith("0x") and len(input_data) >= 10 else ""
    decoded_function = selector_map.get(selector, "")
    input_size = len(input_data)
    error = int(bool(call.get("error") or call.get("revertReason") or call.get("failed")))
    risky_type = int(str(call_type).upper() in {"DELEGATECALL", "CALLCODE", "SELFDESTRUCT"})

    return {
        "call_type": str(call_type),
        "selector": selector,
        "decoded_function": decoded_function,
        "depth": depth,
        "value": value,
        "gas": gas,
        "addresses": addresses,
        "vector": [depth, np.log1p(value), np.log1p(gas), input_size, error, risky_type],
    }


def _first_value(call: dict[str, Any], keys: tuple[str, ...], default: Any) -> Any:
    for key in keys:
        if key in call:
            return call[key]
    return default


def _numeric_value(value: Any) -> float:
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        try:
            return float(int(value, 16) if value.startswith("0x") else value)
        except ValueError:
            return 0.0
    return 0.0


def _anomaly_scores(matrix: np.ndarray) -> np.ndarray:
    if len(matrix) < 4:
        return np.zeros(len(matrix), dtype=np.float32)
    scaled = StandardScaler().fit_transform(matrix)
    model = IsolationForest(contamination=min(0.2, max(1 / len(matrix), 0.05)), random_state=42)
    model.fit(scaled)
    return -model.decision_function(scaled)


def _risk_flags(features: list[dict[str, Any]]) -> list[str]:
    flags = []
    call_types = [item["call_type"].upper() for item in features]
    if "DELEGATECALL" in call_types:
        flags.append("Delegatecall observed in execution trace.")
    if call_types.count("CALL") >= 3:
        flags.append("Multiple external calls observed.")
    if any(item["value"] > 0 for item in features):
        flags.append("Value transfer observed.")
    if any(item["depth"] >= 3 for item in features):
        flags.append("Deep nested call chain observed.")
    if any(item["vector"][4] for item in features):
        flags.append("Failed or reverted call observed.")
    return flags


def _classify_behavior(features: list[dict[str, Any]], risk_flags: list[str]) -> dict[str, Any]:
    call_types = {item["call_type"].upper() for item in features}
    score = min(100, len(risk_flags) * 18 + max(item["depth"] for item in features) * 6)
    if "DELEGATECALL" in call_types:
        label = "Delegatecall-heavy trace"
    elif any(item["value"] > 0 for item in features) and len(features) >= 3:
        label = "Value-transfer call chain"
    elif risk_flags:
        label = "Suspicious execution pattern"
    else:
        label = "Low-risk trace pattern"
    return {"label": label, "risk_score": int(score), "risk_level": "High" if score >= 70 else "Medium" if score >= 35 else "Low"}


def load_abi_selectors(abi_dir: str, exclude_path: str | None = None) -> dict[str, str]:
    """Load function selectors from ABI JSON files in a directory."""
    selectors: dict[str, str] = {}
    if keccak is None or not abi_dir or not os.path.exists(abi_dir):
        return selectors

    exclude_abs = os.path.abspath(exclude_path) if exclude_path else None
    for name in os.listdir(abi_dir):
        if not name.lower().endswith(".json"):
            continue
        path = os.path.join(abi_dir, name)
        if exclude_abs and os.path.abspath(path) == exclude_abs:
            continue
        try:
            with open(path, "r", encoding="utf-8") as abi_file:
                payload = json.load(abi_file)
        except (OSError, json.JSONDecodeError):
            continue
        selectors.update(_selectors_from_abi_payload(payload))
    return selectors


def _selectors_from_abi_payload(payload: Any) -> dict[str, str]:
    abi = payload.get("abi") if isinstance(payload, dict) else payload
    if not isinstance(abi, list):
        return {}

    selectors: dict[str, str] = {}
    for item in abi:
        if not isinstance(item, dict) or item.get("type") != "function" or not item.get("name"):
            continue
        inputs = item.get("inputs", [])
        if not isinstance(inputs, list):
            inputs = []
        arg_types = ",".join(str(arg.get("type", "")) for arg in inputs if isinstance(arg, dict))
        signature = f"{item['name']}({arg_types})"
        selector = "0x" + keccak(text=signature)[:4].hex()
        selectors[selector.lower()] = signature
    return selectors


def format_trace_analysis_markdown(analysis: dict[str, Any]) -> str:
    summary = analysis["summary"]
    behavior = analysis["behavior"]
    flags = analysis["risk_flags"]
    anomalies = analysis["anomalies"]

    rows = [
        "### JSON Trace Deep Learning Analysis",
        "",
        "Isolation Forest is applied to extracted call features: depth, value, gas, input size, errors, and risky call types.",
        "",
        f"- File: `{summary['file']}`",
        f"- Calls analyzed: **{summary['calls']}**",
        f"- Max call depth: **{summary['max_depth']}**",
        f"- Unique addresses: **{summary['unique_addresses']}**",
        f"- Behavior class: **{behavior['label']}**",
        f"- Trace risk score: **{behavior['risk_score']}/100 ({behavior['risk_level']})**",
        f"- Call types: `{summary['call_types']}`",
        f"- ABI selectors loaded: **{summary['abi_selectors_loaded']}**",
        f"- Decoded functions: `{summary['decoded_functions'] or 'None'}`",
        "",
        "#### Risk Flags",
    ]
    rows.extend([f"- {flag}" for flag in flags] or ["- No major trace risk flags found."])
    rows.extend(
        [
            "",
            "#### Anomalous Calls",
            "| # | Type | Decoded function | Depth | Value | Gas | Score |",
            "|---:|---|---|---:|---:|---:|---:|",
        ]
    )
    if anomalies:
        for item in anomalies:
            rows.append(
                f"| {item['index']} | {item['call_type']} | {item.get('decoded_function') or '-'} | {item['depth']} | "
                f"{item['value']:.0f} | {item['gas']:.0f} | {item['score']:.4f} |"
            )
    else:
        rows.append("| - | - | - | - | - | - | No anomalous calls found. |")
    return "\n".join(rows)


def correlate_trace_with_audit(audit_text: str | None, line_map_text: str | None, trace_text: str | None) -> str:
    """Create a lightweight correlation report between static audit findings and runtime trace behavior."""
    audit_lower = (audit_text or "").lower()
    line_lower = (line_map_text or "").lower()
    trace_lower = (trace_text or "").lower()

    rows = [
        "### Trace to Contract Correlation",
        "",
        "This compares static Solidity findings with runtime JSON trace behavior.",
        "",
    ]

    matches: list[tuple[str, str, str]] = []
    if ("delegatecall" in audit_lower or "dangerous delegatecall" in audit_lower) and "delegatecall" in trace_lower:
        matches.append(
            (
                "Strong match",
                "Contract audit found delegatecall risk and the trace contains delegatecall behavior.",
                "Review plugin/external execution paths such as `runPlugin` and any owner-gated call forwarding.",
            )
        )

    if (
        ("reentrancy" in audit_lower or "external value call" in line_lower)
        and ("value transfer observed" in trace_lower or "multiple external calls observed" in trace_lower)
    ):
        matches.append(
            (
                "Strong match",
                "Contract audit found value-transfer or reentrancy-like patterns and the trace shows value transfers or repeated external calls.",
                "Review withdrawal and payment functions, especially state updates before external calls.",
            )
        )

    if ("timestamp" in audit_lower or "weak-prng" in audit_lower) and "delegatecall-heavy trace" not in trace_lower:
        matches.append(
            (
                "No direct runtime confirmation",
                "The audit found timestamp/randomness risk, but this trace does not directly prove timing manipulation.",
                "Review lottery/randomness functions separately from this transaction trace.",
            )
        )

    if "failed or reverted call observed" in trace_lower:
        matches.append(
            (
                "Moderate match",
                "The trace contains a failed or reverted call.",
                "Check access control, plugin execution, recipient validation, and require conditions near the failed path.",
            )
        )

    decoded_mentions = []
    for function_name in ("withdraw", "withdrawall", "runplugin", "sendether", "execute", "transfer"):
        if function_name in trace_lower:
            decoded_mentions.append(function_name)
    if decoded_mentions:
        matches.append(
            (
                "Function-level match",
                f"Trace input selectors decoded function names related to: {', '.join(sorted(set(decoded_mentions)))}.",
                "Compare decoded trace calls with the function-level ML analysis and line map.",
            )
        )

    if not matches:
        rows.append("No strong correlation was found between the current Solidity audit and JSON trace output.")
        rows.append("")
        rows.append("Run both a Solidity audit and JSON trace analysis, then try again.")
        return "\n".join(rows)

    rows.extend(["| Strength | Evidence | Next review step |", "|---|---|---|"])
    for strength, evidence, next_step in matches:
        rows.append(f"| {strength} | {evidence} | {next_step} |")
    return "\n".join(rows)
