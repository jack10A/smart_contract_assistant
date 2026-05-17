import os
import re
from typing import Any

from PIL import Image

from app.image_classifier.predict import image_phishing_classifier


ADDRESS_PATTERN = re.compile(r"\b0x[a-fA-F0-9]{40}\b")
TX_HASH_PATTERN = re.compile(r"\b0x[a-fA-F0-9]{64}\b")

RISK_KEYWORDS = {
    "Wallet approval": ["approve", "pprove", "approval", "allowance", "spender", "unlimited"],
    "Failed transaction": ["failed", "fail", "halled", "reverted", "out of gas", "execution reverted", "trnsaction"],
    "Phishing language": [
        "seed phrase",
        "recovery phrase",
        "verify wallet",
        "claim airdrop",
        "urgent",
        "payment verification",
        "confirm your account",
        "security check",
        "account will be closed",
        "your account will be closed",
        "card holder",
        "cvv",
        "cvv2",
        "support pin",
        "apple id",
        "visa",
    ],
    "Contract interaction": ["contract interaction", "function", "method", "input data"],
    "Value transfer": ["transfer", "withdraw", "send", "swap", "bridge"],
}


def analyze_security_image(file_path: str) -> dict[str, Any]:
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"Image file not found: {file_path}")

    metadata = _image_metadata(file_path)
    classifier_result = image_phishing_classifier.predict(file_path)
    text, engine, ocr_error = _extract_text(file_path)
    normalized_text = _normalize_ocr_text(text)
    indicators = _risk_indicators(text)
    addresses = sorted(set(ADDRESS_PATTERN.findall(normalized_text)))
    tx_hashes = sorted(set(TX_HASH_PATTERN.findall(normalized_text)))
    risk_score = _risk_score(indicators, addresses, tx_hashes, classifier_result)

    return {
        "file": os.path.basename(file_path),
        "metadata": metadata,
        "classifier": classifier_result,
        "ocr_engine": engine,
        "ocr_error": ocr_error,
        "text": text,
        "normalized_text": normalized_text,
        "addresses": addresses,
        "tx_hashes": tx_hashes,
        "indicators": indicators,
        "risk_score": risk_score,
        "risk_level": "High" if risk_score >= 70 else "Medium" if risk_score >= 35 else "Low",
    }


def _image_metadata(file_path: str) -> dict[str, Any]:
    with Image.open(file_path) as image:
        return {
            "width": image.width,
            "height": image.height,
            "mode": image.mode,
            "format": image.format,
        }


def _extract_text(file_path: str) -> tuple[str, str, str | None]:
    try:
        import pytesseract

        with Image.open(file_path) as image:
            return pytesseract.image_to_string(image), "pytesseract", None
    except Exception as pytesseract_error:
        try:
            import easyocr

            reader = easyocr.Reader(["en"], gpu=False)
            result = reader.readtext(file_path, detail=0, paragraph=True)
            return "\n".join(result), "easyocr", None
        except Exception as easyocr_error:
            return (
                "",
                "none",
                (
                    "OCR is not available. Install Tesseract + pytesseract, or install easyocr. "
                    f"pytesseract error: {pytesseract_error}; easyocr error: {easyocr_error}"
                ),
            )


def _risk_indicators(text: str) -> list[dict[str, Any]]:
    lower = _normalize_ocr_words(text.lower())
    indicators: list[dict[str, Any]] = []
    for category, keywords in RISK_KEYWORDS.items():
        hits = [keyword for keyword in keywords if keyword in lower]
        if hits:
            indicators.append({"category": category, "matches": hits})
    return indicators


def _normalize_ocr_words(text: str) -> str:
    replacements = {
        "halled": "failed",
        "trnsaction": "transaction",
        "pprove": "approve",
        "approvalwarning": "approval warning",
    }
    normalized = text
    for bad, good in replacements.items():
        normalized = normalized.replace(bad, good)
    return normalized


def _normalize_ocr_text(text: str) -> str:
    if not text:
        return ""

    normalized = re.sub(r"\b[Oo]x", "0x", text)

    def fix_hex_candidate(match: re.Match[str]) -> str:
        candidate = match.group(0)
        if not candidate.lower().startswith("0x"):
            candidate = "0x" + candidate[2:]
        prefix = candidate[:2]
        body = candidate[2:]
        body = body.translate(str.maketrans({"O": "0", "o": "0", "I": "1", "l": "1"}))
        return prefix + body

    return re.sub(r"\b(?:0x|Ox|ox)[A-Fa-f0-9OoIl]{8,64}\b", fix_hex_candidate, normalized)


def _risk_score(
    indicators: list[dict[str, Any]],
    addresses: list[str],
    tx_hashes: list[str],
    classifier_result: dict[str, Any],
) -> int:
    score = min(70, len(indicators) * 18)
    if addresses:
        score += 8
    if tx_hashes:
        score += 8
    if any(item["category"] == "Phishing language" for item in indicators):
        score += 25
    if classifier_result.get("available") and classifier_result.get("label") == "phishing_page":
        score += int(round(float(classifier_result.get("confidence", 0.0)) * 35))
    return min(100, score)


def format_image_analysis_markdown(analysis: dict[str, Any]) -> str:
    metadata = analysis["metadata"]
    rows = [
        "### Image Security Analysis",
        "",
        "A trained image classifier estimates phishing likelihood, while OCR rules extract addresses, hashes, and risk indicators.",
        "",
        f"- File: `{analysis['file']}`",
        f"- Image: **{metadata['width']}x{metadata['height']}**, `{metadata['format']}`, mode `{metadata['mode']}`",
        _classifier_summary(analysis["classifier"]),
        f"- OCR engine: **{analysis['ocr_engine']}**",
        f"- Risk score: **{analysis['risk_score']}/100 ({analysis['risk_level']})**",
        "",
    ]

    if analysis.get("ocr_error"):
        rows.extend(
            [
                "#### OCR Setup Needed",
                analysis["ocr_error"],
                "",
            ]
        )

    rows.extend(["#### Extracted Indicators"])
    if analysis["indicators"]:
        for indicator in analysis["indicators"]:
            rows.append(f"- **{indicator['category']}**: {', '.join(indicator['matches'])}")
    else:
        rows.append("- No security keywords were detected.")

    rows.extend(
        [
            "",
            "#### Extracted Entities",
            f"- Addresses: `{analysis['addresses'] or 'None'}`",
            f"- Transaction hashes: `{analysis['tx_hashes'] or 'None'}`",
            "",
            "#### Suggested Next Step",
            _suggest_next_step(analysis),
        ]
    )

    if analysis["text"].strip():
        preview = analysis["text"].strip()
        if len(preview) > 1500:
            preview = preview[:1500] + "\n..."
        rows.extend(["", "#### OCR Text Preview", f"```text\n{preview}\n```"])

    if analysis.get("normalized_text") and analysis["normalized_text"] != analysis["text"]:
        normalized_preview = analysis["normalized_text"].strip()
        if len(normalized_preview) > 1500:
            normalized_preview = normalized_preview[:1500] + "\n..."
        rows.extend(["", "#### Normalized OCR Text", f"```text\n{normalized_preview}\n```"])

    return "\n".join(rows)


def _classifier_summary(result: dict[str, Any]) -> str:
    if not result.get("available"):
        return "- Image classifier: **not available**"
    scores = ", ".join(f"{label}={score:.1%}" for label, score in result.get("scores", {}).items())
    return (
        f"- Image classifier: **{result.get('label')}** "
        f"({float(result.get('confidence', 0.0)):.1%})"
        f"\n- Class scores: `{scores}`"
    )


def _suggest_next_step(analysis: dict[str, Any]) -> str:
    categories = {item["category"] for item in analysis["indicators"]}
    classifier = analysis.get("classifier", {})
    if classifier.get("label") == "phishing_page" and float(classifier.get("confidence", 0.0)) >= 0.75:
        return "Treat this screenshot as suspicious. Use OCR indicators to identify the lure, then avoid signing or entering credentials."
    if "Phishing language" in categories:
        return "Treat this screenshot as high risk. Do not connect a wallet or enter recovery phrases."
    if "Failed transaction" in categories or analysis["tx_hashes"]:
        return "Upload the related JSON transaction trace and correlate it with the Solidity audit."
    if "Wallet approval" in categories:
        return "Review spender addresses and approval functions before signing."
    if "Contract interaction" in categories:
        return "Compare the extracted function/method text with the Solidity function-level analysis."
    return "If this image relates to a transaction, upload the JSON trace or related contract for correlation."
