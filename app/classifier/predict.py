import os
import re
import numpy as np
import torch
import torch.nn.functional as F
from transformers import AutoTokenizer, AutoModelForSequenceClassification


class VulnerabilityClassifier:
    """
    Smart Contract Vulnerability Classifier using CodeBERT.
    Trained on 4 classes: Reentrancy, Integer Overflow,
                          Timestamp Dependency, Dangerous Delegatecall
    Matches training config exactly:
        MAX_LEN = 512 | STRIDE = 64 | min_chunk = 32
    """

    HIGH_CONFIDENCE   = 0.65
    MEDIUM_CONFIDENCE = 0.40

    def __init__(self, model_path: str = None):
        if model_path is None:
            model_path = os.path.join(os.path.dirname(__file__), "model_weights")

        if not os.path.exists(model_path):
            raise FileNotFoundError(
                f"Model weights not found at: {model_path}\n"
                f"Extract research_model.zip into that folder."
            )

        print(f"[VulnerabilityClassifier] Loading model from: {model_path}")
        self.tokenizer = AutoTokenizer.from_pretrained(model_path)
        self.model     = AutoModelForSequenceClassification.from_pretrained(model_path)

        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        self.model.to(self.device)
        self.model.eval()

        # Must match training config exactly
        self.max_len          = 512
        self.stride           = 64
        self.min_chunk_tokens = 32

        print(f"[VulnerabilityClassifier] Ready on {self.device} | "
              f"{len(self.model.config.id2label)} classes: "
              f"{list(self.model.config.id2label.values())}")

    # ----------------------------------------------------------
    # CLEANING — must match training clean_solidity() exactly
    # ----------------------------------------------------------
    def _clean_code(self, code: str) -> str:
        if not isinstance(code, str):
            return ""
        code = re.sub(r'//.*',           '', code)   # single-line comments
        code = re.sub(r'/\*[\s\S]*?\*/', '', code)   # multi-line comments
        code = re.sub(r'\s+',            ' ', code)  # normalize whitespace
        return code.strip()

    # ----------------------------------------------------------
    # SLIDING WINDOW — must match training tokenization exactly
    # ----------------------------------------------------------
    def _get_chunks(self, cleaned_code: str):
        ids  = self.tokenizer(
            cleaned_code,
            add_special_tokens=False,
            truncation=False
        )["input_ids"]

        step = self.max_len - 2 - self.stride

        # Short contract — single chunk, no sliding needed
        if len(ids) <= self.max_len - 2:
            return [ids]

        chunks = []
        for i in range(0, len(ids), step):
            piece = ids[i : i + self.max_len - 2]
            if len(piece) < self.min_chunk_tokens:
                continue
            chunks.append(piece)

        return chunks

    def _chunk_to_tensor(self, piece):
        chunk     = [self.tokenizer.cls_token_id] + piece + [self.tokenizer.sep_token_id]
        pad       = self.max_len - len(chunk)
        input_ids = chunk + [self.tokenizer.pad_token_id] * pad
        attn_mask = [1] * len(chunk) + [0] * pad

        return (
            torch.tensor([input_ids], dtype=torch.long).to(self.device),
            torch.tensor([attn_mask], dtype=torch.long).to(self.device),
        )

    # ----------------------------------------------------------
    # PREDICT — main entry point
    # ----------------------------------------------------------
    def predict(self, raw_code: str) -> dict:
        """
        Scan a full Solidity contract and return the highest-risk finding.

        Returns dict with:
            label         : "Reentrancy"
            label_icon    : "🔴 Reentrancy"
            risk          : "🚨 High"
            confidence    : 0.90
            is_vulnerable : True
            all_scores    : {"Reentrancy": 0.90, "Integer Overflow": 0.05, ...}
            chunks_scanned: 3
        """
        cleaned = self._clean_code(raw_code)

        if not cleaned:
            return self._unknown_result()

        chunks      = self._get_chunks(cleaned)
        chunk_probs = []

        with torch.no_grad():
            for piece in chunks:
                input_ids, attn_mask = self._chunk_to_tensor(piece)
                outputs = self.model(input_ids=input_ids, attention_mask=attn_mask)
                probs   = F.softmax(outputs.logits, dim=-1).squeeze().cpu().numpy()
                chunk_probs.append(probs)

        if not chunk_probs:
            return self._unknown_result()

        # MAX POOLING — surface the highest risk found in any chunk
        all_probs  = np.array(chunk_probs)      # (n_chunks, n_classes)
        max_probs  = np.max(all_probs, axis=0)  # highest score per class
        pred_idx   = int(np.argmax(max_probs))
        confidence = float(max_probs[pred_idx])

        label_name = self.model.config.id2label[pred_idx]

        all_scores = {
            self.model.config.id2label[i]: float(max_probs[i])
            for i in range(len(max_probs))
        }

        return {
            "label":          label_name,
            "label_icon":     self._icon(label_name),
            "risk":           self._risk(confidence),
            "confidence":     confidence,
            "is_vulnerable":  True,
            "all_scores":     all_scores,
            "chunks_scanned": len(chunk_probs),
        }

    def predict_batch(self, code_list: list) -> list:
        return [self.predict(code) for code in code_list]

    # ----------------------------------------------------------
    # HELPERS
    # ----------------------------------------------------------
    def _unknown_result(self) -> dict:
        return {
            "label":          "Unknown",
            "label_icon":     "❓ Unknown",
            "risk":           "Unable to analyze",
            "confidence":     0.0,
            "is_vulnerable":  False,
            "all_scores":     {},
            "chunks_scanned": 0,
        }

    def _icon(self, label: str) -> str:
        icons = {
            "Reentrancy":             "🔴 Reentrancy",
            "Integer Overflow":       "🟠 Integer Overflow",
            "Timestamp Dependency":   "🟡 Timestamp Dependency",
            "Dangerous Delegatecall": "🔴 Dangerous Delegatecall",
        }
        return icons.get(label, f"❌ {label}")

    def _risk(self, confidence: float) -> str:
        if confidence >= self.HIGH_CONFIDENCE:
            return "🚨 High"
        if confidence >= self.MEDIUM_CONFIDENCE:
            return "⚠️ Medium"
        return "🔍 Low (Uncertain)"

    def format_report(self, result: dict) -> str:
        """Returns a markdown-formatted audit report for the Gradio UI."""
        lines = [
            "### 🛡️ Deep Learning Security Audit",
            "",
            f"**Finding:** {result['label_icon']}",
            f"**Risk Level:** {result['risk']}",
            f"**Confidence:** {result['confidence']:.1%}",
            f"**Chunks Scanned:** {result['chunks_scanned']}",
            "",
        ]

        if result["is_vulnerable"] and result["all_scores"]:
            lines += [
                "---",
                "**All Class Scores:**",
                "",
                "| Vulnerability | Score | |",
                "|---|---|---|",
            ]
            sorted_scores = sorted(
                result["all_scores"].items(),
                key=lambda x: x[1],
                reverse=True
            )
            for name, score in sorted_scores:
                bar = "█" * int(score * 20)
                lines.append(f"| {name} | {score:.1%} | {bar} |")

            lines += [
                "",
                "> 💡 **Ask the chat assistant for a detailed explanation and fix.**",
            ]
        else:
            lines.append("⚠️ Could not analyze this contract.")

        return "\n".join(lines)


# ----------------------------------------------------------
# SINGLETON — import this in ui.py
# ----------------------------------------------------------
vulnerability_auditor = VulnerabilityClassifier()


# ----------------------------------------------------------
# QUICK TEST — run: python predict.py
# ----------------------------------------------------------
if __name__ == "__main__":
    sample_reentrancy = """
    pragma solidity ^0.4.18;
    contract Vulnerable {
        mapping(address => uint) public balances;

        function withdraw(uint _amount) public {
            require(balances[msg.sender] >= _amount);
            msg.sender.call.value(_amount)();
            balances[msg.sender] -= _amount;
        }
    }
    """

    sample_overflow = """
    pragma solidity ^0.4.11;
    contract Overflow {
        uint public balance = 1;
        function add(uint256 deposit) public {
            balance += deposit;
        }
        function run(uint256 score) public {
            uint256 result = score + 1;
        }
    }
    """

    print("=" * 50)
    print("TEST 1: Reentrancy Contract")
    print("=" * 50)
    result = vulnerability_auditor.predict(sample_reentrancy)
    print(vulnerability_auditor.format_report(result))

    print("\n" + "=" * 50)
    print("TEST 2: Integer Overflow Contract")
    print("=" * 50)
    result = vulnerability_auditor.predict(sample_overflow)
    print(vulnerability_auditor.format_report(result))
