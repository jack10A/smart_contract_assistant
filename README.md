---
title: ChainSentinel AI
emoji: 📑
colorFrom: blue
colorTo: indigo
sdk: docker
app_port: 7860
pinned: false
---

# ChainSentinel AI

ChainSentinel AI is a multi-agent, Gradio/FastAPI smart contract security assistant for contract review, document chat, CSV anomaly analysis, transaction-trace investigation, and screenshot phishing analysis. A coordinator agent routes workspace files to specialist agents for Solidity auditing, RAG indexing, CSV anomaly detection, JSON trace analysis, image security review, cross-domain correlation, remediation guidance, and report writing. The Solidity workflow combines a fine-tuned CodeBERT classifier with Slither static analysis, line-level evidence, generated fixes, and Slither re-audit validation.

## Key Features

- **Multi-agent investigation:** A coordinator agent dispatches specialist agents for Solidity, CSV, trace, image, RAG evidence, correlation, remediation, and report writing.
- **Hybrid Solidity audit:** CodeBERT predicts the primary vulnerability class, while Slither confirms or challenges the result with static-analysis findings.
- **Risk dashboard:** Shows final verdict, hybrid confirmation, confirmed static findings, multi-vulnerability summary, and a transparent risk score breakdown.
- **Line-level evidence:** Groups source lines into primary evidence, related attack surface, and other security-relevant lines.
- **Function-level analysis:** Runs the deep learning classifier per Solidity function and labels results as strong, weak, or low-confidence signals.
- **Automated fix generation:** Generates patched Solidity code, shows a patch diff, and re-runs Slither to validate whether High/Medium findings remain.
- **Fix validation:** Marks generated patches as Accepted, Needs another pass, or Rejected based on Slither re-audit results.
- **Low-signal guard:** Avoids unnecessary fixes when the ML prediction is low-confidence and not confirmed by Slither/source evidence.
- **CSV anomaly detection:** Uses a PyTorch autoencoder plus Isolation Forest consensus to detect anomalous transaction rows.
- **CSV-to-contract correlation:** Links anomalous CSV rows to the last audited Solidity contract and identifies possible transfer-capable functions.
- **JSON trace analysis:** Extracts trace behavior and correlates runtime signals with Solidity audit findings.
- **Image security analysis:** Uses a trained image classifier plus OCR rules to detect phishing screenshots, payment-verification lures, wallet approvals, addresses, and transaction hashes.
- **Workspace chat and reports:** Supports source-grounded chat, summaries, audit history, executive PDF export, and full technical audit reports.

## Supported Inputs

- Solidity contracts: `.sol`
- Documents: `.pdf`, `.doc`, `.docx`, `.txt`
- Transaction datasets: `.csv`
- Transaction traces: `.json`
- Security screenshots: `.png`, `.jpg`, `.jpeg`, `.webp`

## Technology Stack

- **Application:** FastAPI, LangServe, Gradio
- **Agent architecture:** Custom multi-agent coordinator and specialist-agent workflow
- **RAG:** LangChain LCEL, ChromaDB
- **LLM:** Groq Llama 3.1 8B Instant
- **Embeddings:** HuggingFace multilingual MiniLM
- **Solidity ML classifier:** CodeBERT sequence classifier
- **Static analysis:** Slither
- **CSV anomaly model:** PyTorch autoencoder and scikit-learn Isolation Forest
- **Image classifier:** MobileNetV3 small
- **OCR:** pytesseract or EasyOCR
- **Reports:** Matplotlib PDF export

## Run Locally

```bash
pip install -r requirements.txt
python main.py
```

Then open:

```text
http://127.0.0.1:7860
```

Optional but recommended for Solidity static analysis:

```bash
pip install slither-analyzer
```

## Demo Workflow

1. Upload `hybrid_vulnerable_test.sol`.
2. Review the risk dashboard:
   - CodeBERT primary ML focus
   - Slither confirmation
   - multi-vulnerability summary
   - risk score breakdown
3. Click **Generate fix**.
4. Review the patch diff and Slither re-audit validation.
5. Upload the generated fixed file and confirm the dashboard drops to Low risk.
6. Upload `apple (12).png` and run image security analysis to see a phishing example.
7. Upload `legitimate_bookstore_test.png` and confirm it is classified as legitimate/low risk.
8. Run CSV anomaly detection, enter an anomalous row number, and correlate it with the last Solidity audit.
9. Use **Multi-Agent Auto-Investigator** to run the coordinated specialist-agent workflow across the full workspace.

## Multi-Agent Architecture

```text
User
  -> Coordinator Agent
     -> Document Indexer Agent
     -> Solidity Auditor Agent
     -> CSV Anomaly Agent
     -> Trace Analysis Agent
     -> Image Security Agent
     -> Correlation Agent
     -> Remediation Agent
     -> Report Writer Agent
  -> Final investigation summary and PDF report
```

## Example Test Assets

- `data/hybrid_vulnerable_test.sol`: vulnerable contract with delegatecall, reentrancy, and timestamp dependency.
- `data/clean_test.sol`: mostly safe Solidity contract for low-signal testing.
- `data/legitimate_bookstore_test.png`: benign image screenshot for image classifier testing.
- `workspace_uploads/sample_security_screenshot.png`: security screenshot sample.

## Important Limitations

- The current Solidity classifier is trained on four vulnerability classes and does not include a real Clean class.
- Low-risk handling is implemented with a practical confidence/static-evidence guard, not a dedicated clean-label model.
- CSV-to-contract correlation is behavioral. It does not prove a specific function executed unless the CSV or trace includes transaction hash, method name, function selector, or call trace.
- Generated fixes must be manually reviewed and tested before production use.
- Slither and OCR availability depend on the local environment.

## Disclaimer

This tool is for educational and research assistance. It does not replace a professional security audit, legal review, or production-grade testing process.
