

import json

import gradio as gr
from langchain_core.messages import AIMessage, HumanMessage

from app.chain import get_smart_contract_chain
from app.evaluation import print_report, run_evaluation
from app.guardrails import check_query
from app.ingestion import get_retriever, process_document
from app.summarization import summarize_document


# ---------------------------------------------------------------------------
# Tab 1 — Upload
# ---------------------------------------------------------------------------

def upload_file(file):
    if file is not None:
        status = process_document(file.name)
        return status
    return "No file uploaded."


# ---------------------------------------------------------------------------
# Tab 2 — Chat (with guardrails)
# ---------------------------------------------------------------------------

def chat_response(message, history):
    # 1. Guardrail check — BEFORE the LLM is ever called
    is_safe, guard_message = check_query(message)
    if not is_safe:
        return guard_message

    # 2. Get the chain
    chain = get_smart_contract_chain()

    # 3. Convert Gradio history → LangChain messages
    chat_history = []
    for msg in history:
        if isinstance(msg, dict):
            role = msg.get("role")
            content = msg.get("content")
        else:
            role = msg.role
            content = msg.content

        if role == "user":
            chat_history.append(HumanMessage(content=content))
        elif role == "assistant":
            chat_history.append(AIMessage(content=content))

    # 4. Invoke chain
    try:
        response = chain.invoke({"input": message, "chat_history": chat_history})
        answer = response.get("answer", "I'm sorry, I couldn't generate an answer.")

        # 5. Extract page citations
        context_docs = response.get("context", [])
        sources = set()
        for doc in context_docs:
            page = doc.metadata.get("page", 0) + 1
            sources.add(f"Page {page}")

        source_text = "\n\n📍 **Sources:** " + (
            ", ".join(sorted(sources)) if sources else "No specific page cited."
        )
        return answer + source_text

    except Exception as e:
        return f"Error connecting to AI: {str(e)}"


# ---------------------------------------------------------------------------
# Tab 3 — Summarize
# ---------------------------------------------------------------------------

def generate_summary():
    """Retrieve all indexed chunks and run the Map-Reduce summarization pipeline."""
    try:
        retriever = get_retriever(k=50)
        docs = retriever.invoke(
            "contract summary overview parties obligations rights terms"
        )
        if not docs:
            return "⚠️ No indexed document found. Please upload a document first."
        summary = summarize_document(docs)
        return summary
    except Exception as e:
        return f"❌ Summarization failed: {str(e)}"


# ---------------------------------------------------------------------------
# Tab 4 — Evaluate
# ---------------------------------------------------------------------------

DEFAULT_EVAL_QUESTIONS = (
    "What are the payment terms in this contract?\n"
    "Who are the parties involved in this agreement?\n"
    "What happens if one party breaches the contract?\n"
    "What is the governing law for this contract?\n"
    "Are there any confidentiality obligations?"
)


def run_eval(questions_text: str) -> str:
    """Parse newline-separated questions and run the evaluation suite."""
    lines = [q.strip() for q in questions_text.strip().splitlines() if q.strip()]
    if not lines:
        return "⚠️ Please enter at least one question."

    test_cases = [{"question": q} for q in lines]

    try:
        results = run_evaluation(test_cases, output_path="eval_report.json")
    except Exception as e:
        return f"❌ Evaluation failed: {str(e)}"

    # Build a readable markdown table
    rows = ["| # | Question | Latency(s) | Faithfulness | Relevance | MRR | Citations |",
            "|---|----------|-----------|--------------|-----------|-----|-----------|"]
    for i, r in enumerate(results, start=1):
        if "error" in r:
            rows.append(f"| {i} | {r['question'][:40]} | ERROR | — | — | — | — |")
        else:
            rows.append(
                f"| {i} | {r['question'][:40]} "
                f"| {r.get('latency_seconds','—')} "
                f"| {r.get('faithfulness','—')} "
                f"| {r.get('answer_relevance','—')} "
                f"| {r.get('mrr','—')} "
                f"| {'✅' if r.get('citation_coverage') else '❌'} |"
            )

    # Aggregates
    def avg(key):
        vals = [r[key] for r in results if isinstance(r.get(key), float)]
        return f"{sum(vals)/len(vals):.3f}" if vals else "—"

    rows += [
        "",
        f"**Avg Latency:** {avg('latency_seconds')}s &nbsp;|&nbsp; "
        f"**Avg Faithfulness:** {avg('faithfulness')} &nbsp;|&nbsp; "
        f"**Avg Relevance:** {avg('answer_relevance')} &nbsp;|&nbsp; "
        f"**Avg MRR:** {avg('mrr')}",
        "",
        "_Full JSON report saved to `eval_report.json`_",
        "",
        "*DISCLAIMER: AI-generated evaluation. Not legal advice.*",
    ]

    return "\n".join(rows)


# ---------------------------------------------------------------------------
# Build UI
# ---------------------------------------------------------------------------

with gr.Blocks(theme=gr.themes.Soft()) as demo:
    gr.Markdown("# 📑 Smart Contract Assistant")
    gr.Markdown(
        "Upload a contract, ask questions, generate a summary, or evaluate answer quality."
    )

    # ── Tab 1: Upload ──────────────────────────────────────────────────────
    with gr.Tab("1. Upload Contract"):
        gr.Markdown("### Step 1: Upload your PDF or DOCX contract")
        file_input = gr.File(label="Upload Document (PDF or DOCX)")
        upload_button = gr.Button("Process & Index", variant="primary")
        upload_status = gr.Textbox(label="Status", interactive=False)
        upload_button.click(upload_file, inputs=file_input, outputs=upload_status)

    # ── Tab 2: Chat ────────────────────────────────────────────────────────
    with gr.Tab("2. Chat with Assistant"):
        gr.Markdown(
            "### Step 2: Ask questions about the contract\n"
            "_Questions unrelated to legal/contract content will be blocked by the guardrail._"
        )
        gr.ChatInterface(chat_response)

    # ── Tab 3: Summarize ───────────────────────────────────────────────────
    with gr.Tab("3. Summarize Contract"):
        gr.Markdown(
            "### Auto-generate a structured summary of the indexed document\n"
            "Uses a **Map-Reduce** pipeline: each chunk is summarised individually, "
            "then all summaries are combined into one final report."
        )
        summarize_button = gr.Button("Generate Summary", variant="primary")
        summary_output = gr.Markdown(label="Summary")
        summarize_button.click(generate_summary, inputs=[], outputs=summary_output)

    # ── Tab 4: Evaluate ────────────────────────────────────────────────────
    with gr.Tab("4. Evaluate Quality"):
        gr.Markdown(
            "### Run the evaluation suite against the indexed document\n"
            "Enter one question per line. The pipeline measures **faithfulness**, "
            "**answer relevance**, **MRR**, **context precision**, **latency**, and **citation coverage**."
        )
        eval_questions = gr.Textbox(
            label="Test Questions (one per line)",
            lines=8,
            value=DEFAULT_EVAL_QUESTIONS,
        )
        eval_button = gr.Button("Run Evaluation", variant="primary")
        eval_output = gr.Markdown(label="Evaluation Report")
        eval_button.click(run_eval, inputs=eval_questions, outputs=eval_output)


if __name__ == "__main__":
    demo.launch()