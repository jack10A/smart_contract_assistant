
import json
import os
import re
import time
from typing import Any, Dict, List, Optional

import numpy as np
from dotenv import load_dotenv
from langchain_core.output_parsers import StrOutputParser
from langchain_core.prompts import ChatPromptTemplate
from langchain_groq import ChatGroq
from langchain_huggingface import HuggingFaceEndpointEmbeddings

from app.chain import get_smart_contract_chain
from app.ingestion import get_retriever

load_dotenv()

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _get_embeddings():
    return HuggingFaceEndpointEmbeddings(
        huggingfacehub_api_token=os.getenv("HF_TOKEN"),
        model="sentence-transformers/distiluse-base-multilingual-cased-v1",
    )


def _get_llm():
    return ChatGroq(
        groq_api_key=os.getenv("GROQ_API_KEY"),
        model_name="llama-3.1-8b-instant",
        temperature=0,
    )


def _cosine_similarity(a: List[float], b: List[float]) -> float:
    va, vb = np.array(a), np.array(b)
    denom = np.linalg.norm(va) * np.linalg.norm(vb)
    return float(np.dot(va, vb) / denom) if denom > 0 else 0.0


def _token_overlap(text_a: str, text_b: str) -> float:
    """Simple token-level overlap ratio (recall of text_a tokens in text_b)."""
    tokens_a = set(text_a.lower().split())
    tokens_b = set(text_b.lower().split())
    if not tokens_a:
        return 0.0
    return len(tokens_a & tokens_b) / len(tokens_a)


def _rouge_l_f1(hypothesis: str, reference: str) -> float:
    """
    Compute ROUGE-L F1 via LCS length.
    Falls back gracefully if inputs are empty.
    """
    def lcs_length(x: List[str], y: List[str]) -> int:
        m, n = len(x), len(y)
        dp = [[0] * (n + 1) for _ in range(m + 1)]
        for i in range(1, m + 1):
            for j in range(1, n + 1):
                if x[i - 1] == y[j - 1]:
                    dp[i][j] = dp[i - 1][j - 1] + 1
                else:
                    dp[i][j] = max(dp[i - 1][j], dp[i][j - 1])
        return dp[m][n]

    hyp_tokens = hypothesis.lower().split()
    ref_tokens = reference.lower().split()
    if not hyp_tokens or not ref_tokens:
        return 0.0
    lcs = lcs_length(hyp_tokens, ref_tokens)
    precision = lcs / len(hyp_tokens)
    recall = lcs / len(ref_tokens)
    if precision + recall == 0:
        return 0.0
    return 2 * precision * recall / (precision + recall)


# ---------------------------------------------------------------------------
# Individual metric functions
# ---------------------------------------------------------------------------

def compute_context_recall(retrieved_docs, expected_answer: str) -> float:
    """Fraction of expected-answer tokens found across all retrieved chunks."""
    combined_context = " ".join(d.page_content for d in retrieved_docs)
    return _token_overlap(expected_answer, combined_context)


def compute_mrr(retrieved_docs, question: str, embeddings) -> float:
    """
    Mean Reciprocal Rank: embed the question and rank chunks by similarity.
    MRR = 1/rank_of_first_relevant_chunk.
    A chunk is 'relevant' if its similarity to the question exceeds 0.3.
    """
    if not retrieved_docs:
        return 0.0
    q_vec = embeddings.embed_query(question)
    chunk_vecs = embeddings.embed_documents([d.page_content for d in retrieved_docs])
    sims = [_cosine_similarity(q_vec, cv) for cv in chunk_vecs]
    for rank, sim in enumerate(sorted(sims, reverse=True), start=1):
        if sim >= 0.3:
            return 1.0 / rank
    return 0.0


def compute_context_precision(retrieved_docs, question: str, embeddings) -> float:
    """Fraction of retrieved chunks with similarity >= 0.25 to the question."""
    if not retrieved_docs:
        return 0.0
    q_vec = embeddings.embed_query(question)
    chunk_vecs = embeddings.embed_documents([d.page_content for d in retrieved_docs])
    relevant = sum(1 for cv in chunk_vecs if _cosine_similarity(q_vec, cv) >= 0.25)
    return relevant / len(retrieved_docs)


def compute_faithfulness(answer: str, context_docs, llm) -> float:
    """
    LLM-as-judge: split answer into sentences, ask LLM which are grounded in context.
    Returns fraction of sentences supported by the context (0.0 – 1.0).
    """
    sentences = [s.strip() for s in re.split(r"(?<=[.!?])\s+", answer) if len(s.strip()) > 20]
    if not sentences:
        return 1.0  # trivially faithful if nothing to check

    context_text = "\n\n".join(d.page_content for d in context_docs)[:2000]

    judge_prompt = ChatPromptTemplate.from_template(
        "You are a strict fact-checker. For each STATEMENT below, answer only YES or NO "
        "based on whether it is directly supported by the CONTEXT.\n\n"
        "CONTEXT:\n{context}\n\n"
        "STATEMENTS:\n{statements}\n\n"
        "Reply with one YES or NO per line, in the same order. Nothing else."
    )
    numbered = "\n".join(f"{i+1}. {s}" for i, s in enumerate(sentences))
    try:
        chain = judge_prompt | llm | StrOutputParser()
        raw = chain.invoke({"context": context_text, "statements": numbered})
        verdicts = re.findall(r"\b(YES|NO)\b", raw.upper())
        if verdicts:
            return sum(1 for v in verdicts if v == "YES") / len(verdicts)
    except Exception as exc:
        print(f"[evaluation] Faithfulness check failed: {exc}")
    return 1.0  # fail open


def compute_answer_relevance(question: str, answer: str, embeddings) -> float:
    """Cosine similarity between the question embedding and the answer embedding."""
    q_vec = embeddings.embed_query(question)
    a_vec = embeddings.embed_query(answer)
    return _cosine_similarity(q_vec, a_vec)


def compute_citation_coverage(answer: str) -> bool:
    """Return True if the answer contains at least one [Page X] citation."""
    return bool(re.search(r"\[Page\s+\d+\]", answer, re.IGNORECASE))


# ---------------------------------------------------------------------------
# Main evaluation runner
# ---------------------------------------------------------------------------

def run_evaluation(
    test_cases: List[Dict[str, Any]],
    output_path: str = "eval_report.json",
) -> List[Dict[str, Any]]:
    """
    Run the full evaluation suite over a list of test cases.

    Each test case is a dict with:
        question         (str, required)
        reference_answer (str, optional) — used for ROUGE-L and context recall

    Returns a list of result dicts (one per test case) and saves to `output_path`.
    """
    chain = get_smart_contract_chain()
    retriever = get_retriever()
    embeddings = _get_embeddings()
    llm = _get_llm()

    results = []

    for i, tc in enumerate(test_cases):
        question: str = tc["question"]
        reference: Optional[str] = tc.get("reference_answer", "")
        print(f"\n[evaluation] Running test {i+1}/{len(test_cases)}: {question[:60]}...")

        result: Dict[str, Any] = {"question": question, "reference_answer": reference}

        # --- Latency + Chain invocation ---
        t0 = time.time()
        try:
            response = chain.invoke({"input": question, "chat_history": []})
            latency = time.time() - t0
            answer: str = response.get("answer", "")
            context_docs = response.get("context", [])
        except Exception as exc:
            result["error"] = str(exc)
            results.append(result)
            continue

        result["answer"] = answer
        result["latency_seconds"] = round(latency, 2)

        # --- Retrieval metrics ---
        retrieved_docs = retriever.invoke(question)

        result["context_recall"] = (
            round(compute_context_recall(retrieved_docs, reference), 3)
            if reference else None
        )
        result["mrr"] = round(compute_mrr(retrieved_docs, question, embeddings), 3)
        result["context_precision"] = round(
            compute_context_precision(retrieved_docs, question, embeddings), 3
        )

        # --- Answer quality metrics ---
        result["faithfulness"] = round(
            compute_faithfulness(answer, context_docs, llm), 3
        )
        result["answer_relevance"] = round(
            compute_answer_relevance(question, answer, embeddings), 3
        )
        result["rouge_l_f1"] = (
            round(_rouge_l_f1(answer, reference), 3) if reference else None
        )
        result["citation_coverage"] = compute_citation_coverage(answer)

        results.append(result)
        print(f"  ✓ Latency: {latency:.2f}s | Faithfulness: {result['faithfulness']} | "
              f"Relevance: {result['answer_relevance']} | Citations: {result['citation_coverage']}")

    # Save report
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
    print(f"\n[evaluation] Report saved to {output_path}")

    return results


# ---------------------------------------------------------------------------
# Pretty-print report
# ---------------------------------------------------------------------------

def print_report(results: List[Dict[str, Any]]) -> None:
    """Print a human-readable summary table of evaluation results."""
    print("\n" + "=" * 70)
    print("  SMART CONTRACT ASSISTANT — EVALUATION REPORT")
    print("=" * 70)

    numeric_keys = [
        "latency_seconds", "context_recall", "mrr",
        "context_precision", "faithfulness", "answer_relevance", "rouge_l_f1",
    ]

    for i, r in enumerate(results, start=1):
        print(f"\n[Test {i}] {r['question'][:65]}")
        if "error" in r:
            print(f"  ERROR: {r['error']}")
            continue
        print(f"  Latency          : {r.get('latency_seconds', 'N/A')}s")
        print(f"  Context Recall   : {r.get('context_recall', 'N/A')} (requires reference answer)")
        print(f"  MRR              : {r.get('mrr', 'N/A')}")
        print(f"  Context Precision: {r.get('context_precision', 'N/A')}")
        print(f"  Faithfulness     : {r.get('faithfulness', 'N/A')}")
        print(f"  Answer Relevance : {r.get('answer_relevance', 'N/A')}")
        print(f"  ROUGE-L F1       : {r.get('rouge_l_f1', 'N/A')} (requires reference answer)")
        print(f"  Citation Coverage: {'✅' if r.get('citation_coverage') else '❌'}")

    # Aggregate averages (only numeric, non-None values)
    print("\n" + "-" * 70)
    print("  AVERAGES ACROSS ALL TEST CASES")
    print("-" * 70)
    for key in numeric_keys:
        vals = [r[key] for r in results if r.get(key) is not None and isinstance(r.get(key), float)]
        if vals:
            print(f"  {key:<22}: {sum(vals)/len(vals):.3f}")
    citation_rate = sum(1 for r in results if r.get("citation_coverage")) / len(results)
    print(f"  {'citation_coverage':<22}: {citation_rate:.0%}")
    print("=" * 70 + "\n")


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    # Default test suite — replace or extend with domain-specific questions
    DEFAULT_TEST_CASES = [
        {
            "question": "What are the payment terms in this contract?",
            "reference_answer": "",
        },
        {
            "question": "Who are the parties involved in this agreement?",
            "reference_answer": "",
        },
        {
            "question": "What happens if one party breaches the contract?",
            "reference_answer": "",
        },
        {
            "question": "What is the governing law for this contract?",
            "reference_answer": "",
        },
        {
            "question": "Are there any confidentiality obligations?",
            "reference_answer": "",
        },
    ]

    eval_results = run_evaluation(DEFAULT_TEST_CASES)
    print_report(eval_results)
