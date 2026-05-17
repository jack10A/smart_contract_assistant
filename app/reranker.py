"""
reranker.py — Deep Learning Re-Ranking Component
=================================================
WHY THIS EXISTS:
    ChromaDB retrieves chunks using vector similarity (embeddings).
    This is fast but approximate — it finds chunks *topically close*
    to the question, not necessarily the ones that *directly answer* it.

    This module adds a second pass using a Cross-Encoder neural network.
    A Cross-Encoder reads the question AND a chunk together (not separately)
    which gives it a much deeper understanding of relevance.

HOW IT FITS IN THE PIPELINE:
    Before:  ChromaDB(k=5)  →  Llama
    After:   ChromaDB(k=10) →  CrossEncoder re-scores all 10  →  Top 3  →  Llama

    The LLM now only sees the 3 most relevant chunks instead of 5 mediocre ones.
    This directly improves answer quality and reduces hallucination.

MODEL USED:
    cross-encoder/ms-marco-MiniLM-L-6-v2
    - Trained on 500k real search queries (MS MARCO dataset)
    - Very small and fast (~22MB) — runs on CPU easily
    - Returns a raw relevance score (higher = more relevant)
    - No need to train anything — we use it pretrained from HuggingFace
"""

from sentence_transformers import CrossEncoder

# ---------------------------------------------------------------------------
# Model — loaded once at import time, reused on every query (singleton pattern)
# ---------------------------------------------------------------------------

# This is the same pattern you used in predict.py with VulnerabilityClassifier.
# We load the model once so it doesn't re-download on every chat message.

_reranker_model = None

def _get_model() -> CrossEncoder:
    """Lazy-load the cross-encoder model (downloads once, cached locally)."""
    global _reranker_model
    if _reranker_model is None:
        print("[reranker] Loading cross-encoder model...")
        _reranker_model = CrossEncoder(
            "cross-encoder/ms-marco-MiniLM-L-6-v2",
            max_length=512   # same max_length you used in train.py
        )
        print("[reranker] Model ready.")
    return _reranker_model


# ---------------------------------------------------------------------------
# Core function — this is the only thing chain.py needs to call
# ---------------------------------------------------------------------------

def rerank(query: str, docs: list, top_k: int = 3) -> list:
    """
    Re-rank a list of LangChain Document objects by relevance to the query.

    HOW IT WORKS:
        1. Build pairs: [(query, chunk1_text), (query, chunk2_text), ...]
        2. Feed all pairs into the CrossEncoder at once
        3. The model outputs one relevance score per pair
        4. Sort documents by score (highest first)
        5. Return only the top_k most relevant ones

    Parameters
    ----------
    query : str
        The user's question (already condensed by chain.py if needed).
    docs  : list of LangChain Document objects
        The chunks retrieved by ChromaDB — typically 10.
    top_k : int
        How many top documents to keep — typically 3.

    Returns
    -------
    list of LangChain Document objects, sorted best-first, length = top_k
    """
    if not docs:
        return docs

    model = _get_model()

    # Step 1: Build (query, chunk_text) pairs for the model
    # This is the key difference from embeddings:
    # embeddings encode query and chunk SEPARATELY,
    # cross-encoders read them TOGETHER — much more accurate.
    pairs = [(query, doc.page_content) for doc in docs]

    # Step 2: Score all pairs in one forward pass through the neural network
    scores = model.predict(pairs)

    # Step 3: Attach scores to documents so we can sort them
    scored_docs = list(zip(scores, docs))

    # Step 4: Sort by score descending (most relevant first)
    scored_docs.sort(key=lambda x: x[0], reverse=True)

    # Step 5: Return only the top_k documents (without the scores)
    top_docs = [doc for _, doc in scored_docs[:top_k]]

    # Log so you can see it working in the terminal
    print(f"[reranker] Scored {len(docs)} chunks → kept top {top_k}")
    for i, (score, doc) in enumerate(scored_docs[:top_k]):
        source = doc.metadata.get("filename", "?")
        page   = doc.metadata.get("page", "?")
        print(f"  #{i+1} score={score:.3f}  source={source}  page={page}")

    return top_docs