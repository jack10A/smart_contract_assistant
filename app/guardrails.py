

import os
import re
from typing import Tuple

import numpy as np
from dotenv import load_dotenv
from langchain_huggingface import HuggingFaceEndpointEmbeddings

load_dotenv()

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

RELEVANCE_THRESHOLD = 0.10   # cosine similarity minimum (0–1). Tune as needed.

# Representative phrases that define "on-topic" for a legal/contract assistant.
SAFE_TOPIC_PHRASES = [
    "contract terms and conditions",
    "legal clause interpretation",
    "payment obligations in agreement",
    "termination clause",
    "intellectual property rights",
    "liability and indemnification",
    "force majeure provision",
    "governing law and jurisdiction",
    "confidentiality and non-disclosure",
    "dispute resolution arbitration",
    "insurance policy coverage",
    "warranty and representations",
    "amendment and modification of contract",
    "party obligations and responsibilities",
    "effective date and duration of agreement",
]

# Hard-block patterns — rejected immediately, no embedding check needed.
BLOCKLIST_PATTERNS = [
    r"\b(how to (make|build|create) (a )?(bomb|weapon|explosive|poison))\b",
    r"\b(suicide|self.harm|kill (myself|yourself))\b",
    r"\bchild (porn|abuse|exploit)\b",
    r"\b(hack|crack|exploit) (a |the )?(system|server|password|account)\b",
]

# ---------------------------------------------------------------------------
# Lazy-loaded embeddings (same model as ingestion.py)
# ---------------------------------------------------------------------------

_embeddings_model = None
_safe_topic_matrix = None  # shape: (N, D)


def _get_embeddings():
    global _embeddings_model
    if _embeddings_model is None:
        _embeddings_model = HuggingFaceEndpointEmbeddings(
            huggingfacehub_api_token=os.getenv("HF_TOKEN"),
            model="sentence-transformers/distiluse-base-multilingual-cased-v1",
        )
    return _embeddings_model


def _get_safe_topic_matrix() -> np.ndarray:
    """Embed safe topic phrases once and cache them."""
    global _safe_topic_matrix
    if _safe_topic_matrix is None:
        emb = _get_embeddings()
        vecs = emb.embed_documents(SAFE_TOPIC_PHRASES)
        _safe_topic_matrix = np.array(vecs, dtype=np.float32)
    return _safe_topic_matrix


# ---------------------------------------------------------------------------
# Core helpers
# ---------------------------------------------------------------------------

def _cosine_similarity(a: np.ndarray, b: np.ndarray) -> float:
    """Return cosine similarity between two 1-D vectors."""
    norm_a = np.linalg.norm(a)
    norm_b = np.linalg.norm(b)
    if norm_a == 0 or norm_b == 0:
        return 0.0
    return float(np.dot(a, b) / (norm_a * norm_b))


def _max_similarity_to_safe_topics(query_vec: np.ndarray) -> float:
    """Return the highest cosine similarity between the query and any safe topic."""
    topic_matrix = _get_safe_topic_matrix()
    similarities = [
        _cosine_similarity(query_vec, topic_matrix[i])
        for i in range(topic_matrix.shape[0])
    ]
    return max(similarities)


def _hits_blocklist(text: str) -> bool:
    """Return True if the text matches any hard-block pattern."""
    lower = text.lower()
    for pattern in BLOCKLIST_PATTERNS:
        if re.search(pattern, lower):
            return True
    return False


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def check_query(user_input: str) -> Tuple[bool, str]:
    """
    Validate a user query before it reaches the RAG chain.

    Returns
    -------
    (is_safe, message)
        is_safe : True  → query is allowed, proceed normally.
                  False → query is blocked; show `message` to the user instead.
        message : Empty string when safe; rejection explanation when blocked.
    """
    if not user_input or not user_input.strip():
        return False, "⚠️ Please enter a question."

    # 1. Hard blocklist check
    if _hits_blocklist(user_input):
        return (
            False,
            "⛔ Your query contains content that cannot be processed. "
            "Please ask questions related to your uploaded contract or document.",
        )

    # 2. Semantic relevance check
    try:
        emb = _get_embeddings()
        query_vec = np.array(emb.embed_query(user_input), dtype=np.float32)
        similarity = _max_similarity_to_safe_topics(query_vec)

        if similarity < RELEVANCE_THRESHOLD:
            return (
                False,
                (
                    f"⚠️ Your question doesn't appear to be related to legal documents "
                    f"or contracts (relevance score: {similarity:.2f}). "
                    "Please ask about the content of your uploaded document."
                ),
            )
    except Exception as exc:
        
        print(f"[guardrails] Embedding check failed, failing open: {exc}")

    return True, ""
