

import os
from typing import List

from dotenv import load_dotenv
from langchain_core.documents import Document
from langchain_core.output_parsers import StrOutputParser
from langchain_core.prompts import ChatPromptTemplate
from langchain_groq import ChatGroq

load_dotenv()

# ---------------------------------------------------------------------------
# LLM (reuse same provider as chain.py)
# ---------------------------------------------------------------------------

def _get_llm():
    return ChatGroq(
        groq_api_key=os.getenv("GROQ_API_KEY"),
        model_name="llama-3.1-8b-instant",
        temperature=0,
    )


# ---------------------------------------------------------------------------
# Prompts
# ---------------------------------------------------------------------------

MAP_PROMPT = ChatPromptTemplate.from_template(
    "You are a legal analyst. Read the following excerpt from a contract or legal document "
    "and write a concise bullet-point summary (3-5 bullets) of the most important information it contains.\n\n"
    "EXCERPT:\n{chunk_text}\n\n"
    "BULLET-POINT SUMMARY:"
)

REDUCE_PROMPT = ChatPromptTemplate.from_template(
    "You are a Senior Legal Analyst. Below are partial summaries from different sections "
    "of a legal document. Synthesize them into ONE structured final summary.\n\n"
    "PARTIAL SUMMARIES:\n{combined_summaries}\n\n"
    "Write the final summary using EXACTLY this structure:\n\n"
    "## 📋 Executive Overview\n"
    "<One paragraph describing the overall purpose and nature of the document>\n\n"
    "## 👥 Key Parties\n"
    "<List each party and their role>\n\n"
    "## 📌 Main Obligations & Rights\n"
    "<List the most important obligations and rights for each party>\n\n"
    "## 📅 Important Dates & Deadlines\n"
    "<List any dates, durations, or deadlines mentioned>\n\n"
    "## ⚠️ Risk & Liability Highlights\n"
    "<Summarize liability caps, indemnification, penalties, or risk clauses>\n\n"
    "## ❓ Recommended Follow-Up Questions\n"
    "<List 3-5 questions a reader should ask their lawyer about this document>\n\n"
    "*DISCLAIMER: AI-generated summary. Not legal advice.*"
)


# ---------------------------------------------------------------------------
# Map-Reduce pipeline
# ---------------------------------------------------------------------------

def _map_chunks(docs: List[Document], llm) -> List[str]:
    """Summarize each chunk individually (MAP step)."""
    map_chain = MAP_PROMPT | llm | StrOutputParser()
    summaries = []
    for i, doc in enumerate(docs):
        try:
            summary = map_chain.invoke({"chunk_text": doc.page_content})
            summaries.append(f"[Section {i+1}]\n{summary}")
        except Exception as exc:
            print(f"[summarization] Skipping chunk {i+1} due to error: {exc}")
    return summaries


def _reduce_summaries(partial_summaries: List[str], llm) -> str:
    """Combine partial summaries into one final summary (REDUCE step)."""
    combined = "\n\n".join(partial_summaries)

    # Guard against context-window overflow: truncate if too long
    max_chars = 12_000
    if len(combined) > max_chars:
        combined = combined[:max_chars] + "\n\n[... additional sections truncated for length ...]"

    reduce_chain = REDUCE_PROMPT | llm | StrOutputParser()
    return reduce_chain.invoke({"combined_summaries": combined})


def summarize_document(docs: List[Document]) -> str:
    """
    Run the full Map-Reduce summarization pipeline over a list of Document chunks.

    Parameters
    ----------
    docs : list of LangChain Document objects (e.g. from retriever.invoke(...))

    Returns
    -------
    str : Structured markdown summary of the document.
    """
    if not docs:
        return "⚠️ No document content found. Please upload and index a document first."

    llm = _get_llm()

    # MAP
    print(f"[summarization] Mapping {len(docs)} chunks...")
    partial_summaries = _map_chunks(docs, llm)

    if not partial_summaries:
        return "⚠️ Could not generate summaries from the document chunks."

    # REDUCE
    print("[summarization] Reducing to final summary...")
    final_summary = _reduce_summaries(partial_summaries, llm)

    return final_summary
