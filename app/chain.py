import os
from operator import itemgetter
from dotenv import load_dotenv
from langchain_groq import ChatGroq
from langchain_core.prompts import ChatPromptTemplate, MessagesPlaceholder
from langchain_core.runnables import RunnablePassthrough
from langchain_core.output_parsers import StrOutputParser
from app.reranker import rerank  # Step 3: DL re-ranker

load_dotenv()

def get_smart_contract_chain(retriever):
    """
    Builds the RAG chain using a dynamic retriever 
    based on the file selected in the UI.
    """
    
    # --- 1. SETUP LLM ---
    llm = ChatGroq(
        groq_api_key=os.getenv("GROQ_API_KEY"),
        model_name="llama-3.1-8b-instant",
        temperature=0,
        max_tokens=600 
    )

    # --- 2. HISTORY CONDENSATION LOGIC ---
    contextualize_system_prompt = (
        "Given a chat history and the latest user question, "
        "formulate a standalone question that can be understood without history."
    )
    contextualize_prompt = ChatPromptTemplate.from_messages([
        ("system", contextualize_system_prompt),
        MessagesPlaceholder(variable_name="chat_history"),
        ("human", "{input}"),
    ])
    condense_chain = contextualize_prompt | llm | StrOutputParser()

    # --- 3. BASE ANSWER GENERATION PROMPT ---
    system_prompt = (
        "ROLE: Senior Smart Contract Auditor & Legal Analyst. \n"
        "INSTRUCTIONS:\n"
        "1. LANGUAGE: Detect the language of the NEWEST user message. Answer in that EXACT language.\n"
        "2. CONTEXT: Answer ONLY using the provided context. Use technical precision for Solidity code.\n"
        "3. SOURCE: You MUST mention the source filename or page if available in the context metadata.\n"
        "4. MISSING INFO: If the context doesn't contain the answer, say so clearly in the user's language.\n"
        "5. DISCLAIMER: Always finish with the mandatory AI legal disclaimer.\n\n"
        "CONTEXT: {context}"
    )
    
    qa_prompt = ChatPromptTemplate.from_messages([
        ("system", system_prompt),
        MessagesPlaceholder(variable_name="chat_history"),
        ("human", "{input}"),
    ])

    # --- 4. COMPLIANCE VERIFICATION PROMPT ---
    compliance_prompt = ChatPromptTemplate.from_template(
        "You are a strict legal editor. Review the answer based ONLY on the context.\n\n"
        "RULES:\n"
        "1. LANGUAGE: The user's question was: '{user_input}'. The answer MUST be in that same language.\n"
        "2. VERIFY: Ensure the answer accurately reflects the code/document provided in the context.\n"
        "3. LEGAL DISCLAIMER: Ensure the response ends with: '*DISCLAIMER: AI-generated info. Not legal advice.*'\n\n"
        "CONTEXT: {context}\n"
        "ANSWER TO REVIEW: {answer}\n\n"
        "TASK: Provide the final corrected legal answer. NOTHING ELSE."
    )

    # --- 5. BUILD DYNAMIC CHAIN ---
    def get_docs(input_data):
        """
        Fetch documents then re-rank them with the DL cross-encoder.

        Before:  retriever returns 5 chunks by vector similarity  →  Llama
        After:   retriever returns 10 chunks  →  CrossEncoder picks best 3  →  Llama
        """
        user_input = input_data.get("input") or ""
        if input_data.get("chat_history"):
            query = condense_chain.invoke({"input": user_input, "chat_history": input_data["chat_history"]})
        else:
            query = user_input

        # Step A: cast a wider net — retrieve 10 candidates instead of 5
        candidates = retriever.invoke(query)

        # Step B: re-rank with the cross-encoder, keep only the best 3
        return rerank(query, candidates, top_k=3)

    # Step A: Retrieve context and generate draft answer
    base_answer_chain = (
        RunnablePassthrough.assign(context=get_docs)
        | RunnablePassthrough.assign(
            answer=(qa_prompt | llm | StrOutputParser())
        )
    )

    # Step B: Pass draft through compliance reviewer
    final_chain = base_answer_chain | {
        "answer": (
            {
                "answer": itemgetter("answer"),
                "context": itemgetter("context"),
                "user_input": itemgetter("input")
            }
            | compliance_prompt
            | llm
            | StrOutputParser()
        ),
        "context": itemgetter("context")
    }

    return final_chain