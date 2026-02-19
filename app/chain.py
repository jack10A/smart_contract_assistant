import os
from operator import itemgetter
from dotenv import load_dotenv
from langchain_groq import ChatGroq
from langchain_core.prompts import ChatPromptTemplate, MessagesPlaceholder
from langchain_core.runnables import RunnablePassthrough
from langchain_core.output_parsers import StrOutputParser
from app.ingestion import get_retriever

load_dotenv()

def get_smart_contract_chain():
    # --- 1. SETUP LLM ---
    llm = ChatGroq(
        groq_api_key=os.getenv("GROQ_API_KEY"),
        model_name="llama-3.1-8b-instant",
        temperature=0
    )

    retriever = get_retriever()

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
        "ROLE: Senior Legal Analyst. \n"
        "INSTRUCTIONS:\n"
        " 1. LANGUAGE DETECTOR: You must detect the language of the NEWEST user message. "
        "Ignore the language used in chat history. If the new question is English, answer in English. "
        "If it is Spanish, answer in Spanish.\n"
        "2. Answer ONLY using the provided context. You MUST cite at least one page like [Page X] — this is mandatory.Always include specific amounts, dates, or numbers when they appear in the context.\n"
        "3. If info is missing, say so in the user's language.\n"
        "4. Finish with the mandatory legal disclaimer.\n\n"
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
        "1. LANGUAGE: The user's question was: '{user_input}'. "
        "You MUST write the final answer in the EXACT same language as that question. "
        "Ignore the language of the chat history or the draft answer.\n"
        "2. CITATIONS: Ensure page numbers like [Page X] are present.\n"
        "3. LEGAL DISCLAIMER: Ensure the response ends with: '*DISCLAIMER: AI-generated info. Not legal advice.*'\n\n"
        "CONTEXT: {context}\n"
        "ANSWER TO REVIEW: {answer}\n\n"
        "TASK: Provide the final corrected legal answer in the CORRECT language. NOTHING ELSE."
    )

    # --- 5. BUILD CHAIN ---
    def get_docs(input_data):
        user_input = input_data.get("input") or input_data.get("query") or ""
        if input_data.get("chat_history"):
            query = condense_chain.invoke({"input": user_input, "chat_history": input_data["chat_history"]})
        else:
            query = user_input
        return retriever.invoke(query)

    base_answer_chain = (
        RunnablePassthrough.assign(context=get_docs)
        | RunnablePassthrough.assign(
            answer=(qa_prompt | llm | StrOutputParser())
        )
    )

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