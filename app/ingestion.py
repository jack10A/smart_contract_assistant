import os
from dotenv import load_dotenv
from langchain_community.document_loaders import PyPDFLoader, Docx2txtLoader
from langchain_text_splitters import RecursiveCharacterTextSplitter
from langchain_community.vectorstores import Chroma
from langchain_huggingface import HuggingFaceEndpointEmbeddings

load_dotenv()

embeddings = HuggingFaceEndpointEmbeddings(
    huggingfacehub_api_token=os.getenv("HF_TOKEN"),
    model="sentence-transformers/distiluse-base-multilingual-cased-v1"
)

def process_document(file_path: str):
    print(f"--- Processing Document: {file_path} ---")

    if file_path.lower().endswith(".pdf"):
        loader = PyPDFLoader(file_path)
    elif file_path.lower().endswith(".docx") or file_path.lower().endswith(".doc"):
        loader = Docx2txtLoader(file_path)
    else:
        return "Unsupported file format. Please upload a PDF or DOCX."

    documents = loader.load()

    # Configurable chunk size — addresses "Large documents" risk from spec Section 10
    chunk_size = int(os.getenv("CHUNK_SIZE", "1500"))
    chunk_overlap = int(os.getenv("CHUNK_OVERLAP", "200"))
    text_splitter = RecursiveCharacterTextSplitter(
        chunk_size=chunk_size,
        chunk_overlap=chunk_overlap,
    )
    chunks = text_splitter.split_documents(documents)

    vector_db = Chroma.from_documents(
        documents=chunks,
        embedding=embeddings,
        persist_directory="./vector_db"
    )

    return f"Done! {os.path.basename(file_path)} is now indexed and searchable ({len(chunks)} chunks)."


def get_retriever(k: int = 5):
    """
    Return a Chroma retriever.

    Parameters
    ----------
    k : int
        Number of chunks to retrieve. Use a larger value (e.g. 50) for summarization.
    """
    return Chroma(
        persist_directory="./vector_db",
        embedding_function=embeddings
    ).as_retriever(search_kwargs={"k": k})