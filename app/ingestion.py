import os
from dotenv import load_dotenv
from langchain_community.document_loaders import PyPDFLoader, Docx2txtLoader, TextLoader
from langchain_text_splitters import RecursiveCharacterTextSplitter, Language
from langchain_community.vectorstores import Chroma
from langchain_huggingface import HuggingFaceEndpointEmbeddings

load_dotenv()

ALL_FILES_LABEL = "All Files"

# Initialize Embeddings
embeddings = HuggingFaceEndpointEmbeddings(
    huggingfacehub_api_token=os.getenv("HF_TOKEN"),
    model="sentence-transformers/distiluse-base-multilingual-cased-v1"
)

def process_document(file_path: str):
    """
    Loads, cleans, tags, and indexes a document into the persistent workspace.
    """
    print(f"--- Adding Document to Workspace: {file_path} ---")
    filename = os.path.basename(file_path)
    ext = file_path.lower()

    # 1. LOAD THE DATA
    try:
        if ext.endswith(".pdf"):
            loader = PyPDFLoader(file_path)
        elif ext.endswith(".docx") or ext.endswith(".doc"):
            loader = Docx2txtLoader(file_path)
        elif ext.endswith(".sol") or ext.endswith(".txt"):
            loader = TextLoader(file_path, encoding="utf-8")
        else:
            return "Unsupported format. Use PDF, DOCX, or .SOL"
        
        documents = loader.load()
    except Exception as e:
        return f"Error loading {filename}: {str(e)}"

    # 2. TAG WITH FILENAME METADATA
    for doc in documents:
        doc.metadata["filename"] = filename

    # 3. SPLIT THE DATA
    if ext.endswith(".sol"):
        # FIXED: Changed "solidity" to Language.SOL based on your error log
        text_splitter = RecursiveCharacterTextSplitter.from_language(
            language=Language.SOL, 
            chunk_size=1000,
            chunk_overlap=150,
        )
    else:
        text_splitter = RecursiveCharacterTextSplitter(
            chunk_size=1000,
            chunk_overlap=150,
        )
    
    chunks = text_splitter.split_documents(documents)

    # 4. ADD TO PERSISTENT CHROMA DB
    vector_db = Chroma.from_documents(
        documents=chunks,
        embedding=embeddings,
        persist_directory="./vector_db"
    )

    return f"Done! {filename} is now in your workspace and searchable ({len(chunks)} chunks)."


def get_retriever(selected_filename: str | list[str] = None, k: int = 10):
    """
    Returns a retriever.
    If selected_filename is provided, it searches chunks from THAT file.
    If selected_filename is "All Files" or empty, it searches the full workspace.
    """
    vector_db = Chroma(
        persist_directory="./vector_db",
        embedding_function=embeddings
    )
    
    if isinstance(selected_filename, list):
        selected = [name for name in selected_filename if name and name != ALL_FILES_LABEL]
        if selected:
            return vector_db.as_retriever(
                search_kwargs={
                    "k": k,
                    "filter": {"filename": {"$in": selected}}
                }
            )

    if selected_filename and selected_filename != ALL_FILES_LABEL:
        return vector_db.as_retriever(
            search_kwargs={
                "k": k,
                "filter": {"filename": selected_filename} 
            }
        )
    
    return vector_db.as_retriever(search_kwargs={"k": k})

def get_workspace_files():
    """Returns a list of unique filenames currently in the vector database."""
    if not os.path.exists("./vector_db"):
        return []
    
    try:
        vector_db = Chroma(
            persist_directory="./vector_db",
            embedding_function=embeddings
        )
        data = vector_db.get()
        if data and "metadatas" in data:
            filenames = {m.get("filename") for m in data["metadatas"] if m.get("filename")}
            return list(filenames)
    except:
        return []
    return []
