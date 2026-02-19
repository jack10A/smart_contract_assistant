---
title: Smart Contract Assistant
emoji: 📑
colorFrom: blue
colorTo: indigo
sdk: docker
app_port: 7860
pinned: false
---

# Smart Contract Summary & Q&A Assistant

**Workshop Application Project (NVIDIA DLI Course Alignment)**

## Project Overview

A small-scale web application that allows users to upload long-form documents (contracts, insurance policies, reports) and interact with them via a conversational assistant. The system features multi-language support, conversation history tracking, and strict legal compliance guardrails.

## Technology Stack

- **Framework:** LangChain (LCEL), FastAPI, LangServe
- **UI:** Gradio (Multi-tab: Upload & Chat)
- **Database:** ChromaDB (Vector Store)
- **Models:**
  - LLM: Groq (Llama 3.1 8B Instant)
  - Embeddings: HuggingFace Cloud (Multilingual MiniLM)
- **Deployment:** Docker-ready

## Features

- **Multilingual RAG:** Automatically detects and responds in the user's language.
- **Source Citations:** Every answer includes page numbers mapped from the original PDF.
- **Compliance Reviewer:** A secondary AI chain reviews every answer to ensure it is factual and includes a mandatory legal disclaimer.
- **Contextual Memory:** Rephrases questions based on chat history for a true conversational experience.

## Installation & Setup

1. **Clone the Repo** and create a virtual environment.
2. **Install Dependencies:**
   ```bash
   pip install -r requirements.txt
   ```
