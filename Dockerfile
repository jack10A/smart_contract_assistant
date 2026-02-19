FROM python:3.11-slim

# 1. Set the working directory
WORKDIR /code

# 2. Copy requirements and install
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 3. Copy all your files into /code
COPY . .

# 4. STRUCTURE FIXER:
# This creates the 'app' folder and moves the files into it 
# so that your 'from app.xxx' imports work perfectly.
RUN mkdir -p app && \
    mv ingestion.py app/ && \
    mv chain.py app/ && \
    mv ui.py app/ && \
    mv guardrails.py app/ && \
    mv evaluation.py app/ && \
    mv summarization.py app/ && \
    touch app/__init__.py

# 5. Hugging Face port
EXPOSE 7860

# 6. Run main.py (which is still in the root)
CMD ["python", "main.py"]