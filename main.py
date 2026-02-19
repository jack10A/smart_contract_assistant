import os
from fastapi import FastAPI
from langserve import add_routes
import uvicorn
from app.ui import demo
from app.chain import get_smart_contract_chain
import webbrowser
from threading import Timer

app = FastAPI(title="Smart Contract Assistant API")

# LangServe microservice endpoint
add_routes(
    app,
    get_smart_contract_chain(),
    path="/assistant",
)

def open_browser():
    webbrowser.open("http://127.0.0.1:8000")

# Mount Gradio UI
import gradio as gr
app = gr.mount_gradio_app(app, demo, path="/")

if __name__ == "__main__":
    print("--- Server is launching ---")
    if not os.environ.get("DOCKER_CONTAINER"):
        try:
            Timer(1.5, open_browser).start()
        except Exception:
            print("Could not open browser automatically.")
    uvicorn.run(app, host="0.0.0.0", port=7860)