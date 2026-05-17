"use client";
import { useState, useRef, useEffect, useCallback } from "react";
import { chatWithFile, listFiles } from "../../lib/api";

type Message = {
  role: "user" | "assistant";
  text: string;
  timestamp: string;
};

const fileTypeLabel = (filename: string) => {
  const lower = filename.toLowerCase();
  if (lower.endsWith(".sol")) return "Solidity";
  if (lower.endsWith(".csv")) return "CSV";
  if (lower.endsWith(".json") && lower.includes("abi")) return "ABI";
  if (lower.endsWith(".json")) return "Trace / JSON";
  if (lower.endsWith(".png") || lower.endsWith(".jpg") || lower.endsWith(".jpeg") || lower.endsWith(".webp")) return "Images";
  if (lower.endsWith(".pdf") || lower.endsWith(".doc") || lower.endsWith(".docx") || lower.endsWith(".txt")) return "Documents";
  return "Other";
};

const isGeneratedArtifact = (filename: string) => {
  const lower = filename.toLowerCase();
  return lower === "audit_history.json" || lower.includes("_anomaly_report") || lower.includes("_fixed") || lower.endsWith(".sol.txt");
};

const groupOrder = ["Solidity", "CSV", "Trace / JSON", "ABI", "Images", "Documents", "Other"];

export default function ChatPage() {
  const [messages, setMessages] = useState<Message[]>([]);
  const [input, setInput] = useState("");
  const [loading, setLoading] = useState(false);
  const [fileList, setFileList] = useState<string[]>([]);
  const [filesLoaded, setFilesLoaded] = useState(false);
  const [selectedFiles, setSelectedFiles] = useState<string[]>([]);
  const [fileQuery, setFileQuery] = useState("");
  const [showGenerated, setShowGenerated] = useState(false);
  const bottomRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages]);

  const loadFiles = useCallback(async (force = false) => {
    if (filesLoaded && !force) return;
    try {
      const { files } = await listFiles();
      setFileList(files);
      setFilesLoaded(true);
    } catch {
      setFileList([]);
      setFilesLoaded(true);
    }
  }, [filesLoaded]);

  useEffect(() => {
    const timer = window.setTimeout(() => {
      void loadFiles();
    }, 0);
    return () => window.clearTimeout(timer);
  }, [loadFiles]);

  const visibleFiles = fileList.filter((file) => {
    if (!showGenerated && isGeneratedArtifact(file)) return false;
    return file.toLowerCase().includes(fileQuery.trim().toLowerCase());
  });

  const groupedFiles = groupOrder
    .map((group) => ({ group, files: visibleFiles.filter((file) => fileTypeLabel(file) === group) }))
    .filter((item) => item.files.length > 0);

  const toggleFile = (file: string) => {
    setSelectedFiles((current) => current.includes(file) ? current.filter((item) => item !== file) : [...current, file]);
  };

  const send = async () => {
    const text = input.trim();
    if (!text) return;

    const now = new Date().toLocaleTimeString("en-US", { hour: "2-digit", minute: "2-digit", hour12: false });
    setMessages((prev) => [...prev, { role: "user", text, timestamp: now }]);
    setInput("");
    setLoading(true);

    const history = messages.map((message) => ({
      role: message.role === "user" ? "human" : "assistant",
      content: message.text,
    }));

    try {
      const data = await chatWithFile(text, selectedFiles, history);
      setMessages((prev) => [
        ...prev,
        {
          role: "assistant",
          text: data.answer,
          timestamp: new Date().toLocaleTimeString("en-US", { hour: "2-digit", minute: "2-digit", hour12: false }),
        },
      ]);
    } catch (error) {
      setMessages((prev) => [
        ...prev,
        {
          role: "assistant",
          text: error instanceof Error ? error.message : "Could not reach the backend at localhost:7860.",
          timestamp: new Date().toLocaleTimeString("en-US", { hour: "2-digit", minute: "2-digit", hour12: false }),
        },
      ]);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="flex flex-col h-full">
      <div className="flex items-center justify-between px-6 py-4 shrink-0 gap-4 flex-wrap" style={{ backgroundColor: "#141b2b", borderBottom: "1px solid #424754" }}>
        <div>
          <h1 className="font-headline-sm text-headline-sm text-on-surface">Source-Grounded Chat</h1>
          <p className="font-body-sm text-body-sm text-on-surface-variant mt-0.5">RAG answers grounded in selected workspace files or the full indexed workspace</p>
        </div>
      </div>

      <div className="px-6 py-3 shrink-0 space-y-3" style={{ backgroundColor: "#101827", borderBottom: "1px solid #424754" }}>
        <div className="flex items-center justify-between gap-3 flex-wrap">
          <div>
            <p className="font-label-caps text-label-caps text-on-surface-variant">
              RAG FILE CONTEXT {selectedFiles.length > 0 ? `(${selectedFiles.length} selected)` : "(all indexed files)"}
            </p>
            <p className="font-body-sm text-body-sm text-on-surface-variant mt-1">Select files to focus retrieval, or leave empty to search the whole indexed workspace.</p>
          </div>
          <div className="flex items-center gap-2 flex-wrap">
            <input
              value={fileQuery}
              onChange={(event) => setFileQuery(event.target.value)}
              placeholder="Search files"
              className="rounded px-3 py-2 font-code-sm text-on-surface outline-none"
              style={{ backgroundColor: "#191f2f", border: "1px solid #424754", minWidth: "180px", fontSize: "12px" }}
            />
            <button
              onClick={() => setShowGenerated((value) => !value)}
              className="font-label-caps px-3 py-2 rounded transition-colors"
              style={{ fontSize: "10px", border: "1px solid #424754", color: showGenerated ? "#adc6ff" : "#8c909f", backgroundColor: showGenerated ? "rgba(173,198,255,0.12)" : "#191f2f" }}
            >
              {showGenerated ? "HIDE GENERATED" : "SHOW GENERATED"}
            </button>
            <button
              onClick={() => void loadFiles(true)}
              className="font-label-caps px-3 py-2 rounded transition-colors"
              style={{ fontSize: "10px", color: "#4cd7f6", border: "1px solid #424754" }}
            >
              REFRESH FILES
            </button>
            {selectedFiles.length > 0 && (
              <button
                onClick={() => setSelectedFiles([])}
                className="font-label-caps px-3 py-2 rounded transition-colors"
                style={{ fontSize: "10px", color: "#ffb786", border: "1px solid #424754" }}
              >
                CLEAR
              </button>
            )}
          </div>
        </div>

        {!filesLoaded ? (
          <p className="font-body-sm text-body-sm text-on-surface-variant">Loading workspace files...</p>
        ) : groupedFiles.length === 0 ? (
          <p className="font-body-sm text-body-sm text-on-surface-variant">No files match the current search and filter.</p>
        ) : (
          <div className="space-y-3 max-h-44 overflow-auto pr-1">
            {groupedFiles.map(({ group, files }) => (
              <div key={group}>
                <div className="flex items-center gap-2 mb-2">
                  <span className="font-label-caps" style={{ fontSize: "10px", color: "#adc6ff" }}>{group}</span>
                  <span className="font-label-caps text-on-surface-variant" style={{ fontSize: "9px" }}>{files.length}</span>
                </div>
                <div className="flex flex-wrap gap-2">
                  {files.map((file) => {
                    const selected = selectedFiles.includes(file);
                    const generated = isGeneratedArtifact(file);
                    return (
                      <button
                        key={file}
                        onClick={() => toggleFile(file)}
                        className="font-code-sm px-3 py-1 rounded transition-colors"
                        style={{
                          backgroundColor: selected ? "rgba(173,198,255,0.15)" : "#191f2f",
                          border: selected ? "1px solid rgba(173,198,255,0.4)" : "1px solid #424754",
                          color: selected ? "#adc6ff" : generated ? "#6f7482" : "#c2c6d6",
                          fontSize: "11px",
                        }}
                      >
                        {file}
                      </button>
                    );
                  })}
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      <div className="flex-1 overflow-y-auto px-6 py-4 space-y-4">
        {messages.length === 0 && (
          <div className="flex flex-col items-center gap-3 py-16 text-center">
            <span className="material-symbols-outlined" style={{ fontSize: "48px", color: "#2e3545" }}>smart_toy</span>
            <p className="font-body-sm text-on-surface-variant max-w-md">
              Ask anything about your workspace evidence. Select DAO story files to focus the answer, or leave all files unselected for broad workspace retrieval.
            </p>
          </div>
        )}

        {messages.map((message, index) => (
          <div key={index} className={`flex ${message.role === "user" ? "justify-end" : "justify-start"}`}>
            {message.role === "assistant" && (
              <div className="w-8 h-8 rounded-full flex items-center justify-center shrink-0 mr-3 mt-0.5" style={{ backgroundColor: "rgba(173,198,255,0.15)", border: "1px solid rgba(173,198,255,0.3)" }}>
                <span className="material-symbols-outlined" style={{ fontSize: "16px", color: "#adc6ff" }}>smart_toy</span>
              </div>
            )}
            <div className="max-w-2xl rounded-lg px-4 py-3" style={{ backgroundColor: message.role === "user" ? "rgba(173,198,255,0.12)" : "#1a2235", border: message.role === "user" ? "1px solid rgba(173,198,255,0.25)" : "1px solid #2e3545" }}>
              <p className="font-body-sm text-body-sm whitespace-pre-wrap" style={{ color: message.role === "user" ? "#dce2f7" : "#c2c6d6", lineHeight: "1.6" }}>{message.text}</p>
              <p className="font-label-caps mt-2" style={{ fontSize: "9px", color: "#424754" }}>{message.timestamp}</p>
            </div>
            {message.role === "user" && (
              <div className="w-8 h-8 rounded-full flex items-center justify-center shrink-0 ml-3 mt-0.5" style={{ backgroundColor: "#232a3a", border: "1px solid #424754" }}>
                <span className="font-bold" style={{ fontSize: "12px", color: "#adc6ff" }}>U</span>
              </div>
            )}
          </div>
        ))}

        {loading && (
          <div className="flex justify-start">
            <div className="w-8 h-8 rounded-full flex items-center justify-center shrink-0 mr-3" style={{ backgroundColor: "rgba(173,198,255,0.15)", border: "1px solid rgba(173,198,255,0.3)" }}>
              <span className="material-symbols-outlined" style={{ fontSize: "16px", color: "#adc6ff" }}>smart_toy</span>
            </div>
            <div className="px-4 py-3 rounded-lg" style={{ backgroundColor: "#1a2235", border: "1px solid #2e3545" }}>
              <div className="flex gap-1.5 items-center h-5">
                {[0, 1, 2].map((index) => <div key={index} className="w-2 h-2 rounded-full animate-bounce" style={{ backgroundColor: "#4cd7f6", animationDelay: `${index * 150}ms` }} />)}
              </div>
            </div>
          </div>
        )}
        <div ref={bottomRef} />
      </div>

      <div className="px-6 py-4 shrink-0" style={{ backgroundColor: "#141b2b", borderTop: "1px solid #424754" }}>
        <div className="flex items-end gap-3 rounded-lg p-3" style={{ backgroundColor: "#191f2f", border: "1px solid #424754" }}>
          <textarea
            value={input}
            onChange={(event) => setInput(event.target.value)}
            onKeyDown={(event) => {
              if (event.key === "Enter" && !event.shiftKey) {
                event.preventDefault();
                void send();
              }
            }}
            placeholder={selectedFiles.length > 0 ? `Ask about ${selectedFiles.length} selected file${selectedFiles.length === 1 ? "" : "s"}...` : "Ask about vulnerabilities, transactions, or attack paths..."}
            rows={2}
            className="flex-1 bg-transparent resize-none outline-none font-body-sm text-body-sm text-on-surface placeholder:text-on-surface-variant"
            style={{ lineHeight: "1.5" }}
          />
          <button
            onClick={() => void send()}
            disabled={!input.trim() || loading}
            className="w-8 h-8 rounded flex items-center justify-center transition-all active:scale-95"
            style={{ backgroundColor: input.trim() && !loading ? "#adc6ff" : "#2e3545", color: input.trim() && !loading ? "#002e6a" : "#424754" }}
          >
            <span className="material-symbols-outlined" style={{ fontSize: "16px" }}>send</span>
          </button>
        </div>
        <p className="font-label-caps text-on-surface-variant mt-2" style={{ fontSize: "9px" }}>
          Enter to send - Shift+Enter for newline
          {selectedFiles.length > 0 && ` - Grounded in ${selectedFiles.join(", ")}`}
        </p>
      </div>
    </div>
  );
}
