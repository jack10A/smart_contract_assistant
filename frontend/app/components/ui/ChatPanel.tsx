"use client";
import { useState, useRef, useEffect } from "react";

interface Message {
  id: string;
  role: "user" | "assistant";
  content: string;
  sourceRef?: string;
}

interface ChatPanelProps {
  groundedFile?: string;
  initialMessages?: Message[];
  onSend?: (msg: string) => Promise<string>;
}

const DEFAULT_MSGS: Message[] = [
  {
    id: "1",
    role: "user",
    content: "Explain why the delegatecall in the upgrade function is considered high risk.",
  },
  {
    id: "2",
    role: "assistant",
    content:
      "Based on lines 214-220 of hybrid_vulnerable_test.sol, the _upgradeTo function uses delegatecall to an address that is not restricted to a whitelist or admin-controlled registry.\n\nAn attacker could point the implementation to a malicious contract that overwrites the owner storage slot in the proxy, effectively taking control of the entire protocol. This is a classic \"unprotected self-destruct/delegatecall\" vector.",
    sourceRef: "217: (bool success,) = _newImplementation.delegatecall(\"\");",
  },
];

export default function ChatPanel({
  groundedFile = "hybrid_vulnerable_test.sol",
  initialMessages = DEFAULT_MSGS,
  onSend,
}: ChatPanelProps) {
  const [messages, setMessages] = useState<Message[]>(initialMessages);
  const [input, setInput] = useState("");
  const [loading, setLoading] = useState(false);
  const [collapsed, setCollapsed] = useState(false);
  const bottomRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages]);

  const handleSend = async () => {
    const text = input.trim();
    if (!text) return;
    setInput("");
    const userMsg: Message = { id: Date.now().toString(), role: "user", content: text };
    setMessages((m) => [...m, userMsg]);
    setLoading(true);
    try {
      let reply = "I'm analyzing the contract for your query…";
      if (onSend) reply = await onSend(text);
      const botMsg: Message = { id: (Date.now() + 1).toString(), role: "assistant", content: reply };
      setMessages((m) => [...m, botMsg]);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div
      className="flex flex-col shrink-0 transition-all duration-200"
      style={{
        height: collapsed ? "48px" : "260px",
        backgroundColor: "#191f2f",
        borderTop: "1px solid #424754",
      }}
    >
      {/* Header */}
      <div
        className="flex justify-between items-center px-6 py-2 shrink-0"
        style={{ backgroundColor: "#141b2b", borderBottom: "1px solid #424754", minHeight: "48px" }}
      >
        <div className="flex items-center gap-2">
          <span className="material-symbols-outlined text-sm" style={{ color: "#4cd7f6", fontSize: "18px" }}>smart_toy</span>
          <span className="font-label-caps text-label-caps text-on-surface">Sentinel Assistant</span>
          <span
            className="font-label-caps px-2 py-0.5 rounded"
            style={{ fontSize: "10px", color: "#c2c6d6", backgroundColor: "#2e3545" }}
          >
            GROUNDED: {groundedFile}
          </span>
        </div>
        <div className="flex gap-1">
          <button
            onClick={() => setCollapsed(!collapsed)}
            className="p-1 rounded hover:bg-surface-container-highest text-on-surface-variant"
          >
            <span className="material-symbols-outlined text-sm" style={{ fontSize: "16px" }}>
              {collapsed ? "expand_less" : "expand_more"}
            </span>
          </button>
        </div>
      </div>

      {!collapsed && (
        <>
          {/* Messages */}
          <div className="flex-1 overflow-y-auto p-4 space-y-4">
            {messages.map((msg) => (
              <div
                key={msg.id}
                className={`flex ${msg.role === "user" ? "justify-end" : "justify-start"}`}
              >
                {msg.role === "assistant" && (
                  <div className="flex items-start gap-2 max-w-2xl">
                    <div
                      className="w-6 h-6 rounded flex items-center justify-center shrink-0 mt-1"
                      style={{ backgroundColor: "#03b5d3" }}
                    >
                      <span className="material-symbols-outlined" style={{ fontSize: "12px", color: "#00424e" }}>auto_awesome</span>
                    </div>
                    <div
                      className="px-4 py-2 rounded-xl rounded-tl-none"
                      style={{ backgroundColor: "#2e3545", color: "#dce2f7" }}
                    >
                      <p className="font-body-sm text-body-sm whitespace-pre-wrap">{msg.content}</p>
                      {msg.sourceRef && (
                        <div
                          className="mt-2 p-2 rounded"
                          style={{ backgroundColor: "#191f2f", border: "1px solid #424754" }}
                        >
                          <p className="font-label-caps text-label-caps text-on-surface-variant mb-1" style={{ fontSize: "10px" }}>
                            SOURCE_REFERENCE
                          </p>
                          <p className="font-code-sm text-code-sm truncate" style={{ color: "#4cd7f6" }}>
                            {msg.sourceRef}
                          </p>
                        </div>
                      )}
                    </div>
                  </div>
                )}
                {msg.role === "user" && (
                  <div
                    className="px-4 py-2 rounded-xl rounded-tr-none max-w-lg"
                    style={{ backgroundColor: "#4d8eff", color: "#00285d" }}
                  >
                    <p className="font-body-sm text-body-sm">{msg.content}</p>
                  </div>
                )}
              </div>
            ))}
            {loading && (
              <div className="flex justify-start">
                <div
                  className="px-4 py-2 rounded-xl rounded-tl-none"
                  style={{ backgroundColor: "#2e3545", color: "#c2c6d6" }}
                >
                  <span className="font-body-sm text-body-sm">Analyzing…</span>
                </div>
              </div>
            )}
            <div ref={bottomRef} />
          </div>

          {/* Input */}
          <div className="px-4 pb-3 pt-2 shrink-0" style={{ backgroundColor: "#070e1d" }}>
            <div
              className="flex items-center gap-2 px-3 py-2 rounded"
              style={{ backgroundColor: "#191f2f", border: "1px solid #424754" }}
            >
              <input
                className="flex-1 bg-transparent border-none outline-none font-body-sm text-body-sm text-on-surface placeholder:text-on-surface-variant"
                placeholder="Ask about specific lines or findings…"
                value={input}
                onChange={(e) => setInput(e.target.value)}
                onKeyDown={(e) => e.key === "Enter" && !e.shiftKey && handleSend()}
                disabled={loading}
              />
              <button
                onClick={handleSend}
                disabled={loading || !input.trim()}
                className="p-1.5 rounded active:scale-95 transition-transform disabled:opacity-50"
                style={{ backgroundColor: "#adc6ff", color: "#002e6a" }}
              >
                <span className="material-symbols-outlined" style={{ fontSize: "16px" }}>send</span>
              </button>
            </div>
          </div>
        </>
      )}
    </div>
  );
}
