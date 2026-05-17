"use client";
import { createContext, useContext, useEffect, useState, type ReactNode } from "react";
import type {
  AuditResult,
  FixResult,
  CSVAnomalyResult,
  TraceResult,
  ImageSecurityResult,
  InvestigateResult,
} from "../lib/api";

type SessionState = {
  selectedFile: string;
  auditResult: AuditResult | null;
  fixResult: FixResult | null;
  csvFile: string;
  csvResult: CSVAnomalyResult | null;
  traceFile: string;
  traceResult: TraceResult | null;
  imageFile: string;
  imageResult: ImageSecurityResult | null;
  investigateResult: InvestigateResult | null;
};

const STORAGE_KEY = "chainsentinel.session.v1";

const emptySessionState: SessionState = {
  selectedFile: "",
  auditResult: null,
  fixResult: null,
  csvFile: "",
  csvResult: null,
  traceFile: "",
  traceResult: null,
  imageFile: "",
  imageResult: null,
  investigateResult: null,
};

function readStoredSession(): SessionState {
  if (typeof window === "undefined") return emptySessionState;

  try {
    const raw = window.localStorage.getItem(STORAGE_KEY);
    if (!raw) return emptySessionState;
    const parsed = JSON.parse(raw) as Partial<SessionState>;
    return {
      ...emptySessionState,
      selectedFile: typeof parsed.selectedFile === "string" ? parsed.selectedFile : "",
      auditResult: parsed.auditResult ?? null,
      fixResult: parsed.fixResult ?? null,
      csvFile: typeof parsed.csvFile === "string" ? parsed.csvFile : "",
      csvResult: parsed.csvResult ?? null,
      traceFile: typeof parsed.traceFile === "string" ? parsed.traceFile : "",
      traceResult: parsed.traceResult ?? null,
      imageFile: typeof parsed.imageFile === "string" ? parsed.imageFile : "",
      imageResult: parsed.imageResult ?? null,
      investigateResult: parsed.investigateResult ?? null,
    };
  } catch {
    return emptySessionState;
  }
}

type SessionCtx = SessionState & {
  setSelectedFile:      (f: string) => void;
  setAuditResult:       (r: AuditResult | null) => void;
  setFixResult:         (r: FixResult | null) => void;
  setCSVResult:         (file: string, r: CSVAnomalyResult | null) => void;
  setTraceResult:       (file: string, r: TraceResult | null) => void;
  setImageResult:       (file: string, r: ImageSecurityResult | null) => void;
  setInvestigateResult: (r: InvestigateResult | null) => void;
};

const SessionContext = createContext<SessionCtx | null>(null);

export function SessionProvider({ children }: { children: ReactNode }) {
  const [state, setState] = useState<SessionState>(emptySessionState);
  const [storageReady, setStorageReady] = useState(false);

  useEffect(() => {
    const timer = window.setTimeout(() => {
      setState(readStoredSession());
      setStorageReady(true);
    }, 0);
    return () => window.clearTimeout(timer);
  }, []);

  useEffect(() => {
    if (!storageReady) return;
    try {
      window.localStorage.setItem(STORAGE_KEY, JSON.stringify(state));
    } catch {
      // Ignore quota/private-mode failures; the in-memory session still works.
    }
  }, [state, storageReady]);

  const ctx: SessionCtx = {
    ...state,
    setSelectedFile:      (f)      => setState((s) => ({ ...s, selectedFile: f })),
    setAuditResult:       (r)      => setState((s) => ({ ...s, auditResult: r })),
    setFixResult:         (r)      => setState((s) => ({ ...s, fixResult: r })),
    setCSVResult:         (f, r)   => setState((s) => ({ ...s, csvFile: f, csvResult: r })),
    setTraceResult:       (f, r)   => setState((s) => ({ ...s, traceFile: f, traceResult: r })),
    setImageResult:       (f, r)   => setState((s) => ({ ...s, imageFile: f, imageResult: r })),
    setInvestigateResult: (r)      => setState((s) => ({ ...s, investigateResult: r })),
  };

  return <SessionContext.Provider value={ctx}>{children}</SessionContext.Provider>;
}

export function useSession() {
  const ctx = useContext(SessionContext);
  if (!ctx) throw new Error("useSession must be used inside SessionProvider");
  return ctx;
}
