type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO" | "CONFIRMED" | "OPEN" | "FIXED" | "FP";

const config: Record<Severity, { bg: string; text: string; border: string }> = {
  CRITICAL:  { bg: "#93000a",              text: "#ffb4ab", border: "#ffb4ab" },
  HIGH:      { bg: "rgba(223,116,18,0.15)", text: "#ffb786", border: "#df7412" },
  MEDIUM:    { bg: "rgba(76,215,246,0.1)",  text: "#4cd7f6", border: "#03b5d3" },
  LOW:       { bg: "rgba(173,198,255,0.1)", text: "#adc6ff", border: "#adc6ff" },
  INFO:      { bg: "#232a3a",              text: "#c2c6d6", border: "#424754" },
  CONFIRMED: { bg: "rgba(255,180,171,0.1)", text: "#ffb4ab", border: "rgba(255,180,171,0.3)" },
  OPEN:      { bg: "rgba(255,180,171,0.08)",text: "#ffb4ab", border: "transparent" },
  FIXED:     { bg: "rgba(76,215,246,0.1)",  text: "#4cd7f6", border: "transparent" },
  FP:        { bg: "#232a3a",              text: "#8c909f", border: "transparent" },
};

export default function SeverityBadge({ level }: { level: Severity }) {
  const c = config[level] ?? config.INFO;
  return (
    <span
      className="font-label-caps text-label-caps px-2 py-0.5 rounded-full"
      style={{ backgroundColor: c.bg, color: c.text, border: `1px solid ${c.border}` }}
    >
      {level}
    </span>
  );
}
