"use client";

interface RiskGaugeProps {
  score: number;
  label?: string;
  size?: number;
}

function getColor(score: number) {
  if (score >= 80) return "#ffb4ab";
  if (score >= 60) return "#ffb786";
  if (score >= 40) return "#4cd7f6";
  return "#adc6ff";
}

export default function RiskGauge({ score, label, size = 192 }: RiskGaugeProps) {
  const color = getColor(score);
  const pct = Math.min(100, Math.max(0, score));

  return (
    <div className="flex flex-col items-center">
      <div
        className="relative flex items-center justify-center"
        style={{ width: size, height: size }}
      >
        {/* Conic gauge */}
        <div
          style={{
            position: "absolute",
            inset: 0,
            borderRadius: "50%",
            background: `conic-gradient(from -90deg, ${color} 0% ${pct}%, #2e3545 ${pct}% 100%)`,
            WebkitMask: "radial-gradient(transparent 57%, black 58%)",
            mask: "radial-gradient(transparent 57%, black 58%)",
          }}
        />
        {/* Inner circle */}
        <div
          className="absolute inset-0 flex flex-col items-center justify-center"
          style={{
            inset: "10%",
            borderRadius: "50%",
            backgroundColor: "#232a3a",
            display: "flex",
            flexDirection: "column",
            alignItems: "center",
            justifyContent: "center",
          }}
        >
          <span
            className="font-display-lg"
            style={{ fontSize: size * 0.25, lineHeight: 1, color: "#dce2f7", fontWeight: 700 }}
          >
            {score}
          </span>
          {label && (
            <span className="font-label-caps text-label-caps mt-1" style={{ color }}>
              {label}
            </span>
          )}
        </div>
      </div>
    </div>
  );
}
