interface ProgressBarProps {
  label: string;
  count: number;
  total: number;
  color: string;
}

export default function ProgressBar({ label, count, total, color }: ProgressBarProps) {
  const pct = total > 0 ? Math.round((count / total) * 100) : 0;
  return (
    <div className="space-y-1">
      <div className="flex justify-between" style={{ fontSize: "10px" }}>
        <span className="font-label-caps text-label-caps" style={{ color }}>{label}</span>
        <span className="font-label-caps text-label-caps text-on-surface">{count}</span>
      </div>
      <div
        className="w-full h-2 rounded-full overflow-hidden"
        style={{ backgroundColor: "#2e3545" }}
      >
        <div
          className="h-full rounded-full transition-all duration-500"
          style={{ width: `${pct}%`, backgroundColor: color }}
        />
      </div>
    </div>
  );
}
