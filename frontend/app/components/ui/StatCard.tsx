interface StatCardProps {
  label: string;
  value: string;
  sub?: string;
  valueColor?: string;
}

export default function StatCard({ label, value, sub, valueColor = "#dce2f7" }: StatCardProps) {
  return (
    <div
      className="p-4 rounded-lg"
      style={{ backgroundColor: "#191f2f", border: "1px solid #424754" }}
    >
      <p className="font-label-caps text-label-caps text-on-surface-variant mb-1">{label}</p>
      <p className="font-headline-sm text-headline-sm" style={{ color: valueColor }}>
        {value}
      </p>
      {sub && (
        <p className="font-body-sm text-body-sm text-on-surface-variant mt-1">{sub}</p>
      )}
    </div>
  );
}
