interface StatCardProps {
  title: string;
  value: string;
  change: string;
  changeType: "up" | "down" | "neutral";
  icon: string;
}

export default function StatCard({ title, value, change, changeType, icon }: StatCardProps) {
  const changeColor =
    changeType === "up"
      ? "var(--success)"
      : changeType === "down"
      ? "var(--danger)"
      : "var(--muted)";

  const changeArrow = changeType === "up" ? "↑" : changeType === "down" ? "↓" : "→";

  return (
    <div
      className="glow-card rounded-xl p-5"
      style={{
        background: "var(--card-bg)",
        border: "1px solid var(--card-border)",
      }}
    >
      <div className="flex items-center justify-between mb-3">
        <span className="text-xs font-medium uppercase tracking-wider" style={{ color: "var(--muted)" }}>
          {title}
        </span>
        <span className="text-xl">{icon}</span>
      </div>
      <p className="text-2xl font-bold text-white">{value}</p>
      <p className="text-xs mt-1 flex items-center gap-1" style={{ color: changeColor }}>
        {changeArrow} {change}
      </p>
    </div>
  );
}
