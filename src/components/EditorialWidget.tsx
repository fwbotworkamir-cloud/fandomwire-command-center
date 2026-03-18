const articles = [
  { title: "One Piece S2: Everything We Know", action: "Write", priority: "High", category: "Anime" },
  { title: "GTA 6 Map Size Comparison", action: "Write", priority: "High", category: "Gaming" },
  { title: "Marvel Phase 7 Complete Timeline", action: "Update", priority: "Medium", category: "Marvel" },
  { title: "Best Anime of 2026 So Far", action: "Write", priority: "Medium", category: "Anime" },
  { title: "PS5 Pro vs Xbox Series X (2026)", action: "Update", priority: "Low", category: "Gaming" },
];

const priorityColor: Record<string, string> = {
  High: "var(--danger)",
  Medium: "var(--warning)",
  Low: "var(--muted)",
};

const actionStyle: Record<string, { bg: string; color: string }> = {
  Write: { bg: "rgba(99, 102, 241, 0.15)", color: "var(--accent)" },
  Update: { bg: "rgba(245, 158, 11, 0.15)", color: "var(--warning)" },
};

export default function EditorialWidget() {
  return (
    <div
      className="glow-card rounded-xl p-5"
      style={{ background: "var(--card-bg)", border: "1px solid var(--card-border)" }}
    >
      <div className="flex items-center justify-between mb-4">
        <h3 className="text-sm font-semibold text-white">Editorial Queue</h3>
        <span className="text-xs" style={{ color: "var(--muted)" }}>Today</span>
      </div>

      <div className="space-y-2.5">
        {articles.map((a, i) => (
          <div
            key={i}
            className="flex items-center justify-between py-2.5 px-3 rounded-lg"
            style={{ background: "rgba(255,255,255,0.02)" }}
          >
            <div className="flex-1 min-w-0 mr-3">
              <p className="text-sm text-white truncate">{a.title}</p>
              <div className="flex items-center gap-2 mt-0.5">
                <span className="text-xs" style={{ color: "var(--muted)" }}>{a.category}</span>
                <span className="w-1.5 h-1.5 rounded-full" style={{ background: priorityColor[a.priority] }} />
                <span className="text-xs" style={{ color: priorityColor[a.priority] }}>{a.priority}</span>
              </div>
            </div>
            <span
              className="text-xs px-2 py-1 rounded flex-shrink-0"
              style={{ background: actionStyle[a.action].bg, color: actionStyle[a.action].color }}
            >
              {a.action}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}
