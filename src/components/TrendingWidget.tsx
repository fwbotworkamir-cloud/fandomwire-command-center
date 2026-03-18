const trends = [
  { topic: "One Piece Live Action S2", category: "Anime", urgency: "Immediate", heat: 95 },
  { topic: "GTA 6 Release Date Leak", category: "Gaming", heat: 92, urgency: "Immediate" },
  { topic: "Marvel Avengers 5 Recast", category: "Marvel", heat: 88, urgency: "Short-term" },
  { topic: "Stranger Things S5 Finale", category: "Streaming", heat: 85, urgency: "Short-term" },
  { topic: "Elden Ring DLC 2 Rumor", category: "Gaming", heat: 78, urgency: "Evergreen" },
];

const urgencyColor: Record<string, string> = {
  Immediate: "var(--danger)",
  "Short-term": "var(--warning)",
  Evergreen: "var(--success)",
};

export default function TrendingWidget() {
  return (
    <div
      className="glow-card rounded-xl p-5"
      style={{ background: "var(--card-bg)", border: "1px solid var(--card-border)" }}
    >
      <div className="flex items-center justify-between mb-4">
        <h3 className="text-sm font-semibold text-white">Trending Now</h3>
        <span className="text-xs px-2 py-1 rounded-full" style={{ background: "var(--accent-glow)", color: "var(--accent)" }}>
          Live
        </span>
      </div>

      <div className="space-y-3">
        {trends.map((t, i) => (
          <div
            key={i}
            className="flex items-center justify-between py-2 px-3 rounded-lg"
            style={{ background: "rgba(255,255,255,0.02)" }}
          >
            <div className="flex-1 min-w-0">
              <p className="text-sm text-white truncate">{t.topic}</p>
              <div className="flex items-center gap-2 mt-0.5">
                <span className="text-xs" style={{ color: "var(--muted)" }}>{t.category}</span>
                <span
                  className="text-xs px-1.5 py-0.5 rounded"
                  style={{ background: urgencyColor[t.urgency] + "20", color: urgencyColor[t.urgency] }}
                >
                  {t.urgency}
                </span>
              </div>
            </div>
            <div className="text-right ml-3">
              <div className="w-10 h-1.5 rounded-full overflow-hidden" style={{ background: "var(--card-border)" }}>
                <div
                  className="h-full rounded-full"
                  style={{ width: `${t.heat}%`, background: "var(--accent)" }}
                />
              </div>
              <span className="text-xs" style={{ color: "var(--muted)" }}>{t.heat}%</span>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
