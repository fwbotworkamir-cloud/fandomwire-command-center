const pipelineStages = [
  { stage: "New Leads", count: 24, color: "var(--accent)" },
  { stage: "Contacted", count: 18, color: "var(--warning)" },
  { stage: "In Discussion", count: 7, color: "var(--success)" },
  { stage: "Deal Closed", count: 3, color: "#10b981" },
];

const recentLeads = [
  { company: "Sony Pictures", status: "Email Sent", date: "2d ago" },
  { company: "Crunchyroll", status: "Call Booked", date: "1d ago" },
  { company: "Xbox Game Studios", status: "Proposal Sent", date: "3d ago" },
  { company: "A24 Films", status: "New Lead", date: "Today" },
];

const statusColor: Record<string, string> = {
  "Email Sent": "var(--warning)",
  "Call Booked": "var(--success)",
  "Proposal Sent": "var(--accent)",
  "New Lead": "var(--muted)",
};

export default function PipelineWidget() {
  return (
    <div
      className="glow-card rounded-xl p-5"
      style={{ background: "var(--card-bg)", border: "1px solid var(--card-border)" }}
    >
      <div className="flex items-center justify-between mb-4">
        <h3 className="text-sm font-semibold text-white">BD Pipeline</h3>
        <span className="text-xs" style={{ color: "var(--muted)" }}>This Month</span>
      </div>

      {/* Funnel bars */}
      <div className="space-y-2 mb-5">
        {pipelineStages.map((s, i) => (
          <div key={i} className="flex items-center gap-3">
            <span className="text-xs w-24 truncate" style={{ color: "var(--muted)" }}>{s.stage}</span>
            <div className="flex-1 h-2 rounded-full overflow-hidden" style={{ background: "var(--card-border)" }}>
              <div
                className="h-full rounded-full transition-all"
                style={{ width: `${(s.count / 24) * 100}%`, background: s.color }}
              />
            </div>
            <span className="text-xs font-medium text-white w-6 text-right">{s.count}</span>
          </div>
        ))}
      </div>

      {/* Recent leads */}
      <div className="border-t pt-3" style={{ borderColor: "var(--card-border)" }}>
        <p className="text-xs font-medium mb-2" style={{ color: "var(--muted)" }}>Recent Activity</p>
        <div className="space-y-2">
          {recentLeads.map((l, i) => (
            <div key={i} className="flex items-center justify-between">
              <div>
                <p className="text-sm text-white">{l.company}</p>
                <span
                  className="text-xs"
                  style={{ color: statusColor[l.status] }}
                >
                  {l.status}
                </span>
              </div>
              <span className="text-xs" style={{ color: "var(--muted)" }}>{l.date}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
