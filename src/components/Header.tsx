"use client";

export default function Header() {
  const now = new Date();
  const dateStr = now.toLocaleDateString("en-US", {
    weekday: "long",
    year: "numeric",
    month: "long",
    day: "numeric",
  });

  return (
    <header
      className="flex items-center justify-between px-8 py-4 border-b"
      style={{ borderColor: "var(--card-border)", background: "var(--sidebar-bg)" }}
    >
      <div>
        <h1 className="text-xl font-semibold text-white">Command Center</h1>
        <p className="text-xs mt-0.5" style={{ color: "var(--muted)" }}>
          {dateStr}
        </p>
      </div>

      <div className="flex items-center gap-4">
        {/* Live status */}
        <div className="flex items-center gap-2 px-3 py-1.5 rounded-full text-xs" style={{ background: "var(--card-bg)", border: "1px solid var(--card-border)" }}>
          <span className="w-2 h-2 rounded-full pulse-dot" style={{ background: "var(--success)" }} />
          <span style={{ color: "var(--success)" }}>All Systems Live</span>
        </div>

        {/* User */}
        <div className="flex items-center gap-2">
          <div
            className="w-8 h-8 rounded-full flex items-center justify-center text-white text-xs font-semibold"
            style={{ background: "var(--accent)" }}
          >
            A
          </div>
          <span className="text-sm text-white">Amir</span>
        </div>
      </div>
    </header>
  );
}
