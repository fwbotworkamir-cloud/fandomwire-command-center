"use client";

import { useState } from "react";

const navItems = [
  { icon: "📊", label: "Dashboard", href: "/", active: true },
  { icon: "📝", label: "Editorial", href: "#editorial", active: false },
  { icon: "🔍", label: "SEO", href: "#seo", active: false },
  { icon: "🔥", label: "Trends", href: "#trends", active: false },
  { icon: "🤝", label: "BD Pipeline", href: "#bd", active: false },
  { icon: "💰", label: "Monetization", href: "#monetization", active: false },
  { icon: "📧", label: "Outreach", href: "#outreach", active: false },
  { icon: "⚙️", label: "Settings", href: "#settings", active: false },
];

export default function Sidebar() {
  const [activeItem, setActiveItem] = useState("Dashboard");
  const [collapsed, setCollapsed] = useState(false);

  return (
    <aside
      className={`fixed left-0 top-0 h-full z-50 flex flex-col transition-all duration-300 ${
        collapsed ? "w-[72px]" : "w-[240px]"
      }`}
      style={{ background: "var(--sidebar-bg)", borderRight: "1px solid var(--card-border)" }}
    >
      {/* Logo */}
      <div className="flex items-center gap-3 px-5 py-5 border-b" style={{ borderColor: "var(--card-border)" }}>
        <div
          className="w-9 h-9 rounded-lg flex items-center justify-center text-white font-bold text-sm flex-shrink-0"
          style={{ background: "var(--accent)" }}
        >
          FW
        </div>
        {!collapsed && (
          <div className="overflow-hidden">
            <p className="text-sm font-semibold text-white truncate">FandomWire</p>
            <p className="text-xs" style={{ color: "var(--muted)" }}>Command Center</p>
          </div>
        )}
      </div>

      {/* Navigation */}
      <nav className="flex-1 py-4 px-3 space-y-1 overflow-y-auto">
        {navItems.map((item) => (
          <button
            key={item.label}
            onClick={() => setActiveItem(item.label)}
            className={`w-full flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm transition-all ${
              activeItem === item.label
                ? "text-white"
                : "hover:text-white"
            }`}
            style={{
              background: activeItem === item.label ? "var(--accent-glow)" : "transparent",
              color: activeItem === item.label ? "white" : "var(--muted)",
              border: activeItem === item.label ? "1px solid rgba(99, 102, 241, 0.3)" : "1px solid transparent",
            }}
          >
            <span className="text-lg flex-shrink-0">{item.icon}</span>
            {!collapsed && <span className="truncate">{item.label}</span>}
          </button>
        ))}
      </nav>

      {/* Collapse toggle */}
      <div className="px-3 py-4 border-t" style={{ borderColor: "var(--card-border)" }}>
        <button
          onClick={() => setCollapsed(!collapsed)}
          className="w-full flex items-center justify-center gap-2 px-3 py-2 rounded-lg text-xs transition-all hover:text-white"
          style={{ color: "var(--muted)", background: "var(--card-bg)" }}
        >
          {collapsed ? "→" : "← Collapse"}
        </button>
      </div>
    </aside>
  );
}
