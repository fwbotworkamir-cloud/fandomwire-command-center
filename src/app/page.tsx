import Sidebar from "@/components/Sidebar";
import Header from "@/components/Header";
import StatCard from "@/components/StatCard";
import TrendingWidget from "@/components/TrendingWidget";
import PipelineWidget from "@/components/PipelineWidget";
import EditorialWidget from "@/components/EditorialWidget";

export default function Home() {
  return (
    <div className="flex min-h-screen" style={{ background: "var(--background)" }}>
      <Sidebar />

      {/* Main content */}
      <div className="flex-1 ml-[240px]">
        <Header />

        <main className="p-8">
          {/* Stats Row */}
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 mb-8">
            <StatCard
              title="Monthly Traffic"
              value="2.4M"
              change="+12.5% vs last month"
              changeType="up"
              icon="📈"
            />
            <StatCard
              title="Avg. Position"
              value="14.2"
              change="-2.1 positions improved"
              changeType="up"
              icon="🎯"
            />
            <StatCard
              title="Active Leads"
              value="52"
              change="+8 new this week"
              changeType="up"
              icon="🤝"
            />
            <StatCard
              title="Revenue (MTD)"
              value="$18.4K"
              change="+23% vs target"
              changeType="up"
              icon="💰"
            />
          </div>

          {/* Main Grid */}
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            {/* Left column - wider */}
            <div className="lg:col-span-2 space-y-6">
              <EditorialWidget />
              <TrendingWidget />
            </div>

            {/* Right column */}
            <div className="space-y-6">
              <PipelineWidget />

              {/* Quick Actions */}
              <div
                className="glow-card rounded-xl p-5"
                style={{ background: "var(--card-bg)", border: "1px solid var(--card-border)" }}
              >
                <h3 className="text-sm font-semibold text-white mb-4">Quick Actions</h3>
                <div className="space-y-2">
                  {[
                    { label: "Scan Trends", icon: "🔥" },
                    { label: "Generate Brief", icon: "📝" },
                    { label: "Find Leads", icon: "🔍" },
                    { label: "Draft Outreach", icon: "📧" },
                  ].map((action, i) => (
                    <button
                      key={i}
                      className="w-full flex items-center gap-3 px-4 py-3 rounded-lg text-sm text-left transition-all hover:scale-[1.01]"
                      style={{
                        background: "rgba(255,255,255,0.03)",
                        border: "1px solid var(--card-border)",
                        color: "var(--foreground)",
                      }}
                    >
                      <span>{action.icon}</span>
                      <span>{action.label}</span>
                    </button>
                  ))}
                </div>
              </div>
            </div>
          </div>
        </main>
      </div>
    </div>
  );
}
