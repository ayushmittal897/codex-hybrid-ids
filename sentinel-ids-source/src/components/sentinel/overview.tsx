import { useMemo, useState } from "react";
import { Link } from "@tanstack/react-router";
import {
  Activity,
  ArrowDownLeft,
  ArrowUpRight,
  ChevronRight,
  Download,
  Ellipsis,
  Network,
  ShieldAlert,
  ShieldCheck,
  Zap,
} from "lucide-react";
import {
  Area,
  AreaChart,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
  PieChart,
  Pie,
  Cell,
} from "recharts";
import { Button } from "@/components/ui/button";
import { downloadCsv } from "@/lib/sentinel";
import { useWorkspace, PageTitle, MonitorButton } from "./workspace";
import { FlowTable } from "./traffic";

const CHART_PALETTE = [
  "var(--chart-1)",
  "var(--chart-2)",
  "var(--chart-3)",
  "var(--chart-4)",
  "var(--chart-5)",
  "var(--warning)",
  "var(--destructive)",
  "oklch(0.7 0.16 310)",
  "oklch(0.75 0.15 140)",
];

export function Overview() {
  const { flows, running, source } = useWorkspace();
  const [range, setRange] = useState("Last 1 hour");
  const threats = flows.filter((f) => f.attack !== "Benign");
  const critical = threats.filter((f) => f.severity === "Critical");

  // Dynamic time-series data calculated from loaded flows
  const chart = useMemo(() => {
    const bucketsCount = range === "Last 15 minutes" ? 8 : 12;
    if (!flows.length) {
      return Array.from({ length: bucketsCount }, (_, i) => ({
        time: `${(i + 1) * 5}m`,
        benign: 0,
        threats: 0,
      }));
    }
    const chunkSize = Math.max(1, Math.floor(flows.length / bucketsCount));
    const data = [];
    for (let i = 0; i < bucketsCount; i++) {
      const slice = flows.slice(i * chunkSize, (i + 1) * chunkSize);
      const bCount = slice.filter((f) => f.attack === "Benign").length;
      const tCount = slice.filter((f) => f.attack !== "Benign").length;
      const timeStr = slice[0]?.time
        ? new Date(slice[0].time).toLocaleTimeString("en-GB", { hour: "2-digit", minute: "2-digit", hour12: false })
        : `${(i + 1) * 5}m`;
      data.push({
        time: timeStr,
        benign: Math.max(bCount * 12, 10),
        threats: tCount * 12,
      });
    }
    return data;
  }, [flows, range]);

  // Dynamic threat distribution: covers any attack class present
  const distribution = useMemo(() => {
    const counts: Record<string, number> = {};
    for (const f of threats) {
      counts[f.attack] = (counts[f.attack] || 0) + 1;
    }
    return Object.entries(counts)
      .sort((a, b) => b[1] - a[1])
      .map(([name, value], i) => ({
        name,
        value,
        fill: CHART_PALETTE[i % CHART_PALETTE.length],
      }));
  }, [threats]);

  const total = distribution.reduce((a, d) => a + d.value, 0);
  return (
    <>
      <PageTitle
        title="Security overview"
        description="A unified view of your network activity and threat landscape."
        actions={
          <>
            <Button
              variant="outline"
              onClick={() => downloadCsv(flows, "sentinel-security-report.csv")}
            >
              <Download />
              Export report
            </Button>
            <MonitorButton />
          </>
        }
      />
      <div className="monitor-strip">
        <div>
          <span className={`status-dot ${!running ? "paused" : ""}`} />
          <strong>{running ? "Monitoring active" : "Monitoring paused"}</strong>
          <span className="strip-divider" />
          <Network size={14} />
          <span>{source === "Demo simulation" ? "Demo interface" : source}</span>
          <span className="demo-tag">
            {source === "Demo simulation" ? "SIMULATED DATA" : "CSV ANALYSIS"}
          </span>
        </div>
        <span className="update-caption">
          {running ? "Refreshes every 5 seconds" : "Updates paused"}
        </span>
      </div>
      <div className="metric-grid">
        {[
          {
            label: "Total flows analyzed",
            value: flows.length.toLocaleString(),
            icon: Network,
            change: "Current session",
            sub: "All observed network flows",
            tone: "mint",
          },
          {
            label: "Threats detected",
            value: threats.length,
            icon: ShieldAlert,
            change: `${Math.round((threats.length / flows.length) * 100) || 0}% of total flows`,
            sub: "Flagged by the detection engine",
            tone: "amber",
          },
          {
            label: "Critical alerts",
            value: critical.length,
            icon: Zap,
            change: `${critical.filter((f) => !f.acknowledged).length} require attention`,
            sub: "Highest-priority detections",
            tone: "red",
          },
          {
            label: "Detection engines",
            value: source.includes("ML") || source.includes("Hybrid") ? "Hybrid" : "Hybrid active",
            icon: ShieldCheck,
            change: "Rules + ML Active",
            sub: "Random Forest & Rule Engine connected",
            tone: "mint",
          },
        ].map((m) => (
          <div className="metric-card" key={m.label}>
            <div className="metric-label">
              {m.label}
              <span className={`metric-icon ${m.tone}`}>
                <m.icon size={18} />
              </span>
            </div>
            <div className="metric-value">{m.value}</div>
            <div className={`metric-change ${m.tone}`}>
              {m.tone === "red" ? <ArrowUpRight size={13} /> : <Activity size={13} />} {m.change}
            </div>
            <small>{m.sub}</small>
          </div>
        ))}
      </div>
      <div className="chart-grid">
        <section className="chart-panel traffic-chart">
          <div className="panel-heading">
            <div>
              <h2>Network traffic</h2>
              <p>
                Flow activity over time <span className="demo-inline">· Illustrative sample</span>
              </p>
            </div>
            <select
              aria-label="Traffic chart time range"
              value={range}
              onChange={(e) => setRange(e.target.value)}
            >
              <option>Last 1 hour</option>
              <option>Last 15 minutes</option>
            </select>
          </div>
          <div className="chart-legend">
            <span>
              <i className="legend-mint" />
              Benign traffic
            </span>
            <span>
              <i className="legend-red" />
              Threat traffic
            </span>
            <span className="legend-unit">Flows / min</span>
          </div>
          <div className="area-chart">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={chart} margin={{ top: 10, right: 8, left: -22, bottom: 0 }}>
                <defs>
                  <linearGradient id="mint-fill" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor="var(--primary)" stopOpacity={0.27} />
                    <stop offset="100%" stopColor="var(--primary)" stopOpacity={0.01} />
                  </linearGradient>
                </defs>
                <CartesianGrid stroke="var(--border)" strokeDasharray="3 4" vertical={false} />
                <XAxis
                  dataKey="time"
                  tick={{ fill: "var(--muted-foreground)", fontSize: 11 }}
                  tickLine={false}
                  axisLine={false}
                  minTickGap={55}
                />
                <YAxis
                  tick={{ fill: "var(--muted-foreground)", fontSize: 11 }}
                  tickLine={false}
                  axisLine={false}
                  domain={[0, 500]}
                />
                <Tooltip
                  contentStyle={{
                    background: "var(--popover)",
                    borderColor: "var(--border)",
                    borderRadius: 6,
                    color: "var(--foreground)",
                  }}
                />
                <Area
                  isAnimationActive={false}
                  type="monotone"
                  dataKey="benign"
                  stroke="var(--primary)"
                  strokeWidth={2}
                  fill="url(#mint-fill)"
                />
                <Area
                  isAnimationActive={false}
                  type="monotone"
                  dataKey="threats"
                  stroke="var(--destructive)"
                  fill="var(--destructive)"
                  fillOpacity={0.04}
                  strokeWidth={1.8}
                />
              </AreaChart>
            </ResponsiveContainer>
          </div>
          <div className="chart-bottom">
            <span>
              <span className="status-dot" />
              Demo sensor stream
            </span>
            <span>5-second refresh interval</span>
          </div>
        </section>
        <section className="chart-panel threat-chart">
          <div className="panel-heading">
            <div>
              <h2>Threat distribution</h2>
              <p>Detected attack categories</p>
            </div>
            <ShieldAlert size={17} className="text-muted-foreground" />
          </div>
          <div className="donut-wrap">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  isAnimationActive={false}
                  data={distribution}
                  dataKey="value"
                  innerRadius={66}
                  outerRadius={85}
                  paddingAngle={4}
                  stroke="none"
                >
                  {distribution.map((d) => (
                    <Cell fill={d.fill} key={d.name} />
                  ))}
                </Pie>
                <Tooltip
                  contentStyle={{
                    background: "var(--popover)",
                    borderColor: "var(--border)",
                    color: "var(--foreground)",
                  }}
                />
              </PieChart>
            </ResponsiveContainer>
            <div className="donut-center">
              <strong>{threats.length}</strong>
              <small>Total threats</small>
            </div>
          </div>
          <div className="distribution-list">
            {distribution.map((d) => (
              <div key={d.name}>
                <span>
                  <i className={`category-dot ${d.name.toLowerCase().replaceAll(" ", "-")}`} />
                  {d.name}
                </span>
                <strong>
                  {d.value}
                  <small>{Math.round((d.value / (total || 1)) * 100)}%</small>
                </strong>
              </div>
            ))}
          </div>
        </section>
      </div>
      <section className="recent-section">
        <div className="panel-heading">
          <div>
            <h2>
              Recent threat alerts{" "}
              <span className="heading-count">
                {threats.filter((f) => !f.acknowledged).length} open
              </span>
            </h2>
            <p>Latest suspicious activity across your network</p>
          </div>
          <Button variant="ghost" asChild>
            <Link to="/alerts">
              View all alerts
              <ArrowUpRight />
            </Link>
          </Button>
        </div>
        <FlowTable flows={threats.slice(0, 5)} compact />
      </section>
      <div className="engine-band">
        <span className="engine-badge">
          <ShieldCheck size={22} />
        </span>
        <div>
          <strong>Two perspectives. One security posture.</strong>
          <p>Behavioral rules and model predictions form the hybrid detection pipeline.</p>
        </div>
        <div className="engine-status">
          <span>
            <span className="status-dot" />
            Rule engine active
          </span>
          <span>
            <span className="status-dot" />
            ML model connected
          </span>
        </div>
        <Button variant="ghost" asChild>
          <Link to="/models" aria-label="View detection engines">
            <ChevronRight />
          </Link>
        </Button>
      </div>
    </>
  );
}
