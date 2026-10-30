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
import { useWorkspace, PageTitle } from "./workspace";
import { FlowTable } from "./traffic";
export function Overview() {
  const { flows, source } = useWorkspace();
  const threats = flows.filter((f) => f.attack !== "Benign");
  const critical = threats.filter((f) => f.severity === "Critical");
  const chart = Array.from(
    flows.reduce((buckets, flow) => {
      const time = new Date(flow.time).toLocaleTimeString([], {
        hour: "2-digit",
        minute: "2-digit",
      });
      const bucket = buckets.get(time) ?? { time, benign: 0, threats: 0 };
      if (flow.attack === "Benign") bucket.benign += 1;
      else bucket.threats += 1;
      buckets.set(time, bucket);
      return buckets;
    }, new Map<string, { time: string; benign: number; threats: number }>()),
  )
    .map(([, bucket]) => bucket)
    .slice(-30);
  const distribution = Array.from(
    threats.reduce((categories, flow) => {
      categories.set(flow.attack, (categories.get(flow.attack) ?? 0) + 1);
      return categories;
    }, new Map<string, number>()),
  ).map(([name, value], index) => ({ name, value, fill: `var(--chart-${(index % 4) + 1})` }));
  const total = distribution.reduce((a, d) => a + d.value, 0);
  const usesModel = source.endsWith(" · ML model");
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
          </>
        }
      />
      <div className="monitor-strip">
        <div>
          <span className={`status-dot ${flows.length ? "" : "paused"}`} />
          <strong>{flows.length ? "Session data loaded" : "No data loaded"}</strong>
          <span className="strip-divider" />
          <Network size={14} />
          <span>{source}</span>
          <span className="demo-tag">
            {usesModel ? "ML CSV ANALYSIS" : flows.length ? "RULE CSV ANALYSIS" : "AWAITING DATA"}
          </span>
        </div>
        <span className="update-caption">Current browser session</span>
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
            value: usesModel ? "Random Forest" : "Rules",
            icon: ShieldCheck,
            change: usesModel ? "Offline CSV inference" : "Threshold analysis",
            sub: usesModel ? "Model output loaded" : "Upload compatible CSV for ML inference",
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
              <p>Observed flow activity in the current session</p>
            </div>
            <span className="demo-tag">
              {chart.length ? `${chart.length} time buckets` : "NO DATA"}
            </span>
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
            {chart.length ? (
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
            ) : (
              <div className="empty-state">
                <Network />
                <h3>No session flows</h3>
                <p>Run an analysis or live capture to populate this chart.</p>
              </div>
            )}
          </div>
          <div className="chart-bottom">
            <span>
              <span className="status-dot" />
              Session flow data
            </span>
            <span>{source}</span>
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
                  <i style={{ background: d.fill }} />
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
          <strong>Explainable offline analysis</strong>
          <p>Rule evidence and the approved Random Forest model remain visibly separate.</p>
        </div>
        <div className="engine-status">
          <span>
            <span className="status-dot" />
            Rule analysis available
          </span>
          <span>
            <span className="status-dot paused" />
            ML inference available for compatible CSV files
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
