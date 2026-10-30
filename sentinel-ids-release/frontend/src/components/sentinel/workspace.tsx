import { createContext, useContext, useState, type ReactNode } from "react";
import { Link, useRouterState } from "@tanstack/react-router";
import {
  Activity,
  Bell,
  ChevronDown,
  CircleHelp,
  FileChartColumn,
  FlaskConical,
  LayoutDashboard,
  Menu,
  Network,
  Settings2,
  ShieldCheck,
  SlidersHorizontal,
  X,
  ArrowUpRight,
  Cpu,
  Radio,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
} from "@/components/ui/dialog";
import { defaultRules, type Flow, type Rules } from "@/lib/sentinel";
const links = [
  { to: "/", label: "Overview", icon: LayoutDashboard },
  { to: "/traffic", label: "Live traffic", icon: Activity },
  { to: "/alerts", label: "Threat alerts", icon: ShieldCheck },
  { to: "/analysis", label: "Dataset analysis", icon: FlaskConical },
  { to: "/models", label: "ML models", icon: Cpu },
  { to: "/reports", label: "Reports", icon: FileChartColumn },
] as const;
type State = {
  flows: Flow[];
  setFlows: React.Dispatch<React.SetStateAction<Flow[]>>;
  running: boolean;
  setRunning: React.Dispatch<React.SetStateAction<boolean>>;
  rules: Rules;
  setRules: React.Dispatch<React.SetStateAction<Rules>>;
  selected: Flow | null;
  setSelected: React.Dispatch<React.SetStateAction<Flow | null>>;
  source: string;
  setSource: React.Dispatch<React.SetStateAction<string>>;
};
const Context = createContext<State | null>(null);
export function useWorkspace() {
  const state = useContext(Context);
  if (!state) throw new Error("Workspace provider missing");
  return state;
}
export function WorkspaceProvider({ children }: { children: ReactNode }) {
  const [flows, setFlows] = useState<Flow[]>([]);
  const [running, setRunning] = useState(false);
  const [rules, setRules] = useState(defaultRules);
  const [selected, setSelected] = useState<Flow | null>(null);
  const [source, setSource] = useState("No data loaded");
  return (
    <Context.Provider
      value={{
        flows,
        setFlows,
        running,
        setRunning,
        rules,
        setRules,
        selected,
        setSelected,
        source,
        setSource,
      }}
    >
      {children}
    </Context.Provider>
  );
}
export function Workspace({ children }: { children: ReactNode }) {
  const { flows, running, setRunning, selected, setSelected, setFlows, source } = useWorkspace();
  const pathname = useRouterState({ select: (s) => s.location.pathname });
  const [menu, setMenu] = useState(false);
  const [help, setHelp] = useState(false);
  const count = flows.filter((f) => f.attack !== "Benign" && !f.acknowledged).length;
  return (
    <div className="workspace">
      <aside className={`sidebar ${menu ? "is-open" : ""}`}>
        <Link className="brand" to="/">
          <span className="brand-symbol">
            <ShieldCheck />
          </span>
          <span>
            SENTINEL<span className="brand-caption">HYBRID INTRUSION DETECTION</span>
          </span>
        </Link>
        <div className="workspace-selector">
          <span className="workspace-avatar">S</span>
          <div>
            Security workspace<small>Personal environment</small>
          </div>
          <ChevronDown size={15} />
        </div>
        <div className="nav-label">MONITOR</div>
        <nav>
          {links.map(({ to, label, icon: Icon }) => (
            <Button
              key={to}
              variant="ghost"
              className={`nav-item ${pathname === to ? "active" : ""}`}
              asChild
            >
              <Link to={to} onClick={() => setMenu(false)}>
                <Icon />
                {label}
                {to === "/alerts" && <span className="nav-count">{count}</span>}
              </Link>
            </Button>
          ))}
        </nav>
        <div className="nav-label configuration-label">CONFIGURATION</div>
        <Button
          className={`nav-item ${pathname === "/settings" ? "active" : ""}`}
          variant="ghost"
          asChild
        >
          <Link to="/settings">
            <SlidersHorizontal />
            Detection rules
          </Link>
        </Button>
        <div className="sidebar-bottom">
          <div className="sensor-health">
            <span className="status-dot" />
            <span>
              Local capture available<small>Choose an adapter in Live traffic</small>
            </span>
            <Radio size={15} />
          </div>
          <Button variant="ghost" className="nav-item" onClick={() => setHelp(true)}>
            <CircleHelp />
            Help & documentation
            <ArrowUpRight className="ml-auto" />
          </Button>
          <div className="profile">
            <span className="profile-avatar">S</span>
            <div>
              Sentinel workspace<small>Local analyst session</small>
            </div>
            <Settings2 size={16} />
          </div>
        </div>
      </aside>
      {menu && <div className="mobile-scrim" onClick={() => setMenu(false)} />}
      <div className="main-shell">
        <header className="topbar">
          <div className="breadcrumb">
            <Button
              variant="ghost"
              size="icon"
              className="mobile-menu"
              aria-label="Open navigation"
              onClick={() => setMenu(!menu)}
            >
              {menu ? <X /> : <Menu />}
            </Button>
            <span>Workspace</span>
            <span className="crumb-slash">/</span>
            <strong>{links.find((l) => l.to === pathname)?.label ?? "Detection rules"}</strong>
          </div>
          <div className="topbar-right">
            <span className="system-status">
              <span className="status-dot" />
              Local workspace
            </span>
            <Button variant="ghost" size="icon" asChild>
              <Link to="/alerts" aria-label="Notifications">
                <Bell />
              </Link>
            </Button>
            <span className="header-avatar">S</span>
          </div>
        </header>
        <main>{children}</main>
        <footer>
          <span>
            <ShieldCheck size={13} /> Sentinel IDS <span className="footer-version">v1.0.0</span>
          </span>
          <span>
            {source} <span className="footer-separator">·</span>{" "}
            {running ? "Monitoring active" : "Monitoring paused"}
          </span>
        </footer>
      </div>
      <Dialog
        open={!!selected}
        onOpenChange={(open) => {
          if (!open) setSelected(null);
        }}
      >
        <DialogContent className="detail-dialog">
          <DialogHeader>
            <DialogTitle>Flow investigation</DialogTitle>
            <DialogDescription>
              {selected?.id} · {selected?.engine}
            </DialogDescription>
          </DialogHeader>
          {selected && (
            <>
              <div className="detail-banner">
                <div>
                  <span className={`severity ${selected.severity.toLowerCase()}`}>
                    {selected.severity}
                  </span>
                  <h2>{selected.attack}</h2>
                </div>
                <div className="risk-number">
                  {selected.score}
                  <small>risk score / 100</small>
                </div>
              </div>
              <div className="detail-grid">
                <div>
                  <small>Source IP</small>
                  <strong>{selected.source}</strong>
                </div>
                <div>
                  <small>Destination</small>
                  <strong>
                    {selected.destination}:{selected.port}
                  </strong>
                </div>
                <div>
                  <small>Protocol</small>
                  <strong>{selected.protocol}</strong>
                </div>
                <div>
                  <small>Detection engine</small>
                  <strong>{selected.engine}</strong>
                </div>
              </div>
              <h3>Detection evidence</h3>
              {selected.reasons.map((r) => (
                <div key={r} className="evidence">
                  <Activity size={16} />
                  {r}
                </div>
              ))}
              <p className="small-note">
                {selected.engine === "ML model"
                  ? "This is an offline Random Forest prediction. Review the model confidence and source data before taking action."
                  : "Threshold-based findings are indicators, not a confirmed attack or ML prediction."}
              </p>
              <Button
                disabled={selected.acknowledged || selected.attack === "Benign"}
                onClick={() => {
                  setFlows((prev) =>
                    prev.map((f) => (f.id === selected.id ? { ...f, acknowledged: true } : f)),
                  );
                  setSelected({ ...selected, acknowledged: true });
                }}
              >
                <ShieldCheck />
                {selected.acknowledged ? "Acknowledged" : "Acknowledge alert"}
              </Button>
            </>
          )}
        </DialogContent>
      </Dialog>
      <Dialog open={help} onOpenChange={setHelp}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>About this workspace</DialogTitle>
            <DialogDescription>Sentinel · Hybrid intrusion detection</DialogDescription>
          </DialogHeader>
          <p>
            Upload a CSV flow dataset for rule analysis, or use the connected Random Forest model
            when your CSV contains its required CICIDS-compatible features.
          </p>
          <p>
            Live capture records bounded connection metadata only. It is not evaluated by the model
            until a validated live feature extractor is available.
          </p>
          <Button asChild variant="outline">
            <Link to="/analysis" onClick={() => setHelp(false)}>
              <FlaskConical />
              Open dataset analysis
            </Link>
          </Button>
        </DialogContent>
      </Dialog>
    </div>
  );
}
export function PageTitle({
  eyebrow,
  title,
  description,
  actions,
}: {
  eyebrow?: string;
  title: string;
  description: string;
  actions?: ReactNode;
}) {
  return (
    <div className="page-heading">
      <div>
        {eyebrow && <div className="eyebrow">{eyebrow}</div>}
        <h1>{title}</h1>
        <p>{description}</p>
      </div>
      <div className="page-actions">{actions}</div>
    </div>
  );
}
