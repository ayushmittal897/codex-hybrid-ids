import { useEffect, useState } from "react";
import {
  ArrowUpRight,
  Download,
  Play,
  Radio,
  Search,
  ShieldAlert,
  ShieldCheck,
  Square,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { downloadCsv, type Flow } from "@/lib/sentinel";
import { PageTitle, MonitorButton, useWorkspace } from "./workspace";

export function FlowTable({ flows, compact = false }: { flows: Flow[]; compact?: boolean }) {
  const { setSelected } = useWorkspace();
  return (
    <div className="table-scroll">
      <table className="flow-table">
        <thead>
          <tr>
            <th>Timestamp</th>
            <th>Source IP</th>
            <th>Attack type</th>
            <th>Severity</th>
            <th>{compact ? "Risk score" : "Destination"}</th>
            <th>Detection</th>
            <th />
          </tr>
        </thead>
        <tbody>
          {flows.map((f) => (
            <tr key={f.id}>
              <td className="time-cell">
                {new Date(f.time).toLocaleTimeString("en-GB", { hour12: false, timeZone: "UTC" })}
                <small>{f.id}</small>
              </td>
              <td className="mono">{f.source}</td>
              <td>
                <span className="attack-label">
                  <span className={`tiny-square ${f.severity.toLowerCase()}`} />
                  {f.attack}
                </span>
              </td>
              <td>
                <span className={`severity ${f.severity.toLowerCase()}`}>{f.severity}</span>
              </td>
              <td>
                {compact ? (
                  <div className="score-cell">
                    <span>
                      {f.score}
                      <small>/100</small>
                    </span>
                    <progress max="100" value={f.score} className={f.severity.toLowerCase()} />
                  </div>
                ) : (
                  <span className="mono">
                    {f.destination}:{f.port}
                  </span>
                )}
              </td>
              <td>
                <span className="engine-pill">
                  {f.acknowledged ? (
                    <>
                      <ShieldCheck size={12} />
                      Reviewed
                    </>
                  ) : f.engine.includes("Hybrid") || f.engine.includes("ML") ? (
                    "Hybrid ML"
                  ) : f.engine === "Rules only" ? (
                    "Rules"
                  ) : (
                    "Hybrid · Demo"
                  )}
                </span>
              </td>
              <td>
                <Button
                  variant="ghost"
                  size="icon"
                  aria-label={`Investigate ${f.id}`}
                  onClick={() => setSelected(f)}
                >
                  <ArrowUpRight />
                </Button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      {flows.length === 0 && (
        <div className="empty-state">
          <ShieldCheck />
          <h3>No matching flows</h3>
          <p>There are no results for the selected filters.</p>
        </div>
      )}
    </div>
  );
}

export function TrafficPage({ alerts = false }: { alerts?: boolean }) {
  const { flows, setFlows, setSource, setRunning } = useWorkspace();
  const [query, setQuery] = useState("");
  const [severity, setSeverity] = useState("All severities");
  const [status, setStatus] = useState("All statuses");
  const [page, setPage] = useState(1);

  // Live traffic capture states
  const [isCapturing, setIsCapturing] = useState(false);
  const [captureStats, setCaptureStats] = useState({
    packets: 0,
    flows: 0,
    threats: 0,
    elapsed: 0,
    interface: "Auto",
  });
  const [interfaces, setInterfaces] = useState<Array<{ id: string; name: string; ip: string }>>([]);
  const [selectedIface, setSelectedIface] = useState<string>("");

  // Check initial capture status and interfaces
  useEffect(() => {
    fetch("http://127.0.0.1:8000/capture/status")
      .then((res) => (res.ok ? res.json() : null))
      .then((data) => {
        if (data && data.running) {
          setIsCapturing(true);
          setCaptureStats({
            packets: data.packets_captured,
            flows: data.flows_evaluated,
            threats: data.threats_detected,
            elapsed: data.elapsed_seconds,
            interface: data.interface,
          });
        }
      })
      .catch(() => {});

    fetch("http://127.0.0.1:8000/capture/interfaces")
      .then((res) => (res.ok ? res.json() : null))
      .then((data) => {
        if (data && data.interfaces) {
          setInterfaces(data.interfaces);
          if (data.interfaces.length > 0) {
            setSelectedIface(data.interfaces[0].id);
          }
        }
      })
      .catch(() => {});
  }, []);

  // Poll for live captured flows when capturing
  useEffect(() => {
    if (!isCapturing) return;

    const interval = setInterval(async () => {
      try {
        const res = await fetch("http://127.0.0.1:8000/capture/flows?limit=30");
        if (res.ok) {
          const data = await res.json();
          if (data.status) {
            setCaptureStats({
              packets: data.status.packets_captured,
              flows: data.status.flows_evaluated,
              threats: data.status.threats_detected,
              elapsed: data.status.elapsed_seconds,
              interface: data.status.interface,
            });
          }
          if (data.flows && data.flows.length > 0) {
            setFlows((prev) => {
              const existingIds = new Set(prev.map((f) => f.id));
              const newArrivals = data.flows.filter((f: Flow) => !existingIds.has(f.id));
              if (newArrivals.length === 0) return prev;
              return [...newArrivals, ...prev].slice(0, 1000);
            });
          }
        }
      } catch (err) {
        console.error("Live capture poll error:", err);
      }
    }, 1500);

    return () => clearInterval(interval);
  }, [isCapturing, setFlows]);

  const toggleLiveCapture = async () => {
    if (isCapturing) {
      try {
        await fetch("http://127.0.0.1:8000/capture/stop", { method: "POST" });
        setIsCapturing(false);
      } catch (err) {
        console.error("Stop capture error:", err);
      }
    } else {
      try {
        const url = selectedIface
          ? `http://127.0.0.1:8000/capture/start?interface=${encodeURIComponent(selectedIface)}`
          : "http://127.0.0.1:8000/capture/start";
        const res = await fetch(url, { method: "POST" });
        if (res.ok) {
          setIsCapturing(true);
          setSource("Live Sniffer (Real-Time Capture)");
          setRunning(true);
        }
      } catch (err) {
        alert("Failed to connect to backend capture agent. Is backend running on port 8000?");
      }
    }
  };

  const downloadLiveCsv = () => {
    window.open("http://127.0.0.1:8000/capture/download", "_blank");
  };

  const filtered = flows.filter(
    (f) =>
      (!alerts || f.attack !== "Benign") &&
      `${f.source} ${f.destination} ${f.attack} ${f.id}`
        .toLowerCase()
        .includes(query.toLowerCase()) &&
      (severity === "All severities" || f.severity === severity) &&
      (status === "All statuses" || (status === "Acknowledged" ? f.acknowledged : !f.acknowledged)),
  );
  const max = Math.max(1, Math.ceil(filtered.length / 10));
  const current = Math.min(page, max);

  return (
    <>
      <PageTitle
        title={alerts ? "Threat alerts" : "Live traffic"}
        description={
          alerts
            ? "Investigate and acknowledge suspicious network activity."
            : "Inspect network flows from the selected traffic source or active live capture."
        }
        actions={
          <>
            <Button variant="outline" onClick={() => downloadCsv(filtered)}>
              <Download />
              Export CSV
            </Button>
            <MonitorButton />
          </>
        }
      />

      {/* Real-Time Live Capture Controller Panel (Visible on Live Traffic view) */}
      {!alerts && (
        <div className="live-capture-card">
          <div className="live-capture-header">
            <div className="flex items-center gap-2">
              <span className={`live-pulse-indicator ${isCapturing ? "pulsing" : ""}`} />
              <strong>{isCapturing ? "LIVE NETWORK SNIFFER ACTIVE" : "LIVE CAPTURE STANDBY"}</strong>
              <span className="demo-tag">{isCapturing ? "SNIFFING PACKETS" : "READY"}</span>
            </div>
            <div className="flex items-center gap-2">
              {interfaces.length > 0 && !isCapturing && (
                <select
                  className="interface-select"
                  value={selectedIface}
                  onChange={(e) => setSelectedIface(e.target.value)}
                  aria-label="Select network interface"
                >
                  {interfaces.map((iface) => (
                    <option key={iface.id} value={iface.id}>
                      {iface.name} ({iface.ip})
                    </option>
                  ))}
                </select>
              )}
              <Button
                variant={isCapturing ? "destructive" : "default"}
                size="sm"
                onClick={toggleLiveCapture}
                className="gap-2"
              >
                {isCapturing ? <Square size={14} /> : <Play size={14} />}
                {isCapturing ? "Stop Live Capture" : "Start Live Capture"}
              </Button>
              <Button variant="outline" size="sm" onClick={downloadLiveCsv} className="gap-2">
                <Download size={14} />
                Download Captured CSV
              </Button>
            </div>
          </div>
          <div className="live-capture-metrics">
            <div>
              <small>Packets Sniffed</small>
              <strong>{captureStats.packets.toLocaleString()}</strong>
            </div>
            <div>
              <small>Flows Evaluated</small>
              <strong>{captureStats.flows.toLocaleString()}</strong>
            </div>
            <div>
              <small>Threats Flagged</small>
              <strong className={captureStats.threats > 0 ? "text-destructive" : ""}>
                {captureStats.threats}
              </strong>
            </div>
            <div>
              <small>Elapsed Time</small>
              <strong>{captureStats.elapsed}s</strong>
            </div>
          </div>
        </div>
      )}

      <div className="filter-bar">
        <div className="search-input">
          <Search size={16} />
          <input
            aria-label="Search flows"
            placeholder="Search IP address, attack or flow ID..."
            value={query}
            onChange={(e) => {
              setQuery(e.target.value);
              setPage(1);
            }}
          />
        </div>
        <select
          aria-label="Filter severity"
          value={severity}
          onChange={(e) => {
            setSeverity(e.target.value);
            setPage(1);
          }}
        >
          {["All severities", "Critical", "High", "Medium", "Low"].map((x) => (
            <option key={x}>{x}</option>
          ))}
        </select>
        {alerts && (
          <select
            aria-label="Filter alert status"
            value={status}
            onChange={(e) => {
              setStatus(e.target.value);
              setPage(1);
            }}
          >
            {["All statuses", "Open", "Acknowledged"].map((x) => (
              <option key={x}>{x}</option>
            ))}
          </select>
        )}
        <span className="text-muted-foreground text-sm">
          {filtered.length} {alerts ? "alerts" : "flows"}
        </span>
      </div>

      <section className="data-panel">
        <FlowTable flows={filtered.slice((current - 1) * 10, current * 10)} />
        <div className="pagination">
          <span>
            Showing {filtered.length ? (current - 1) * 10 + 1 : 0}–
            {Math.min(current * 10, filtered.length)} of {filtered.length}
          </span>
          <div>
            <Button
              variant="outline"
              size="sm"
              disabled={current === 1}
              onClick={() => setPage(current - 1)}
            >
              Previous
            </Button>
            <span>
              {current} / {max}
            </span>
            <Button
              variant="outline"
              size="sm"
              disabled={current === max}
              onClick={() => setPage(current + 1)}
            >
              Next
            </Button>
          </div>
        </div>
      </section>
    </>
  );
}
