import { useState } from "react";
import { ArrowUpRight, Download, Search, ShieldCheck } from "lucide-react";
import { Button } from "@/components/ui/button";
import { downloadCsv, type Flow } from "@/lib/sentinel";
import { PageTitle, useWorkspace } from "./workspace";
import { LiveCapture } from "./live-capture";
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
                  ) : f.engine === "Rules only" ? (
                    "Rules"
                  ) : (
                    f.engine
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
  const { flows } = useWorkspace();
  const [query, setQuery] = useState("");
  const [severity, setSeverity] = useState("All severities");
  const [status, setStatus] = useState("All statuses");
  const [page, setPage] = useState(1);
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
            : "Inspect network flows from the selected traffic source."
        }
        actions={
          <>
            <Button variant="outline" onClick={() => downloadCsv(filtered)}>
              <Download />
              Export CSV
            </Button>
          </>
        }
      />
      {!alerts && <LiveCapture />}
      {!alerts && <h2 className="mb-3">Uploaded CSV analysis</h2>}
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
