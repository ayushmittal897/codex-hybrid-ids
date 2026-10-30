import { useEffect, useState } from "react";
import { Button } from "@/components/ui/button";

type LiveFlow = {
  source: string;
  source_port: number;
  destination: string;
  destination_port: number;
  protocol: string;
  first_seen: string;
  last_seen: string;
  packets: number;
  bytes: number;
  forward: number;
  reverse: number;
};
export type CaptureStatus = {
  running: boolean;
  interface: string | null;
  error: string | null;
  packets: number;
  omitted: number;
  flows: LiveFlow[];
};
const base = "http://127.0.0.1:8000";
async function api(path: string, body?: object) {
  const response = await fetch(
    base + path,
    body
      ? {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(body),
        }
      : undefined,
  );
  const data = await response.json();
  if (!response.ok) throw new Error(data.detail || "Capture request failed");
  return data;
}
export function LiveCapture() {
  const [interfaces, setInterfaces] = useState<Array<{ index: number; name: string }>>([]);
  const [selected, setSelected] = useState("");
  const [status, setStatus] = useState<CaptureStatus | null>(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [page, setPage] = useState(0);
  useEffect(() => {
    let active = true;
    let timer: ReturnType<typeof setTimeout>;
    api("/capture/interfaces")
      .then((data) => {
        if (active) setInterfaces(data);
      })
      .catch((e) => {
        if (active) setError(String(e));
      });
    const poll = async () => {
      try {
        const data = await api("/capture/status");
        if (active) setStatus(data);
      } catch (e) {
        if (active) setError(String(e));
      }
      if (active) timer = setTimeout(poll, 1500);
    };
    void poll();
    return () => {
      active = false;
      clearTimeout(timer);
    };
  }, []);
  async function command(start: boolean) {
    setBusy(true);
    setError("");
    try {
      setStatus(
        await api(
          start ? "/capture/start" : "/capture/stop",
          start ? { interface_index: Number(selected) } : {},
        ),
      );
      if (start) setPage(0);
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  }
  const rows = status?.flows ?? [];
  return (
    <section className="data-panel mb-6 p-5">
      <h2>Live capture — ML not evaluated</h2>
      <p className="text-muted-foreground my-3">
        60-second personal capture. TCP/UDP connections are grouped in both directions, with IPv4
        and IPv6 support. No payload is saved. These rows do not create threat alerts.
      </p>
      <div className="flex flex-wrap items-center gap-3">
        <select
          aria-label="Capture interface"
          value={selected}
          disabled={status?.running || busy}
          onChange={(event) => setSelected(event.target.value)}
        >
          <option value="">Choose a network adapter</option>
          {interfaces.map((iface) => (
            <option key={iface.index} value={iface.index}>
              {iface.index}: {iface.name}
            </option>
          ))}
        </select>
        <Button disabled={!selected || busy || status?.running} onClick={() => void command(true)}>
          Start 60-second capture
        </Button>
        <Button
          variant="outline"
          disabled={busy || !status?.running}
          onClick={() => void command(false)}
        >
          Stop capture
        </Button>
      </div>
      {(error || status?.error) && (
        <p role="alert" className="my-3">
          {error || status?.error}. Check that the updated API is running and Npcap is available.
        </p>
      )}
      <p className="my-3">
        {status?.running ? "Capturing" : "Stopped"} · {status?.interface ?? "No adapter selected"} ·{" "}
        {status?.packets ?? 0} TCP/UDP packets · {rows.length} connections
      </p>
      <p className="text-muted-foreground mb-3">
        Session connection summaries, not CICIDS model features. IP bytes include headers. Capture
        may miss packets; short capture-window transitions are not lossless. At most 1,000
        connections are retained; {status?.omitted ?? 0} packets omitted by that limit.
      </p>
      <div className="table-scroll">
        <table className="flow-table">
          <thead>
            <tr>
              <th>Last seen (local)</th>
              <th>Source</th>
              <th>Destination</th>
              <th>Protocol</th>
              <th>Packets (out / back)</th>
              <th>IP bytes</th>
              <th>Assessment</th>
            </tr>
          </thead>
          <tbody>
            {rows.slice(page * 20, page * 20 + 20).map((row) => (
              <tr
                key={`${row.protocol}-${row.source}:${row.source_port}-${row.destination}:${row.destination_port}`}
              >
                <td>{new Date(row.last_seen).toLocaleTimeString()}</td>
                <td>
                  [{row.source}]:{row.source_port}
                </td>
                <td>
                  [{row.destination}]:{row.destination_port}
                </td>
                <td>{row.protocol}</td>
                <td>
                  {row.packets} ({row.forward} / {row.reverse})
                </td>
                <td>{row.bytes}</td>
                <td>Not evaluated</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {!rows.length && <p className="my-3">No live connections captured yet.</p>}
      <div className="flex gap-3 my-3">
        <Button variant="outline" disabled={!page} onClick={() => setPage(page - 1)}>
          Previous
        </Button>
        <Button
          variant="outline"
          disabled={(page + 1) * 20 >= rows.length}
          onClick={() => setPage(page + 1)}
        >
          Next
        </Button>
      </div>
    </section>
  );
}
