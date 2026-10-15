import Papa from "papaparse";
export type Severity = "Critical" | "High" | "Medium" | "Low";
export type Flow = {
  id: string;
  time: string;
  source: string;
  destination: string;
  port: number;
  protocol: string;
  bytes: number;
  packets: number;
  attack: string;
  severity: Severity;
  score: number;
  engine: string;
  acknowledged: boolean;
  reasons: string[];
};
export type Rules = { packetRate: number; synCount: number; enabled: boolean };
export const defaultRules: Rules = { packetRate: 1000, synCount: 100, enabled: true };
const attacks = [
  "Port Scan",
  "SYN Flood",
  "Benign",
  "Benign",
  "Brute Force",
  "Benign",
  "DDoS",
  "Benign",
  "Benign",
  "Port Scan",
  "Benign",
  "Benign",
];
export function sampleFlow(i: number, baseTime = Date.now()): Flow {
  const attack = attacks[i % attacks.length] ?? "Benign";
  const severity: Severity =
    attack === "DDoS"
      ? "Critical"
      : attack === "SYN Flood"
        ? "High"
        : attack === "Benign"
          ? "Low"
          : "Medium";
  return {
    id: `SF-${String(10482 + i).padStart(6, "0")}`,
    time: new Date(baseTime - i * 18000).toISOString(),
    source: `192.168.1.${[105, 82, 24, 12, 68, 32, 105, 19][i % 8]}`,
    destination: `10.0.0.${[12, 5, 24, 1][i % 4]}`,
    port: [443, 80, 22, 8080, 53][i % 5] ?? 443,
    protocol: i % 5 === 4 ? "UDP" : "TCP",
    bytes: 12400 + ((i * 917) % 190000),
    packets: 40 + ((i * 123) % 4200),
    attack,
    severity,
    score: attack === "Benign" ? 8 + (i % 12) : 65 + (i % 33),
    engine: "Demo hybrid",
    acknowledged: false,
    reasons:
      attack === "Port Scan"
        ? [
            "Multiple destination ports observed in a short window",
            "Unusual connection frequency from a single source",
          ]
        : attack === "SYN Flood"
          ? ["SYN flag count exceeds the configured threshold", "Low SYN-to-ACK completion ratio"]
          : attack === "DDoS"
            ? ["Elevated incoming packet rate", "High concentration of inbound flows"]
            : ["Repeated connection attempts", "Behavior differs from baseline"],
  };
}
export const initialFlows = Array.from({ length: 36 }, (_, i) =>
  sampleFlow(i, Date.UTC(2026, 9, 8, 16, 10)),
);
export function analyzeCsv(text: string, rules: Rules): Flow[] {
  const parsed = Papa.parse<Record<string, string>>(text, {
    header: true,
    skipEmptyLines: true,
    transformHeader: (h) => h.trim().toLowerCase().replace(/[ _/]/g, ""),
  });
  if (parsed.errors.some((error) => error.code !== "UndetectableDelimiter"))
    throw new Error("The CSV could not be read. Check its headers and formatting.");
  const headers = parsed.meta.fields ?? [];
  if (!headers.includes("flowpacketss") && !headers.includes("packetrate"))
    throw new Error("Missing required column: Flow Packets/s or packet_rate.");
  if (parsed.data.length > 20000) throw new Error("Maximum 20,000 flows per analysis.");
  return parsed.data.map((r, i) => {
    const rate = Number(r["flowpacketss"] ?? r["packetrate"]);
    const syn = Number(r["synflagcount"] ?? r["syncount"] ?? 0);
    if (!Number.isFinite(rate) || !Number.isFinite(syn) || rate < 0 || syn < 0)
      throw new Error(`Invalid packet rate or SYN count in row ${i + 2}.`);
    const triggered = rules.enabled && (rate > rules.packetRate || syn > rules.synCount);
    const attack = triggered
      ? syn > rules.synCount
        ? "SYN Flood"
        : "Packet Rate Anomaly"
      : "Benign";
    return {
      id: `CSV-${i + 1}`,
      time: new Date().toISOString(),
      source: r["sourceip"] ?? r["srcip"] ?? "Unknown",
      destination: r["destinationip"] ?? r["dstip"] ?? "Unknown",
      port: Number(r["destinationport"] ?? r["dstport"] ?? 0),
      protocol: r["protocol"] ?? "TCP",
      bytes: Number(r["flowbytess"] ?? r["bytes"] ?? 0) || 0,
      packets: rate,
      attack,
      severity: triggered ? "High" : "Low",
      score: triggered
        ? Math.min(
            99,
            Math.round(60 + 20 * Math.max(rate / rules.packetRate, syn / rules.synCount)),
          )
        : 0,
      engine: "Rules only",
      acknowledged: false,
      reasons: triggered
        ? [
            `Packet rate: ${rate.toLocaleString()} /s (threshold ${rules.packetRate})`,
            `SYN count: ${syn} (threshold ${rules.synCount})`,
          ]
        : ["No configured threshold exceeded"],
    };
  });
}
function sanitizeCsvField(val: unknown): string | number | boolean {
  if (typeof val === "number" || typeof val === "boolean") return val;
  if (!val) return "";
  const str = String(val);
  if (/^[=+\-@\t\r]/.test(str)) {
    return `'${str}`;
  }
  return str;
}

export function downloadCsv(flows: Flow[], name = "sentinel-flows.csv") {
  const csv = Papa.unparse(
    flows.map((f) => ({
      ID: sanitizeCsvField(f.id),
      Time: sanitizeCsvField(f.time),
      Source: sanitizeCsvField(f.source),
      Destination: sanitizeCsvField(f.destination),
      Protocol: sanitizeCsvField(f.protocol),
      Attack: sanitizeCsvField(f.attack),
      Severity: sanitizeCsvField(f.severity),
      Risk: f.score,
      Engine: sanitizeCsvField(f.engine),
      Acknowledged: f.acknowledged,
    })),
  );
  const url = URL.createObjectURL(new Blob([csv], { type: "text/csv;charset=utf-8;" }));
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  a.click();
  URL.revokeObjectURL(url);
}
export function pageHead(title: string, description: string) {
  return {
    meta: [
      { title: `${title} · Sentinel IDS` },
      { name: "description", content: description },
      { property: "og:title", content: `${title} · Sentinel IDS` },
      { property: "og:description", content: description },
      { property: "og:type", content: "website" },
      { name: "twitter:card", content: "summary_large_image" },
    ],
  };
}
