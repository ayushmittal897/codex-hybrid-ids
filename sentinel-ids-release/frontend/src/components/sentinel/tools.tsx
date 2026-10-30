import { useEffect, useRef, useState } from "react";
import {
  Activity,
  Check,
  CircleAlert,
  Cpu,
  Download,
  FileSpreadsheet,
  FlaskConical,
  Play,
  ShieldCheck,
  Upload,
  X,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { analyzeCsv, downloadCsv, type Severity } from "@/lib/sentinel";
import { PageTitle, useWorkspace } from "./workspace";
import { FlowTable } from "./traffic";
export function AnalysisPage() {
  const { rules, setFlows, setSource, setRunning } = useWorkspace();
  const input = useRef<HTMLInputElement>(null);
  const [file, setFile] = useState<File | null>(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [modelBusy, setModelBusy] = useState(false);
  const [modelResult, setModelResult] = useState<{
    rows: number;
    predictions: Record<string, number>;
    model: string;
    labels: string[];
  } | null>(null);
  const [results, setResults] = useState<ReturnType<typeof analyzeCsv> | null>(null);
  const analyze = async () => {
    if (!file) return;
    setError("");
    setBusy(true);
    try {
      if (file.size > 20 * 1024 * 1024) throw new Error("Maximum file size is 20 MB.");
      const rows = analyzeCsv(await file.text(), rules);
      if (!rows.length) throw new Error("This file has no flow rows.");
      setResults(rows);
      setFlows(rows);
      setSource(file.name);
      setRunning(false);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Analysis failed.");
    } finally {
      setBusy(false);
    }
  };
  const choose = (f: File | undefined) => {
    if (!f) return;
    setResults(null);
    setModelResult(null);
    setError("");
    if (!f.name.toLowerCase().endsWith(".csv")) {
      setFile(null);
      setError("Please select a CSV file. PCAP extraction requires a capture agent.");
      return;
    }
    setFile(f);
  };
  const runModel = async () => {
    if (!file) return;
    setError("");
    setModelBusy(true);
    try {
      const body = new FormData();
      body.append("file", file);
      const response = await fetch("http://127.0.0.1:8000/predict", { method: "POST", body });
      const payload = (await response.json()) as {
        detail?: string;
        rows?: number;
        predictions?: Record<string, number>;
        prediction_labels?: string[];
        prediction_confidences?: number[];
        model?: string;
      };
      if (!response.ok)
        throw new Error(
          typeof payload.detail === "string" ? payload.detail : "Model inference failed.",
        );
      if (
        payload.rows === undefined ||
        !payload.predictions ||
        !payload.prediction_labels ||
        !payload.prediction_confidences ||
        !payload.model
      )
        throw new Error("The model response was incomplete.");
      const baseRows = results ?? analyzeCsv(await file.text(), rules);
      const mlRows = baseRows.map((row, index) => {
        const label = payload.prediction_labels?.[index] ?? "Unknown";
        const confidence = payload.prediction_confidences?.[index] ?? 0;
        const attack = label === "BENIGN" ? "Benign" : label;
        const severity: Severity = attack === "Benign" ? "Low" : "High";
        return {
          ...row,
          attack,
          severity,
          score: Math.round(confidence * 100),
          engine: "ML model",
          reasons: [
            `Random Forest prediction: ${label}`,
            `Model confidence: ${(confidence * 100).toFixed(1)}%`,
          ],
        };
      });
      setFlows(mlRows);
      setSource(`${file.name} · ML model`);
      setRunning(false);
      setModelResult({
        rows: payload.rows,
        predictions: payload.predictions,
        model: payload.model,
        labels: payload.prediction_labels,
      });
    } catch (e) {
      setError(
        e instanceof Error ? e.message : "Model inference failed. Is the API running on port 8000?",
      );
    } finally {
      setModelBusy(false);
    }
  };
  return (
    <>
      <PageTitle
        title="Dataset analysis"
        description="Analyze network-flow datasets against your configured detection rules."
      />
      <div className="analysis-layout">
        <section className="upload-section">
          <div className="section-eyebrow">
            <FlaskConical size={16} /> OFFLINE ANALYSIS
          </div>
          <h2>Analyze a flow dataset</h2>
          <p className="section-copy">
            CSV flow features · Rule analysis or connected ML inference
          </p>
          <div
            className="dropzone"
            onDragOver={(e) => e.preventDefault()}
            onDrop={(e) => {
              e.preventDefault();
              choose(e.dataTransfer.files[0]);
            }}
          >
            <span className="upload-icon">
              <FileSpreadsheet size={32} />
            </span>
            <h3>{file ? file.name : "Drop your dataset here"}</h3>
            <p>
              {file
                ? `${(file.size / 1024).toFixed(1)} KB · Ready to analyze`
                : "CSV files up to 20 MB · 20,000 flows"}
            </p>
            <Button variant="outline" onClick={() => input.current?.click()}>
              <Upload />
              {file ? "Choose another file" : "Browse files"}
            </Button>
            <input
              ref={input}
              type="file"
              accept=".csv"
              aria-label="Upload CSV dataset"
              className="hidden"
              onChange={(e) => choose(e.target.files?.[0])}
            />
          </div>
          {error && (
            <div className="error-message" role="alert">
              <CircleAlert size={18} />
              {error}
            </div>
          )}
          <Button className="analyze-button" disabled={!file || busy} onClick={analyze}>
            <Play />
            {busy ? "Analyzing…" : "Run rule analysis"}
          </Button>
          <Button
            variant="outline"
            className="analyze-button"
            disabled={!file || modelBusy}
            onClick={runModel}
          >
            <Cpu />
            {modelBusy ? "Running model…" : "Run connected ML model"}
          </Button>
        </section>
        <aside className="analysis-info">
          <h3>Analysis configuration</h3>
          <div className="config-row">
            <span>Detection engine</span>
            <strong>{modelResult ? "Rules + Random Forest" : "Rule-based"}</strong>
          </div>
          <div className="config-row">
            <span>Packet-rate threshold</span>
            <strong>{rules.packetRate.toLocaleString()} /s</strong>
          </div>
          <div className="config-row">
            <span>SYN-count threshold</span>
            <strong>{rules.synCount}</strong>
          </div>
          <div className="config-row">
            <span>Rules</span>
            <span className="severity low">{rules.enabled ? "Enabled" : "Disabled"}</span>
          </div>
          <h3 className="mt-8">Expected columns</h3>
          <div className="column-chips">
            <code>Flow Packets/s</code>
            <code>SYN Flag Count</code>
            <code>Source IP</code>
            <code>Destination IP</code>
          </div>
          <p className="small-note">
            packet_rate and syn_count are also accepted. Packet rate is required; source,
            destination and SYN count are optional.
          </p>
          <div className="notice">
            <CircleAlert size={18} />
            <span>
              {modelResult
                ? `${modelResult.model} returned ${Object.entries(modelResult.predictions)
                    .map(([label, count]) => `${label}: ${count}`)
                    .join(", ")}. This is offline CSV inference; it is not live capture.`
                : "Run the connected ML model after starting the local API. Rules-only findings are indicators, not confirmed attacks. PCAP and live capture require an external sensor."}
            </span>
          </div>
        </aside>
      </div>
      {results && (
        <section className="analysis-results">
          <div className="panel-heading">
            <div>
              <h2>Analysis complete</h2>
              <p>
                {results.length} flows analyzed ·{" "}
                {results.filter((f) => f.attack !== "Benign").length} flagged · Rules only
              </p>
            </div>
            <Button variant="outline" onClick={() => downloadCsv(results, "sentinel-analysis.csv")}>
              <Download />
              Download results
            </Button>
          </div>
          <FlowTable flows={results.slice(0, 20)} />
          {results.length > 20 && (
            <p className="small-note">
              Showing the first 20 flows. All results are available in Live traffic and the
              download.
            </p>
          )}
        </section>
      )}
      {modelResult && (
        <section className="analysis-results">
          <div className="panel-heading">
            <div>
              <h2>ML inference complete</h2>
              <p>
                {modelResult.rows} flows analyzed · {modelResult.model} · Offline CSV mode
              </p>
            </div>
          </div>
        </section>
      )}
    </>
  );
}
export function ModelsPage() {
  const [health, setHealth] = useState<{
    status: string;
    model: string | null;
    classes: string[] | null;
  } | null>(null);
  useEffect(() => {
    fetch("http://127.0.0.1:8000/health")
      .then((response) => response.json())
      .then((payload: { status: string; model: string | null; classes: string[] | null }) =>
        setHealth(payload),
      )
      .catch(() => setHealth(null));
  }, []);
  const connected = health?.status === "ok" && health.model === "RandomForest";
  return (
    <>
      <PageTitle
        title="Detection models"
        description="Model readiness, evaluation and your hybrid detection pipeline."
      />
      <div className="pipeline">
        <div>
          <Activity />
          <strong>Flow features</strong>
          <small>CSV feature input</small>
        </div>
        <span>→</span>
        <div>
          <ShieldCheck />
          <strong>Rule engine</strong>
          <small>Ready for analysis</small>
        </div>
        <span>→</span>
        <div>
          <Cpu />
          <strong>ML classifier</strong>
          <small>{connected ? "Connected · offline CSV" : "Not connected"}</small>
        </div>
        <span>→</span>
        <div>
          <ShieldCheck />
          <strong>Hybrid decision</strong>
          <small>{connected ? "ML service ready" : "Demo only"}</small>
        </div>
      </div>
      <section className="model-section">
        <div className="panel-heading">
          <div>
            <h2>Model registry</h2>
            <p>
              {connected
                ? `Connected model classes: ${health.classes?.join(", ")}`
                : "Evaluation results appear only after a trained model is connected."}
            </p>
          </div>
          <span className="demo-tag">{connected ? "MODEL CONNECTED" : "NO TRAINED MODELS"}</span>
        </div>
        <div className="model-grid">
          {["Random Forest", "XGBoost"].map((name, i) => (
            <article className="model-card" key={name}>
              <span className="model-icon">
                <Cpu size={24} />
              </span>
              <span className="engine-pill">
                {name === "Random Forest" && connected ? "Connected" : "Not connected"}
              </span>
              <h2>{name}</h2>
              <p>
                {i === 0
                  ? "Ensemble tree classifier · Baseline candidate"
                  : "Gradient-boosted trees · Comparison candidate"}
              </p>
              <div className="model-metrics">
                {["Accuracy", "Precision", "Recall", "F1 score"].map((m) => (
                  <div key={m}>
                    <small>{m}</small>
                    <strong>—</strong>
                  </div>
                ))}
              </div>
              <div className="model-footer">
                <CircleAlert size={15} />{" "}
                {name === "Random Forest" && connected
                  ? "Offline inference ready · metrics from model card"
                  : "Evaluation pending"}
              </div>
            </article>
          ))}
        </div>
      </section>
      <div className="notice large-notice">
        <CircleAlert />
        <div>
          <strong>Measured results, not assumed performance</strong>
          <p>
            The connected Random Forest currently supports offline CSV inference for the approved
            PortScan bundle. It is not live capture, and the dashboard does not yet display
            per-class evaluation metrics from the Python model card.
          </p>
        </div>
      </div>
    </>
  );
}
export function ReportsPage() {
  const { flows, source } = useWorkspace();
  const threats = flows.filter((f) => f.attack !== "Benign");
  return (
    <>
      <PageTitle
        title="Security reports"
        description="Review and export the current monitoring session."
        actions={
          <>
            <Button
              variant="outline"
              onClick={() => downloadCsv(flows, "sentinel-security-report.csv")}
            >
              <Download />
              Export CSV
            </Button>
            <Button onClick={() => window.print()}>
              <FileSpreadsheet />
              Print / save PDF
            </Button>
          </>
        }
      />
      <article className="report-document">
        <div className="report-header">
          <div className="brand">
            <span className="brand-symbol">
              <ShieldCheck />
            </span>
            <span>SENTINEL</span>
          </div>
          <span className="demo-tag">SECURITY REPORT</span>
        </div>
        <div className="report-title">
          <div className="eyebrow">SESSION SUMMARY</div>
          <h2>Network security assessment</h2>
          <p>
            {new Date().toLocaleDateString("en-GB", {
              day: "numeric",
              month: "long",
              year: "numeric",
              timeZone: "UTC",
            })}{" "}
            · {source}
          </p>
        </div>
        <div className="report-stats">
          <div>
            <small>Total flows</small>
            <strong>{flows.length}</strong>
          </div>
          <div>
            <small>Flagged flows</small>
            <strong>{threats.length}</strong>
          </div>
          <div>
            <small>Critical alerts</small>
            <strong>{threats.filter((f) => f.severity === "Critical").length}</strong>
          </div>
          <div>
            <small>Reviewed alerts</small>
            <strong>{threats.filter((f) => f.acknowledged).length}</strong>
          </div>
        </div>
        <h3>Attack breakdown</h3>
        {Array.from(new Set(threats.map((f) => f.attack))).map((attack) => (
          <div className="report-row" key={attack}>
            <span>{attack}</span>
            <strong>{threats.filter((f) => f.attack === attack).length} flows</strong>
          </div>
        ))}
        {!threats.length && <p>No configured rule violations detected.</p>}
        <h3>Recommended investigation</h3>
        <ul className="report-recommendations">
          <li>Review critical and high-severity alerts before lower-priority findings.</li>
          <li>Verify flagged source IPs against authorized devices and network activity.</li>
          <li>Validate thresholds against your environment to reduce false positives.</li>
        </ul>
        <div className="notice">
          <CircleAlert size={18} />
          <span>
            {source.endsWith(" · ML model")
              ? "This report summarizes offline model inference. Predictions require analyst review."
              : "This report contains rule-based CSV analysis. Flagged flows are indicators requiring investigation."}
          </span>
        </div>
      </article>
    </>
  );
}
export function SettingsPage() {
  const { rules, setRules, source, setSource, setFlows, setRunning } = useWorkspace();
  const [rate, setRate] = useState(rules.packetRate);
  const [syn, setSyn] = useState(rules.synCount);
  const [enabled, setEnabled] = useState(rules.enabled);
  const [saved, setSaved] = useState(false);
  const [error, setError] = useState("");
  return (
    <>
      <PageTitle
        title="Detection rules"
        description="Configure thresholds for rule-based flow analysis."
      />
      <section className="settings-section">
        <div className="panel-heading">
          <div>
            <h2>Behavioral thresholds</h2>
            <p>Settings apply to subsequent CSV analysis in this session.</p>
          </div>
          <span className="severity low">Rule engine</span>
        </div>
        <form
          onSubmit={(e) => {
            e.preventDefault();
            if (!Number.isFinite(rate) || !Number.isFinite(syn) || rate < 1 || syn < 1) {
              setError("Thresholds must be positive numbers.");
              return;
            }
            setRules({ packetRate: rate, synCount: syn, enabled });
            setSaved(true);
            setError("");
          }}
        >
          <div className="setting-row">
            <div>
              <h3>Packet-rate anomaly</h3>
              <p>Flag flows with packet rates above this threshold.</p>
            </div>
            <label className="number-control">
              <input
                aria-label="Packet-rate threshold"
                type="number"
                min="1"
                value={rate}
                onChange={(e) => {
                  setRate(Number(e.target.value));
                  setSaved(false);
                }}
              />
              <span>packets /s</span>
            </label>
          </div>
          <div className="setting-row">
            <div>
              <h3>SYN flood indicator</h3>
              <p>Flag flows with unusually high SYN flag counts.</p>
            </div>
            <label className="number-control">
              <input
                aria-label="SYN-count threshold"
                type="number"
                min="1"
                value={syn}
                onChange={(e) => {
                  setSyn(Number(e.target.value));
                  setSaved(false);
                }}
              />
              <span>SYN flags</span>
            </label>
          </div>
          <div className="setting-row">
            <div>
              <h3>Rule-based detection</h3>
              <p>Enable threshold analysis for uploaded datasets.</p>
            </div>
            <label className="toggle-label">
              <input
                type="checkbox"
                checked={enabled}
                onChange={(e) => {
                  setEnabled(e.target.checked);
                  setSaved(false);
                }}
              />
              <span>{enabled ? "Enabled" : "Disabled"}</span>
            </label>
          </div>
          {error && (
            <p role="alert" className="error-message">
              {error}
            </p>
          )}
          <div className="settings-actions">
            {saved && (
              <span className="saved-message">
                <Check size={16} />
                Rules saved for this session
              </span>
            )}
            <Button type="submit">
              <Check />
              Save changes
            </Button>
          </div>
        </form>
      </section>
      <section className="settings-section">
        <div className="panel-heading">
          <div>
            <h2>Traffic source</h2>
            <p>Current source: {source}</p>
          </div>
        </div>
        <div className="setting-row">
          <div>
            <h3>Clear workspace</h3>
            <p>Remove all loaded flows and stop monitoring.</p>
          </div>
          <Button
            variant="outline"
            onClick={() => {
              setFlows([]);
              setSource("No data loaded");
              setRunning(false);
            }}
          >
            <X />
            Clear data
          </Button>
        </div>
        <div className="notice">
          <CircleAlert size={18} />
          <span>
            Changes and alerts are session-only. Live capture, shared history and trained ML require
            connected services.
          </span>
        </div>
      </section>
    </>
  );
}
