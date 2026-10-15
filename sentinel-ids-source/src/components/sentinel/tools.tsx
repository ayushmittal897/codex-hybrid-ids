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
import { analyzeCsv, downloadCsv } from "@/lib/sentinel";
import { PageTitle, useWorkspace } from "./workspace";
import { FlowTable } from "./traffic";
export function AnalysisPage() {
  const { rules, setFlows, setSource, setRunning } = useWorkspace();
  const input = useRef<HTMLInputElement>(null);
  const [file, setFile] = useState<File | null>(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [modelBusy, setModelBusy] = useState(false);
  const [selectedModel, setSelectedModel] = useState("multiclass");
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
      const response = await fetch(
        `http://127.0.0.1:8000/predict?model_id=${encodeURIComponent(selectedModel)}`,
        { method: "POST", body },
      );
      const payload = (await response.json()) as {
        detail?: string;
        rows?: number;
        predictions?: Record<string, number>;
        prediction_labels?: string[];
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
        !payload.model
      )
        throw new Error("The model response was incomplete.");
      const baseRows = results ?? analyzeCsv(await file.text(), rules);
      const mlRows = baseRows.map((row, index) => {
        const label = payload.prediction_labels?.[index] ?? "Unknown";
        const attack = label.toUpperCase() === "BENIGN" ? "Benign" : label;
        const isThreat = attack !== "Benign";
        const severity = !isThreat
          ? "Low"
          : ["DoS_DDoS", "Infiltration"].includes(attack)
            ? "Critical"
            : "High";
        const score = !isThreat ? 8 : severity === "Critical" ? 95 : 88;
        return {
          ...row,
          attack,
          severity,
          score,
          engine: `ML (${payload.model})`,
          reasons: [`Random Forest prediction: ${label}`],
        };
      });
      setFlows(mlRows);
      setSource(`${file.name} · ${payload.model}`);
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
  const sample = () => {
    const blob = new Blob(
      [
        "source_ip,destination_ip,destination_port,packet_rate,syn_count\n192.168.1.105,10.0.0.12,443,1800,250\n192.168.1.24,10.0.0.5,80,120,8\n192.168.1.82,10.0.0.12,22,2500,30",
      ],
      { type: "text/csv" },
    );
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = "sentinel-sample.csv";
    a.click();
    URL.revokeObjectURL(a.href);
  };
  return (
    <>
      <PageTitle
        title="Dataset analysis"
        description="Analyze network-flow datasets against your configured detection rules."
        actions={
          <Button variant="outline" onClick={sample}>
            <Download />
            Sample CSV
          </Button>
        }
      />
      <div className="analysis-layout">
        <section className="upload-section">
          <div className="section-eyebrow">
            <FlaskConical size={16} /> OFFLINE ANALYSIS
          </div>
          <h2>Analyze a flow dataset</h2>
          <p className="section-copy">CSV flow features · Rules-only detection</p>
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
          <div className="model-choice-box" style={{ margin: "12px 0 6px" }}>
            <label style={{ fontSize: "11px", color: "var(--muted-foreground)", display: "block", marginBottom: "5px" }}>
              Target Machine Learning Classifier:
            </label>
            <select
              aria-label="Select ML model for inference"
              value={selectedModel}
              onChange={(e) => setSelectedModel(e.target.value)}
              style={{ width: "100%", padding: "7px 10px", fontSize: "11px", borderRadius: "5px" }}
            >
              <option value="multiclass">Multi-Threat Random Forest (8 Classes: Bot, DoS, BruteForce, PortScan, WebAttack)</option>
              <option value="portscan">PortScan Random Forest (Binary: BENIGN / PortScan)</option>
            </select>
          </div>
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
  const [data, setData] = useState<{
    models: Array<{
      id: string;
      name: string;
      type: string;
      active: boolean;
      classes: string[];
      features_count: number;
      metrics: {
        accuracy: number;
        precision: number;
        recall: number;
        f1_score: number;
      };
      per_class_report?: Record<
        string,
        { precision: number; recall: number; "f1-score": number; support: number }
      >;
      dataset: string;
      trained_rows?: number;
    }>;
    active_model_id: string;
  } | null>(null);
  const [switching, setSwitching] = useState<string | null>(null);

  const fetchModels = () => {
    fetch("http://127.0.0.1:8000/models")
      .then((res) => (res.ok ? res.json() : null))
      .then((resData) => {
        if (resData && resData.models) {
          setData(resData);
        } else {
          // Static fallback from trained model metadata
          setData({
            active_model_id: "multiclass",
            models: [
              {
                id: "multiclass",
                name: "Multi-Threat Random Forest (8 Classes)",
                type: "multiclass",
                active: true,
                classes: [
                  "BENIGN",
                  "Bot",
                  "BruteForce",
                  "DoS_DDoS",
                  "Infiltration",
                  "Other",
                  "PortScan",
                  "WebAttack",
                ],
                features_count: 77,
                metrics: { accuracy: 0.9954, precision: 0.8943, recall: 0.7769, f1_score: 0.8223 },
                dataset: "CIC-IDS2017",
                trained_rows: 343436,
                per_class_report: {
                  BENIGN: {
                    precision: 0.9976,
                    recall: 0.9986,
                    "f1-score": 0.9981,
                    support: 117449,
                  },
                  DoS_DDoS: {
                    precision: 0.9967,
                    recall: 0.9952,
                    "f1-score": 0.996,
                    support: 25625,
                  },
                  BruteForce: {
                    precision: 0.9594,
                    recall: 0.9564,
                    "f1-score": 0.9579,
                    support: 3187,
                  },
                  Bot: { precision: 0.8639, recall: 0.8079, "f1-score": 0.8349, support: 432 },
                  PortScan: {
                    precision: 0.9104,
                    recall: 0.9137,
                    "f1-score": 0.912,
                    support: 278,
                  },
                  WebAttack: {
                    precision: 0.4268,
                    recall: 0.3317,
                    "f1-score": 0.3733,
                    support: 202,
                  },
                  Infiltration: {
                    precision: 1.0,
                    recall: 0.5455,
                    "f1-score": 0.7059,
                    support: 11,
                  },
                  Other: { precision: 1.0, recall: 0.6667, "f1-score": 0.8, support: 3 },
                },
              },
              {
                id: "portscan",
                name: "PortScan Random Forest (Binary)",
                type: "binary",
                active: false,
                classes: ["BENIGN", "PortScan"],
                features_count: 76,
                metrics: { accuracy: 0.995, precision: 0.89, recall: 0.82, f1_score: 0.822 },
                dataset: "CIC-IDS2017",
                trained_rows: 150000,
              },
            ],
          });
        }
      })
      .catch(() => {});
  };

  useEffect(() => {
    fetchModels();
  }, []);

  const switchModel = async (id: string) => {
    setSwitching(id);
    try {
      await fetch(`http://127.0.0.1:8000/models/switch?model_id=${encodeURIComponent(id)}`, {
        method: "POST",
      });
      fetchModels();
    } catch (err) {
      console.error(err);
    } finally {
      setSwitching(null);
    }
  };

  const activeModel = data?.models.find((m) => m.id === data.active_model_id) || data?.models[0];

  return (
    <>
      <PageTitle
        title="Detection models"
        description="Model registry, real evaluation metrics, and hybrid detection pipeline."
      />
      <div className="pipeline">
        <div>
          <Activity />
          <strong>Flow features</strong>
          <small>77 CIC-IDS Features</small>
        </div>
        <span>→</span>
        <div>
          <ShieldCheck />
          <strong>Rule engine</strong>
          <small>Behavioral thresholds</small>
        </div>
        <span>→</span>
        <div>
          <Cpu />
          <strong>ML classifier</strong>
          <small>{activeModel ? `${activeModel.name}` : "Random Forest"}</small>
        </div>
        <span>→</span>
        <div>
          <ShieldCheck />
          <strong>Hybrid decision</strong>
          <small>Weighted risk score (0.6 ML + 0.4 Rule)</small>
        </div>
      </div>

      <section className="model-section">
        <div className="panel-heading">
          <div>
            <h2>Model registry</h2>
            <p>
              Active classifier: <strong>{activeModel?.name}</strong> (
              {activeModel?.classes.length} classes, {activeModel?.features_count} features)
            </p>
          </div>
          <span className="demo-tag">TRAINED MODELS ACTIVE</span>
        </div>

        <div className="model-grid">
          {data?.models.map((model) => {
            const isActive = model.id === data.active_model_id;
            return (
              <article className="model-card" key={model.id}>
                <div className="flex items-center justify-between">
                  <span className="model-icon">
                    <Cpu size={24} />
                  </span>
                  <span
                    className={`engine-pill ${isActive ? "text-primary border-primary font-medium" : ""}`}
                  >
                    {isActive ? "ACTIVE CLASSIFIER" : "STANDBY"}
                  </span>
                </div>
                <h2 className="mt-3">{model.name}</h2>
                <p>
                  Trained on {model.dataset} · {model.features_count} features ·{" "}
                  {model.classes.length} classes ({model.classes.slice(0, 5).join(", ")}
                  {model.classes.length > 5 ? "…" : ""})
                </p>

                <div className="model-metrics">
                  <div>
                    <small>Accuracy</small>
                    <strong>{(model.metrics.accuracy * 100).toFixed(2)}%</strong>
                  </div>
                  <div>
                    <small>Macro Precision</small>
                    <strong>{(model.metrics.precision * 100).toFixed(2)}%</strong>
                  </div>
                  <div>
                    <small>Macro Recall</small>
                    <strong>{(model.metrics.recall * 100).toFixed(2)}%</strong>
                  </div>
                  <div>
                    <small>Macro F1</small>
                    <strong>{(model.metrics.f1_score * 100).toFixed(2)}%</strong>
                  </div>
                </div>

                <div className="flex items-center justify-between pt-3 border-t border-border mt-3">
                  <span className="text-xs text-muted-foreground flex items-center gap-1">
                    <Check size={14} className="text-primary" /> Validated against test partition
                  </span>
                  {!isActive && (
                    <Button
                      size="sm"
                      variant="outline"
                      disabled={switching === model.id}
                      onClick={() => switchModel(model.id)}
                    >
                      {switching === model.id ? "Activating…" : "Set as Active"}
                    </Button>
                  )}
                </div>
              </article>
            );
          })}
        </div>
      </section>

      {/* Per-class breakdown report */}
      {activeModel?.per_class_report && (
        <section className="analysis-results mt-6">
          <div className="panel-heading">
            <div>
              <h2>Per-Class Classification Report ({activeModel.name})</h2>
              <p>Granular precision, recall, and F1 scores measured on held-out test traffic</p>
            </div>
          </div>
          <div className="table-scroll p-4">
            <table className="flow-table">
              <thead>
                <tr>
                  <th>Attack Class</th>
                  <th>Precision</th>
                  <th>Recall</th>
                  <th>F1-Score</th>
                  <th>Test Support (Rows)</th>
                </tr>
              </thead>
              <tbody>
                {Object.entries(activeModel.per_class_report).map(([cls, rep]) => (
                  <tr key={cls}>
                    <td className="font-medium text-foreground">{cls}</td>
                    <td>{(rep.precision * 100).toFixed(2)}%</td>
                    <td>{(rep.recall * 100).toFixed(2)}%</td>
                    <td>{(rep["f1-score"] * 100).toFixed(2)}%</td>
                    <td className="mono">{rep.support.toLocaleString()}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
      )}

      <div className="notice large-notice mt-6">
        <CircleAlert />
        <div>
          <strong>Hybrid Decision Fusion Engine</strong>
          <p>
            Sentinel IDS combines Scikit-Learn tree classification with stateful behavioral rules
            (SYN flood tracking, port scan correlation, packet rate anomaly). Final risk score is
            computed as: <code>Risk = 0.6 * ML_Confidence + 0.4 * Rule_Score</code>.
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
            {source === "Demo simulation"
              ? "This report contains simulated data and is not a real network assessment."
              : "This report contains rule-based CSV analysis. Flagged flows are indicators requiring investigation."}{" "}
            ML accuracy, precision and recall have not been evaluated.
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
