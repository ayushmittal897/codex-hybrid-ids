# Project review and readiness report

## Assessment

Retain the existing Lovable interface and Python experiments. The missing integration, feature contract and evaluation controls are more important than adding another model algorithm. The realistic initial use case is analyst-assisted review of network-flow files in a college lab. A small monitored VLAN is the next stage; enterprise protection and automatic blocking are outside the demonstrated capabilities.

## Review coverage

Reviewed the four root Python scripts, all saved JSON model metadata, application-specific UI components, routes, tests, runtime/error wrappers, configuration and project prose. Inventoried the shared UI library, lockfile and static assets, with targeted checks of data handling and unsafe HTML construction; this was not a line-by-line dependency security audit. The source tree contains 46 reusable UI component files. All eight CSV files were scanned in chunks across all rows and numeric columns by the accompanying utility. Exact duplicates and conflicting labels are not counted by that audit and remain model-pipeline work.

Read the four-page capstone report, one-page university rubric and the DOCX brief. The 13-page marks sheet was text-inspected for project context; it contains unrelated student contact information and is not reproduced in the new documentation. The supplied screenshot establishes the desired documentation structure. Model pickle files and confusion-matrix images were inventoried; the pickle objects were not executed/deserialized and the images were not used to independently validate metrics. Saved metadata is the source for the performance numbers below.

## Asset map

| Asset | Actual role | Decision |
|---|---|---|
| `MachineLearningCSV/MachineLearningCVE` | Eight historical labeled flow CSV files | Preserve raw; version audit and split manifests |
| `DOC-20261012-WA0010.py` | RF/optional XGBoost trainer, rules, fusion, CSV predictor | Refactor into one tested engine |
| `DOC-20261012-WA0010_backup.py` | Byte-identical backup of that script | Preserve; do not maintain a second engine |
| `hybrid_ids_multi.py` | Multiclass RF training with imputation | Correct sampler and evaluation before promotion |
| `inspect_labels.py` | Label counts only | Complement with new complete numeric audit |
| `models` | BENIGN/PortScan model, 76 features | Legacy experimental baseline |
| `models_portscan_backup` | Same reported metadata as `models` | Backup, not evidence of a separate experiment |
| `models_multi` | Eight grouped classes, 77 features | Experimental; incompatible with legacy predictor |
| `sentinel-ids-source` | TanStack Start/React/TypeScript UI | Reuse navigation, components and visual design |
| DOCX brief | Motivation and intended threat scope | Requirements input; not performance evidence |
| Capstone report PDF | Earlier proposal | Retain architecture ideas; update schedule/evidence |
| Rubric PDF | Dates and assessment allocation | Drive delivery gates and evidence collection |

## Findings prioritized by impact

| Priority | Evidence | Impact and required resolution |
|---|---|---|
| P0 | `load_dataset` uses `len(samples.get(category, []))`, where each element is a batch | 15,000 cap is not a row cap. Eight classes should permit at most 120,000 selected rows, but metadata reports 490,623. Use a uniform bounded sampler over the intended training partition and test its limits. |
| P0 | Both trainers use random row train/test splits | Correlated sessions can cross partitions. Deduplication alone does not prove independence. Preserve source/scenario groups, create validation set and document unavailable grouping information. |
| P0 | No inference call in UI; `ModelsPage` explicitly says not connected | Dashboard cannot use local `.pkl` files. Add Python service and explicit result provenance. |
| P0 | No PCAP or capture adapter in source | Live deployment has no measured feature parity or visibility. Establish recorded-PCAP extraction before live mode. |
| P1 | Multiclass artifact uses imputer/string classes; legacy predictor requires scaler/label encoder/different filenames | Pointing the existing CLI at `models_multi` fails. Introduce one versioned bundle/loader; never mix artifact directories. |
| P1 | `normalize_label` checks `brute force` before `web attack` | Web brute-force flows become BruteForce, while XSS/SQL injection become WebAttack. Publish an explicit mapping and preserve original labels. This may be intentional taxonomy, but currently obscures comparisons. |
| P1 | Legacy train drops missing rows; predict uses `fillna(0)` | Training/inference missing-data behavior differs. Use one fitted preprocessing pipeline with quality checks. |
| P1 | Legacy cross-flow scan groups all rows by source without timestamps/window | Decision depends on input batch size and can include future traffic. Use event-time windows and bounded state. |
| P1 | `_col` returns zero when a rule feature is absent | Missing backward packets can look like no response. Missing evidence must produce `not_evaluable`, not a match. |
| P1 | Rule override changes prediction text while risk remains `0.6*ML+0.4*rule` | A strong rule with ML score 0 produces risk 0.4, below alert threshold 0.5. Define one authoritative alert decision and test disagreements. |
| P1 | UI assigns packet rate to `packets`, byte rate to `bytes`, now to flow timestamp, defaults protocol to TCP | Rate/volume and event-time semantics are lost. Separate fields and preserve unknown values. |
| P1 | UI rule toggle off produces `Benign` | Disabled detection is not evidence of benign activity. Show `not evaluated`. |
| P1 | Browser download uses Papa.unparse without formula escaping | Analyst-exported untrusted strings may be spreadsheet formulas. Escape formula prefixes and test exports. |
| P2 | UI overview uses fixed time series and fixed attack category list | CSV findings such as Packet Rate Anomaly are omitted from the donut categories; replace with real grouped data. |
| P2 | Browser state only; no auth, backend database or audit trail | Acknowledgements and rules disappear on reload. Persist versioned configuration and alert actions. |
| P2 | `rows_scanned` is null; library versions/splits/hashes absent in legacy metadata | Old runs cannot be reliably reconstructed from artifacts alone. Save provenance for every future run. |

Do not treat the shared chart component's `dangerouslySetInnerHTML` alone as an exploitable vulnerability: it builds CSS from chart configuration. Keep imported traffic strings out of that configuration and validate any future user-controlled colors/IDs. Error reporting hooks and Google-hosted fonts also need review before an offline/private deployment; no transmission of raw traffic was observed in the application code inspected.

## What the saved metrics actually say

| Model/result | Saved measure | Interpretation |
|---|---|---|
| Legacy PortScan ML | Accuracy 99.9906%; F1 99.9890% | One file, two classes, random held-out rows |
| Legacy PortScan rules | FPR 37.9012% | Too noisy to promote directly |
| Legacy PortScan hybrid | F1 99.9835% | Slightly below ML-only in this experiment; no demonstrated hybrid advantage |
| Multiclass | Accuracy 99.5441%; macro F1 82.2254%; macro recall 77.6949% | Overall accuracy hides class weaknesses |
| WebAttack | Recall 33.1683%; F1 37.3259%; test support 202 | Roughly two-thirds of this grouped class missed |
| Infiltration | Recall 54.5455%; support 11 | Too little evidence for a deployment claim |
| Other | Recall 66.6667%; support 3 | Not a validated unknown-attack detector |

These are historical metadata values. Balanced sampling and changed taxonomy will change prevalence and metrics; do not directly rank new runs against these without a common test set.

## Verification performed and limits

Python syntax parsing passed for all four original scripts. The audit utility ran against real local data; consult its JSON output for measured counts. Frontend tests/build were not run: project `node_modules` is absent. The available bundled Python has pandas/NumPy but no scikit-learn/joblib, so training and saved-model inference were not executed. No evidence currently verifies capture, API availability, throughput, GPU capability or live detection. The earlier PDF's RTX 4050 statement is an unverified source assertion on this task.

The source snapshot contains no root Python environment lock/requirements file and no integrated IDS backend. Treat proposed tooling as work to implement, not a completed capability.
