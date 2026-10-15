# Implementation plan and acceptance checklist

## Delivery strategy

As of 15 October 2026, the supplied rubric ends Phase III on 24 October and schedules exhibition for 26–31 October. A fresh ten-week schedule from the older planning report does not fit those dates. Prioritize a reliable CSV model-to-dashboard prototype for exhibition; add PCAP only if feature parity passes. Present live capture as pending if visibility or validation is incomplete. The dates below are proposed work targets, not a delivery guarantee; confirm the current university schedule with the guide.

## Completed in this review

- [x] Inspect existing model, UI, brief and rubric assets; identify actual integration gaps.
- [x] Scan eight local CSVs across all 2,830,743 rows; save numeric quality and label evidence.
- [x] Create the six requested core Markdown files plus detailed review/model/manual-step reports.
- [x] Add a reproducible audit tool and file-checksum inventory.

## Work breakdown

| ID / target | Work and concrete deliverable | Dependencies | Acceptance / owner |
|---|---|---|---|
| T01 / Oct 15–16 | Root environment, dependency lock, data ignores, runtime inventory | None | Fresh environment reproduces imports; no data/models/marks sheet accidentally published. Developer |
| T02 / Oct 16 | Feature/label schemas, duplicate/conflicting-label audit, split manifests | T01 | Exact counts, no cross-split duplicate groups, raw labels retained. ML developer |
| T03 / Oct 16–18 | Correct uniform bounded training sampler and fitted pipeline | T02 | Row cap and later-chunk sampling tests; train-only preprocessing; no artifact overwrite. ML developer |
| T04 / Oct 18–19 | Dummy/RF baselines, validation thresholds, untouched test and model card | T03 | Metrics/support/limitations, reload equality, CSV inference succeeds and rejects mismatches. ML developer |
| T05 / Oct 18–20 | Unify rules and decision semantics; implement evidence statuses | T02 | Missing data never matches, override consistency, chronological windows when metadata exists. Backend developer |
| T06 / Oct 19–21 | FastAPI jobs, approved model loader and SQLite history | T04, T05 | Fixture reaches persistent result; restart/idempotency/error tests pass. Backend developer |
| T07 / Oct 21–22 | Connect existing UI to jobs/models/alerts | T06 | No fake real-mode charts, UI/API result parity, persistent acknowledgement. Frontend developer |
| T08 / Oct 22–24 | Integrated tests, resource measurement, report/demo rehearsal | T07 | PRD gates documented; tested CSV demonstration and recovery on same laptop. Team |
| T09 / Oct 24–25 | Exhibition evidence freeze and backup | T08 | Reproducible run, short recorded demo, model card, poster and honest limitation list. Team + guide |
| T10 / after CSV gate | Pinned extractor and golden PCAP parity suite | T04, authorized capture inputs | Feature-by-feature parity; no invented endpoint metadata. Sensor developer |
| T11 / after PCAP gate | Authorized passive sensor and local shadow pilot | T10, network access | Five representative workdays of analyst review; measured drops/latency/alert budget. Operator + developer |
| T12 / after pilot gate | Security hardening, restore/rollback and optional model comparison | T11 | LAN access controls and operational acceptance; only then widen scope. Operator + developer |

Roles describe responsibilities, not assumed team membership. One developer can own multiple roles; the timeline depends on available hours. Network permission, SPAN configuration and source PCAP availability are external dependencies. A failed model or parity gate narrows scope; it must not be disguised by demo data.

## Tests that matter

| Area | Required evidence |
|---|---|
| Data | Duplicate/conflicting-label report; exact alias mapping; split membership; raw file hashes |
| Sampling | Cap applies to rows across chunks; seeded reproducibility; later-file inclusion; no test contamination |
| Model | Save/load prediction equality; pipeline input shape; rare/unknown coverage; invalid/missing schema rejection |
| Rules | Window boundaries; out-of-order data; unavailable inputs; disagreement; state limit/expiry |
| API | Upload bounds; invalid model ID; job failure/partial state; auth before LAN exposure; retry idempotency |
| Storage | Restart persistence; alert action audit; backup/restore; model rollback |
| UI | Build/lint/tests; import through investigation/export; accurate counts; disabled/stale source states |
| Sensor | Bidirectional visibility; known test-flow detection; packet-drop counters; extractor parity |
| Performance | Hardware and input rate; peak RAM; throughput; p50/p95 latency; queue depth and lost records |

## Proposed reproducible development workflow

Create a project-local Python environment with a supported Python version, install and lock the minimal chosen ML/API/test dependencies, and document the interpreter path. Suggested packages are pandas, NumPy, scikit-learn, joblib, FastAPI, Uvicorn, pytest and a database layer; these are not yet installed/locked project requirements. Add matplotlib only for figures and XGBoost only for a justified comparison.

The frontend has a Bun text lockfile. Prefer a compatible Bun runtime and `bun install --frozen-lockfile`, then `bun run test`, `bun run lint` and `bun run build` from `sentinel-ids-source`. Record runtime versions and actual outcomes. Do not silently regenerate dependency locks or bypass the existing release-age policy to make installation succeed. Verify the Lovable/Nitro output target for a local deployment; do not assume a Cloudflare-oriented output is a standalone local server build.

Legacy CLI commands below already exist, but require the correct Python dependencies and trusted compatible saved artifacts. They are not validated runnable in the current environment:

```powershell
python .\DOC-20261012-WA0010.py predict --data ".\your-compatible-flows.csv" --model-dir ".\models" --out ".\alerts.csv"
```

This command is limited to the legacy BENIGN/PortScan model and its documented 76-feature schema. It is not a multiclass or PCAP command. Do not run `hybrid_ids_multi.py` as the next production-training step until T02–T04 repair its sampling/evaluation/artifact behavior. Future package/API commands must be added to this document after implementation, rather than presented as existing entrypoints now.

## University evidence mapping

| Rubric | Marks | Evidence to prepare |
|---|---:|---|
| Phase I initiation | 10 | Problem, related work, scope, novelty and feasibility |
| Phase II planning/design | 10 | PRD, architecture, work breakdown, risks and guide review |
| Mid-term | 20 | Dated prototype and experimental evidence; verify submission status with guide |
| Phase III implementation | 20 | Working code, tests, measured performance, completed milestones |
| Exhibition/expert review | 10 | Reliable working demo, poster, explanation and honest limitations |
| Final report | 10 | Reproducible methods, results, ablations and discussion |
| Final presentation/demo/viva | 15 | Live walkthrough, technical reasoning and recovery demonstration |
| Research paper/patent/IPR as applicable | 5 | Guide-agreed submission/evidence; no invented publication claim |

Maintain a short contribution log with task ID, contributor, date, evidence link and outcome. Do not publish the supplied marks sheet or unrelated student identifiers as project evidence.
