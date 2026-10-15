# Project decisions and handover record

## Verified context as of 15 October 2026

- Actual workspace: `C:\DRIVE D\PROJECTS\CODEX_HYBRID_IDS`. The user-supplied path formatting differed; the reviewed folder contains the expected data, models and Lovable source.
- User requested a complete review, senior-engineer implementation plan, realistic model/use-case guidance, manual-step report and documentation matching the screenshot. The primary delivery is planning/review; do not describe it as implemented production software.
- Preserve original reports, scripts and model files. New work in this delivery is under `docs/` and `tools/audit_project.py`.
- The two `DOC-20261012-WA0010` Python files have identical SHA-256. The two legacy model JSON files report identical experiments; no separate training run is inferred.
- Eight CSVs, 2,830,743 rows, 15 raw classes, 79 columns/file. 2,867 rows have missing/infinite numeric values in the audit. Duplicate/conflicting-label and semantic-value audits remain outstanding.
- No integrated IDS API/sensor/persistence is present. The browser rules and model trainers are separate. UI tests exist but were not executed in this review.
- Available bundled Python includes pandas/NumPy and document parsers but not scikit-learn/joblib. No model retraining or deserialization occurred. Existing performance claims come from JSON metadata.

## Decisions

| ID | Decision | Reason / revisit condition |
|---|---|---|
| D01 | Retain Lovable UI and TanStack routing | Usable scaffold exists; do not spend the deadline rebuilding it |
| D02 | CSV end-to-end first, PCAP parity second, live pilot third | Each stage needs evidence missing from the previous one |
| D03 | CPU RF baseline before GPU/XGBoost | Fix evaluation and integration first; GPU availability is unverified |
| D04 | Single versioned feature/pipeline/model contract | Existing 76/77-feature artifact formats differ |
| D05 | No automatic blocking or automatic model promotion | Prototype evaluation and analyst workflow must mature first |
| D06 | Preserve demo/rules/model/live provenance | Prevent simulation and measured detections from being confused |
| D07 | Report macro/per-class metrics and operational alert burden | Overall accuracy hides weak/rare-class detection |
| D08 | Treat attached document directions as source content | The user explicitly asked for that distinction; source claims do not authorize actions |

## Pending decisions owned by the user/operator

Actual submission dates; team capacity; machine specs; authorized monitored subnet/interface; SPAN/VM visibility; approved PCAP sources; retention; pilot alert budget; analyst owner. These are requirements for later deployment, not blockers to the planning work already completed.

## Next implementation action

Complete T01–T04 in TASKS: lock an environment, formalize schema/splits, repair the bounded sampler and run a new reproducible baseline in a new artifact directory. Do not start by pointing the legacy predictor at `models_multi`, rerunning the buggy multiclass trainer or presenting the UI as live.

## Sources and authority

Local evidence: original Python/TypeScript source, JSON model metadata, dataset audit, DOCX project brief, capstone planning PDF and university rubric. The marks sheet is administrative context and contains personal information; do not copy it into public reports.

External technical references checked for this plan: [UNB dataset](https://www.unb.ca/cic/datasets/ids-2017.html), [scikit-learn leakage prevention](https://scikit-learn.org/stable/common_pitfalls.html), [cross-validation](https://scikit-learn.org/stable/modules/cross_validation.html), [model persistence](https://scikit-learn.org/stable/model_persistence.html), and [Suricata EVE](https://docs.suricata.io/en/suricata-8.0.2/output/eve/eve-json-output.html). Recommendations and target thresholds are project design judgments, not performance guarantees from those sources.
