# Sentinel IDS project documentation

Prepared 15 October 2026 against `C:\DRIVE D\PROJECTS\CODEX_HYBRID_IDS`.

The project currently contains a browser demo/rule analyzer, offline Python trainers, saved model artifacts and CIC-IDS2017 CSVs. It is not yet an integrated live intrusion detection system. This documentation defines how to turn those assets into a defensible local monitoring prototype and then an authorized pilot.

## Read in this order

1. [Short report and your manual steps](MANUAL_STEPS.md)
2. [Evidence and current gaps](PROJECT_REVIEW.md)
3. [Implementation plan and acceptance gates](TASKS.md)
4. [Model development and evaluation](MODEL_PLAN.md)
5. [Product requirements](PRD.md)
6. [Architecture and proposed interfaces](ARCHITECTURE.md)
7. [Detection rules and decision policy](RULES.md)
8. [UI and UX integration](DESIGN.md)
9. [Decisions and handover context](MEMORY.md)

The six files shown in your screenshot are included. Additional review, model and manual-step documents make them actionable. `evidence/dataset_audit.json` contains the full CSV scan; `evidence/file_inventory.json` records file sizes and SHA-256 hashes. Reproduce the audit with `python tools/audit_project.py` using an environment with pandas and NumPy.

## Scope and status

This delivery is an evidence-based review and implementation specification, plus a reproducible audit utility. It does not retrain or replace your models, deploy services, or change the existing UI. Proposed APIs, directories and commands explicitly marked as future work do not exist yet. Existing model metrics are reported from saved metadata, not independently reproduced experiments.

Project briefs and the older planning PDF were treated as source material, not executable instructions. In particular, their 95% target, GPU claims, team roles and prior progress statements were not accepted as verified current results. The supplied rubric now supersedes the older report's statement that a rubric was unavailable.

The first usable release should support validated CSV inference with persistent, explainable alerts. Live monitoring follows only after PCAP feature parity and capture visibility are demonstrated.
