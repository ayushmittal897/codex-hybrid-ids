# Model development and evaluation plan

## Decision

Build a reproducible CPU Random Forest baseline first. Preserve both existing model directories as historical experiments. Do not retrain into their paths. Promote a new model only after schema validation, independent evaluation and an inference smoke test. A GPU is not a prerequisite for this project; verify hardware separately before budgeting an XGBoost GPU experiment.

This is the training specification, not a newly trained model. No new weights or improved accuracy are claimed in this delivery.

## Measured dataset audit

All eight local files contain 79 columns including Label. The scan counted 2,830,743 rows, 15 raw labels, and 2,867 rows with at least one missing or infinite numeric value. Rate fields contain the observed invalid values. This does not count duplicate records, negative sentinel values, label errors or semantic extractor defects; those checks remain required.

| Raw label | Rows |
|---|---:|
| BENIGN | 2,273,097 |
| DoS Hulk | 231,073 |
| PortScan | 158,930 |
| DDoS | 128,027 |
| DoS GoldenEye | 10,293 |
| FTP-Patator | 7,938 |
| SSH-Patator | 5,897 |
| DoS slowloris | 5,796 |
| DoS Slowhttptest | 5,499 |
| Bot | 1,966 |
| Web Attack [replacement character] Brute Force | 1,507 |
| Web Attack [replacement character] XSS | 652 |
| Infiltration | 36 |
| Web Attack [replacement character] Sql Injection | 21 |
| Heartbleed | 11 |

These machine-learning CSVs do not provide the source IP, destination IP or timestamp needed for genuine session-level splitting and time-window rules. Destination Port alone cannot recover those fields. Request corresponding labeled flows/PCAPs when moving beyond the benchmark. The official dataset distinguishes these distributions: [UNB CIC-IDS2017](https://www.unb.ca/cic/datasets/ids-2017.html).

## Pipeline implementation sequence

1. Record SHA-256, source filename and original row number before any transformation. Keep raw data immutable. Normalize header whitespace, reject collisions, inspect missing labels and enumerate exact label strings.
2. Create `label_mapping.json` with exact supported raw aliases, preserving original labels in evaluation outputs. Suggested families: BENIGN; DoS_DDoS; PortScan; CredentialAttack (FTP/SSH and explicitly declared web brute force); WebAttack (XSS/SQL injection); Bot. Keep Infiltration and Heartbleed separate for research reporting. If a family has insufficient independent examples, mark it experimental/unsupported; do not claim that Other means novel-threat detection.
3. Define a versioned feature list. Exclude labels, IPs, timestamps and row/source identifiers from the model. Retain identifiers outside features for audit and rules. Investigate the duplicate `Fwd Header Length.1` and constant/redundant columns. Any data-driven feature selection uses training data only. RF does not need standardization; a logistic baseline does, inside its own pipeline.
4. Define canonical numeric parsing, infinity-to-missing handling and accepted sentinel values. Reject all-missing vectors. Treat unsupported negative values as quality failures, but document legitimate exporter sentinels rather than clipping all negatives blindly. Fit median imputation only on training; define how all-empty training columns retain/drop dimensionality and how inference enforces it.
5. Group exact feature duplicates before splitting, ignoring the target when defining groups; quarantine feature-identical rows with conflicting labels and report their count. Keep all members of a duplicate group in one partition. This is an integrity control, not proof that nearby flows are independent.
6. Freeze training/validation/test manifests before sampling or tuning. Sample only training; keep validation/test prevalence intact within their declared corpus. A row-shuffled deduplicated 60/20/20 baseline is acceptable only as a labeled benchmark experiment, never as evidence of live generalization.
7. Implement scenario/file holdout stress tests. CIC attacks are tied to particular days/files: a held-out class may be absent from training. Report train/test class support and unseen-class performance explicitly; do not silently remove that class to make scores look better. Once timestamps/session metadata are available, group by scenario/session and time with a separation gap appropriate to flow/window duration. See [scikit-learn cross-validation guidance](https://scikit-learn.org/stable/modules/cross_validation.html).
8. Replace the broken sampler with a seeded per-class reservoir or random-priority top-K stream over training rows across all eligible files. Track rows, not number of batch containers. Test no class exceeds K, later chunks can be selected, sample row IDs repeat for a fixed seed, and evaluation rows are never sampled into training. Start with up to 15,000/class to control runtime; choose final training prevalence/weights using validation evidence.
9. Fit a dummy/majority baseline and a bounded RF (starting experiment: 150 trees, depths 16/24, leaf sizes 2/5, fixed seed, at most four CPU workers). Measure runtime and peak RAM before increasing capacity. Try class weighting as an ablation. Keep the search small; architecture correctness is more valuable than a broad tuning sweep.
10. Fit imputation and model together in a pipeline. Tune decision thresholds on validation only. If calibrated probabilities are needed, use a separate/group-respecting calibration partition and record calibration metrics. Class balancing alters probability interpretation; raw tree vote fractions are not verified deployment probabilities. See [scikit-learn leakage guidance](https://scikit-learn.org/stable/common_pitfalls.html).
11. Evaluate locked candidates on the untouched test once, retaining row-level predictions. Report binary confusion counts, precision/recall/F1, FPR/FNR, PR-AUC, multiclass macro/weighted F1, per-class support and confusion matrices. Estimate uncertainty over independent sessions/scenarios when available; a three-row rare-class score is not reliable evidence.
12. Evaluate rules-only, ML-only and hybrid on identical inputs with identical target definitions. Bootstrap uncertainty on the difference where justified. Retain ML-only as the default if hybrid does not improve the agreed error/alert budget. Freeze a new policy after validation; do not select weights on test results.
13. Save a complete immutable run bundle and a schema-enforcing inference CLI. Test save/reload equality, missing/extra/shuffled columns, no BENIGN class, malformed values, all-missing rows, empty input and unsupported schema. Build backend integration only after these pass.

## Required model bundle

`pipeline.joblib`, `feature_schema.json`, `label_mapping.json`, `model_card.md`, `metrics.json`, `confusion_matrix.csv`, `test_predictions` with source locators, `split_manifest`, `training_config.json`, dependency lock/version report and a manifest with code/data/artifact hashes. Model card records data scope, intended use, disallowed claims, class limitations, thresholds, hardware, runtime, evaluation protocol and known failure modes. Hashing verifies consistency, not trust; load only approved artifacts from controlled local storage. Never accept uploaded pickle files. Cross-version scikit-learn loading is unsupported: [model persistence guidance](https://scikit-learn.org/stable/model_persistence.html).

## Feature parity and real data

Select one extractor/version and record its build, settings and time units. Prepare small authorized golden PCAPs with bidirectional TCP, UDP, single-packet flows, retransmissions, resets, zero-duration cases and long-lived sessions. Extract twice and test deterministic outputs; compare each feature against a trusted reference/hand calculation with justified tolerances. Record packet counts and capture drops. Reject schema-compatible but semantically incompatible extractors.

If reproducing CIC semantics is not dependable, choose a smaller feature schema the live sensor reliably emits, re-extract labeled PCAPs with that sensor and retrain. Do not rename Suricata/Zeek columns to pretend they are CIC features. Suricata's [EVE JSON output](https://docs.suricata.io/en/suricata-8.0.2/output/eve/eve-json-output.html) is useful corroborating evidence with its own schema.

Acquire representative local benign flows across normal browsing, backups, updates, meetings, development and authorized administration. Collect separate authorized scenario captures and maintain scenario start/end, endpoints, expected behavior and provenance. Authentication server logs are needed to corroborate credential-failure claims; encrypted packet flows alone do not establish them. Hold out later days for local evaluation, and never feed analyst labels directly into automatic online retraining.

## Promotion and rollback

Promotion requires the PRD gates, passing schema tests, a model card and an operator-reviewed pilot. Rare classes can remain experimental without preventing a narrowly scoped binary detector, but the UI/report must display that limitation. Keep the previous approved bundle and policy version. Roll back on schema drift, sustained alert-budget breach, unexplained latency/data loss or corrupted artifacts. No automatic retraining/promotion in the first release.
