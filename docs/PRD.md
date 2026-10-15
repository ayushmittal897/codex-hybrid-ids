# Product requirements

## Purpose and users

Sentinel assists a college lab operator or junior analyst in investigating suspicious network flows using a trained classifier and transparent rules. The primary user reviews evidence, acknowledges alerts, records disposition and exports a report. The administrator manages approved models, thresholds, retention and sensor configuration.

Initial deployment is single-organization, local and passive. It observes traffic and produces evidence for a human; it does not block connections. Flow-based predictions cannot confirm encrypted authentication failure or guarantee detection of unseen attacks.

## Delivery levels

| Level | User outcome | Required proof |
|---|---|---|
| Existing demo | Explore interface and rule CSV analysis | Clearly marked simulation/rules-only; no ML claim |
| Release 1 CSV prototype | Submit compatible flow CSV, run real inference, investigate persisted results | Shared preprocessing, schema rejection, measured model card, backend/UI parity |
| Release 2 recorded traffic | Process authorized PCAP through pinned extractor | Feature-parity fixtures, provenance and replay evidence |
| Release 3 local pilot | Observe one approved subnet/interface | Visibility proof, sensor health, bounded load, analyst review and rollback |

## Functional acceptance

- Import jobs identify input checksum, schema, row counts, rejected rows and their reasons. A partial failure is visible; it cannot silently become a clean security assessment.
- Predictions include model version, preprocessing/schema version, class scores, rule evidence, decision policy version and source mode.
- Rules-only remains a browser-safe offline feature, distinctly labeled. Backend hybrid results are authoritative and are not recalculated by browser heuristics.
- Alerts support open, acknowledged, investigating, closed-benign and closed-confirmed dispositions, with actor, timestamp and notes. Acknowledgement does not change the original detector evidence.
- Model page shows actual metrics, test-set identity, support per class, limitations and promotion state. No metric is hardcoded from a marketing target.
- Operators can filter by time, source, destination, severity, detector and disposition; exports preserve provenance and protect spreadsheet consumers.
- Health distinguishes API availability, model availability, sensor heartbeat, stale data, capture drops, queue pressure and analysis failure.

## Proposed acceptance targets

These are engineering targets to validate, not current results or universal security guarantees. Benchmark gate: binary precision and recall each at least 0.90 and macro F1 at least 0.80 on a declared untouched test; require at least 0.80 recall for any named threat family advertised as supported, with sufficient independent test evidence. A high aggregate score never overrides a failing supported family.

Pilot gate: aim for no more than five actionable false alerts per analyst-day after deduplication, assessed over at least five representative workdays; agree the actual budget with the operator. Report benign flow count and raw false-positive rate too. At 100,000 benign flows/day, 0.1% FPR still yields about 100 false-positive flows/day before aggregation.

Performance gate: initial measured target 100 completed flows/second and p95 processing latency below one second after flow emission, at documented hardware/load. Record packet-to-alert latency separately because waiting for flow closure may dominate. Test overload behavior and data loss explicitly; zero silently lost jobs or alerts is required.

## Nonfunctional requirements

Use bounded memory/chunked input and versioned configuration. Reject incompatible schema before inference. Persist job/alert state across restarts. Keep payload collection optional and access-controlled. Bind local prototypes to loopback; before exposing to a LAN, add authentication, role enforcement, TLS and an explicit origin allowlist. Test backup restoration and previous-model rollback. No public cloud traffic upload is needed for the basic product.

## Out of scope for the first release

Automatic blocking, enterprise high availability, mobile app, installer, deep learning, guaranteed zero-day detection, encrypted payload inspection and claims of replacing a mature IDS. XGBoost/GPU comparison is optional after the CPU baseline and end-to-end prototype work.
