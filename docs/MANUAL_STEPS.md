# Short report and steps required from you

## Where the project stands

You already have the CIC-IDS2017 dataset, trained experimental artifacts and a useful Lovable UI. You do not need to redesign the dashboard or buy a GPU to start. You need a corrected, reproducible model pipeline, a Python inference API, persistent alerts, and then a validated traffic extractor.

The existing multiclass model reports 99.54% accuracy but only 33.17% WebAttack recall. Its sampler also fails to enforce its intended row limit. The UI currently uses demo data or browser rules, not those saved models. These are the first implementation priorities, not evidence that the project must be discarded.

The review scanned all 2,830,743 local dataset rows. There are 15 raw labels, only 36 Infiltration rows and 11 Heartbleed rows, and 2,867 rows with missing/infinite numeric values. Rare attack classes cannot support strong real-world claims from this data alone.

## Your manual checklist

| When | What you need to provide/do | Why |
|---|---|---|
| Now | Confirm guide/exhibition dates and how many team members/hours are available | Choose realistic scope before October 24 |
| Now | Confirm development machine RAM, CPU, free SSD space and intended OS for deployment | Bound training and capture resources; GPU optional |
| Before live capture | Obtain network-owner approval covering subnet, devices, capture window and retention | Establish the actual permitted pilot environment |
| Before live capture | Arrange an isolated lab/VM network or a managed switch mirror/TAP with the network administrator | A normal laptop NIC does not see the whole campus |
| Before PCAP support | Supply/download authorized PCAPs and corresponding labels/scenario schedule from a trusted source | Current ML CSVs cannot reconstruct missing IPs/timestamps or packets |
| Before pilot | Identify an analyst/operator and acceptable false-alert workload | Thresholds need an operational budget |
| During pilot | Label a small reviewed set as benign, confirmed incident or uncertain, with evidence | Measure usefulness and avoid treating predictions as ground truth |
| Before LAN deployment | Arrange certificates/login access and agree flow/PCAP retention and backup storage | Protect operational data and make access/recovery manageable |
| Before submission | Rehearse demo, confirm evidence with guide and record team contributions | Meet rubric requirements with a working, explainable result |

You do not need to manually label millions of benchmark rows, manually calculate 77 features or keep uploading the dataset into the web UI. Feature extraction and training should be automated. You do need to supply access/context that code cannot invent.

## What real data is required

1. **Already available: benchmark flows.** Use existing CIC CSVs to establish a controlled offline baseline. They are historical benchmark data, not your network's current traffic.
2. **Next: packets with trustworthy scenario context.** Use official labeled PCAPs where available or authorized lab recordings. Retain capture start/end, timezone, endpoints, scenario description, exporter version and hashes. Validate labels against the scenario schedule; do not blindly join rows by position after changing extractors.
3. **Before deployment: representative local benign traffic.** Begin with a few representative workdays and extend to cover backups, updates and peak usage. Later unseen days are the local test. An initial planning allowance of 5–10 workdays is a collection target, not statistical proof of readiness.
4. **For credential claims: host/service authentication logs.** Correlate failed logins by time/host/service with network evidence. Treat encrypted connection patterns alone as suspicion.
5. **Optional corroboration: existing IDS events.** Suricata EVE can supplement evidence, but its verdicts are not automatic ground truth and its fields do not replace CIC features.

Do not purchase hardware yet. First measure offline training RAM/runtime and confirm where packets can be observed. A starting planning estimate is a modern CPU, 16 GB RAM and tens of GB of free storage for the development/lab machine; actual requirements depend on model and capture rate. Full packet capture at 100 Mbit/s sustained is roughly 45 GB/hour before format overhead, so retention/filtering must be designed around measured traffic.

## Real operational workflow after implementation

1. The operator selects an approved source/interface and sees a successful heartbeat plus known test traffic.
2. The sensor collects authorized traffic and produces completed bidirectional flows under the pinned schema. Capture loss and incomplete flows are reported.
3. The validator rejects incompatible data; the saved preprocessing and classifier produce model scores, while rules evaluate available evidence.
4. The policy creates a reviewable alert with endpoints/time when available, model/rule versions and reasons. Storage preserves it across restarts.
5. The analyst reviews the evidence, checks expected backups/scans/service logs, then records a disposition. Confirmed incidents follow the institution's response process; the prototype does not automatically block devices.
6. The daily report shows alert workload, confirmed/false/uncertain outcomes, gaps, stale sensors and processing loss. The team tunes on validation evidence and tests changes before promotion.

## Exhibition fallback

If live parity is not ready, demonstrate a real model on a declared held-out compatible CSV, show rule/ML/hybrid evidence and persist/export an alert through the UI. Explain unavailable endpoint fields honestly. A measured offline prototype is a valid engineering milestone; a simulated screen is not proof of real-time network protection.

This delivery creates the review and implementation documentation plus audit evidence. Model retraining, backend/UI integration and live capture remain the implementation tasks in [TASKS.md](TASKS.md).
