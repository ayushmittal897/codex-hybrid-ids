# UI and UX implementation design

## Preserve the interface

Keep the Sentinel sidebar, dark visual style, responsive tables, investigation dialog and seven leaf routes. Retain shared `WorkspaceProvider` state for the current view/session. Add a separate API/query layer for persisted server data; server-side detections remain authoritative. Follow the existing TanStack route layout and do not hand-edit the generated route tree.

## Route changes

| View | Keep | Required change |
|---|---|---|
| Overview | Summary cards and chart layout | Aggregate real observations; remove fixed sample series in real modes; list every observed category |
| Traffic | Search, filters, pagination | Server pagination, event time, null unknown fields, units and source provenance |
| Alerts | Investigation and acknowledgement | Persist disposition, actor/note/history; show ML/rule disagreement and quality issues |
| Analysis | Dropzone and validation feedback | Separate Browser rules / Model CSV / Recorded PCAP modes; expose job progress and rejected rows |
| Models | Registry cards | Actual bundle metadata, per-class support, split identity, schema and promotion status |
| Reports | Summary/export/print | Provenance, observation window, limitations, detector versions and adjudicated outcomes |
| Settings | Threshold editing | Server-validated versioned rules, rollback and sensor/retention settings |

## Honest states and field meanings

Use prominent source labels: DEMO, CSV RULES ONLY, CSV MODEL, PCAP REPLAY and LIVE SENSOR. Changing source starts a separate result set; never mix simulated and real events silently. Display API and sensor health separately. The current fixed "System operational" label is not sufficient for a pilot.

Display observed start/end separately from imported-at time. Where dataset IPs/timestamps are unavailable, show "Unavailable in source". Keep `packet_count`, `packet_rate_pps`, `byte_count` and `byte_rate_bps` separate. Allow unknown protocol/port; zero should not stand in for unknown. Align class labels and severity with backend enums rather than checking whether the engine string contains Demo.

For an alert, show what happened, where/when, evidence, score meaning, model/rule versions, data quality and analyst action. Keep supported/experimental class coverage visible. For disabled detectors show "Not evaluated". A connection failure should retain the last data with a stale timestamp and a retry action, never silently switch to demo mode.

## Usability and trust tests

Test keyboard upload/dialog operation, focus return, accessible status/error announcements and tables on narrow screens. Ensure criticality is conveyed by text/icons as well as color. Disable duplicate submits while a job runs; allow safe cancellation. Offer export with the same filters as the visible report and neutralize spreadsheet formula prefixes. The current UI row/size limits should remain visible even when backend modes gain different limits.

Integration test: import a known fixture, compare API and UI counts/labels, investigate an alert, acknowledge it, reload, verify persistence, export, then disconnect the service and verify stale/error presentation. Demo must still work offline independently of backend model availability.

Review external fonts and Lovable preview error hooks for local-only operation. Do not put raw packets, credentials or full imported rows into telemetry or error messages. UI build/lint/tests and a browser walkthrough are required before claiming the changes work; they have not been run during this documentation review.
