# Detection rules and decision policy

## One meaning per rule

The current browser rules and Python rules are different engines. Preserve the browser's offline rules-only mode. Implement versioned production rules in Python and expose their evidence through the API. Do not imply that the browser's SYN-count threshold of 100 is equivalent to the Python rate threshold of 1,000 packets/second with no responses.

Each rule returns `matched`, `not_matched`, `not_evaluable` or `disabled`, plus rule version, required inputs, event window, measured values, threshold and explanation. Absence of evidence cannot be encoded as zero. Disabling rules or failing ML must produce an explicitly degraded/unassessed state.

## Initial proposed rules

| Rule | Required evidence | Starting behavior | Important limit |
|---|---|---|---|
| Port scan | Source/destination, destination port, event timestamp | Count distinct ports per source/target within trailing 60 seconds; investigate at 20 | Proposed starting values; tune for legitimate scanners and admin traffic |
| Host sweep | Source, target addresses, timestamps | Count distinct targets in trailing window | Separate from port count; not validated by current CSV |
| SYN flood indicator | SYN count/rate, responses, duration, destination | Aggregate destination-oriented SYN/no-response activity | Count semantics depend on extractor; one SYN is not proof of flood |
| High packet rate | Valid packets/second | Flag rate anomaly above configured local baseline/threshold | Backups/video and short flows cause benign spikes |
| Credential suspicion | Repeated connections and optional authentication failure logs | Connection-only anomaly; elevate with correlated failed-login evidence | Cannot assert password failures from TLS/SSH flow size alone |

The current per-flow scan heuristic is a weak fallback indicator, not a confirmed scan. Keep that distinction in the UI. DDoS classification needs aggregation across sources and target/service context; a high rate in one flow is insufficient proof of distribution.

## Window and resource behavior

Use event time, not import time. Replay chronologically, record tolerated lateness, and do not use future events to classify earlier ones. Key state by sensor and network context so private IP reuse across networks does not collide. Use bounded TTL maps, explicit memory limits and overflow counters. Deduplicate replay IDs and merge related alerts into incidents without discarding raw evidence. Approved-scanner suppressions require scope, owner, expiry and an audit trail; never use permanent broad allowlists casually.

## Decision policy to validate

Start with an interpretable policy: alert when a validated high-confidence rule matches OR the validated ML attack threshold is exceeded. Otherwise keep the observation available as unflagged, unassessed or unsupported according to quality/coverage. Record both channels even when they disagree. Choose severity from evidence and asset context under a versioned policy; a 0–100 rank is not attack probability.

This OR policy may increase false positives and is only a candidate for validation. Compare it with ML-only and weighted fusion on the same held-out set. If weighted fusion wins the operational tradeoff, document why, weights and thresholds. Never let textual override, severity and `is_alert` disagree as the legacy script can.

Test exact threshold boundaries, missing inputs, rule-disabled state, stale/out-of-order events, IPv4/IPv6, restarted sensor state, NAT/shared sources, benign high-rate transfers, ML-benign/rule-positive disagreement and model-unavailable behavior. Do not infer that one connection anomaly confirms compromise.
