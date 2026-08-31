# Logging and Privacy Design

Status: updated with data classes and enforcement semantics. Collection method **decided**
(D-01, 2026-08-31): hostname-level at the egress, no TLS interception (ADR-0002 Option 1).

## 1. Default policy

Default research sessions generate:
- user and device identity;
- session ID;
- start/end timestamps;
- selected egress region and public egress identity;
- authentication/authorisation results;
- policy and administrative events;
- approved URL/hostname telemetry level (per D-01).

## 2. HTTPS constraint

For HTTPS, full URL paths are not visible to a network egress layer without browser
instrumentation or TLS interception. The project must not silently add TLS decryption. The
realistic choices, analysed in ADR-0002: hostname/domain-level telemetry without interception
(recommended); browser-originated URL telemetry (higher privacy impact and tamper surface —
future ADR + DPO only); TLS inspection (not recommended for this project; own ADR + legal if
ever tabled).

A specific FIAU sensitivity drives the recommendation: URL paths/queries frequently identify
*research subjects*. Hostname-level telemetry provides accountability with far lower
subject-inference risk.

## 3. Data classes

| Class | Content | Store | Wazuh? | SigNoz? | Suppressible? |
|---|---|---|---|---|---|
| C1 Governance audit | auth results, session lifecycle, approvals, policy/admin, break-glass | SQL `audit` schema (append-only, hash-chained) + WORM export | Yes | No | **Never** |
| C2 Session metadata | user, device, session ID, region, timestamps, aggregate counters | SQL audit schema | In events | Counts only | **Never** |
| C3 Hostname telemetry | per-connection hostname/port/bytes (mina.hostname.v1) | SQL telemetry schema | **No** | **No** | Yes — sensitive sessions |
| C4 Full-URL telemetry | paths/queries | **Not collected** (exists only if ADR-0002 Option 2/3 ever approved) | No | No | Yes |
| C5 Operational telemetry | metrics/traces/logs, scrubbed of research content | SigNoz | No | Yes | n/a |
| C6 Justifications | sensitive-session justification references | SQL audit schema | Reference only | No | Never (but keep to case references, not content) |

Access to C3 (and C6) is role-restricted and **itself audited** (threat N10: telemetry must not
become an unsupervised instrument against analysts).

## 4. Sensitive-session suppression

- Analyst submits justification reference and requested duration; manager (≠ requester)
  approves/denies via the management interface; approval is time-bound (ADR-0003).
- Suppression is **authoritative in the control/logging plane**: under D-01 Option 1 the egress
  node stops recording C3 for the flagged session and emits suppression markers + aggregate
  counters. The endpoint plays no enforcement role. If browser-originated telemetry is ever
  adopted, enforcement becomes dual (client instructed to stop *and* server drops regardless).
- Node acknowledgement is verified; a control-plane/node mismatch raises a critical event (N5),
  and any records mis-collected during an approved suppression window are purged under a
  DPO-supervised procedure.
- Expiry terminates the session (proposed default, D-06); C1/C2 remain complete throughout.
- No permanent exemptions.

## 5. Wazuh

Security/audit events per `docs/EVENT_SCHEMAS.md` §3: authentication failures, unauthorised
actions, policy changes, approval decisions, suspicious client state, egress-node security
events, suppression mismatches, and all break-glass use. **Wazuh never receives URL or hostname
content** — including for default sessions.

## 6. SigNoz

Operational telemetry per `docs/EVENT_SCHEMAS.md` §5: service health, latency,
tunnel/session establishment, egress capacity, component errors, integration health. A scrub
processor removes URL/hostname-shaped attributes before export; scrubber activity is itself a
metric (leak canary). AC-014 verifies with content scans.

## 7. Retention

Operating values set by the owner (D-09, 2026-08-31), implemented as configuration per data
class and forming the formal proposal for ratification:

| Class | Retention |
|---|---|
| C3 hostname telemetry | **180 days** |
| C1/C2 governance audit + session metadata | **5 years** |
| C5 operational telemetry | **90 days** |
| C6 justification references | with C1 (5 years) |

Per REQUIREMENTS §5 these require legal/data-protection ratification before production; that
sign-off remains a production-gate item. No permanent exemptions.
