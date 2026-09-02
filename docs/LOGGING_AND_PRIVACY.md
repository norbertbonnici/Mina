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
| C1 Governance audit | auth results, session lifecycle, approvals, policy/admin, break-glass | On-premises SQL Server `audit` schema (append-only, hash-chained) + Azure immutable-blob anchors | Yes | No | **Never** |
| C2 Session metadata | user, device, session ID, region, timestamps, aggregate counters | On-premises SQL audit schema | In events | Counts only | **Never** |
| C3 Hostname telemetry | per-connection hostname/port/bytes (mina.hostname.v1) | On-premises SQL telemetry schema | **No** | **No** | Yes — sensitive sessions |
| C4 Full-URL telemetry | paths/queries | **Not collected** (exists only if ADR-0002 Option 2/3 ever approved) | No | No | Yes |
| C5 Operational telemetry | metrics/traces/logs, scrubbed of research content | SigNoz | No | Yes | n/a |
| C6 Justifications | sensitive-session justification references | On-premises SQL audit schema | Reference only | No | Never (but keep to case references, not content) |

**Residency (ADR-0006).** Every class above resides on FIAU infrastructure. Two things leave the
premises, neither of which carries research content: the CA signing key, generated and used inside
Azure Key Vault and never exported, and the audit export anchors — hash-chain checkpoints of C1,
written to Azure immutable storage precisely because tamper evidence anchored to a filesystem the same
administrator controls is not evidence. The egress nodes hold C3 only transiently before ingest, and
withhold destinations locally for a suppressed session.

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
- Expiry terminates the session when suppression was activated (D-06, as amended by D-06a
  2026-09-01: an approval that lapsed unused does not end the analyst's normal session); C1/C2
  remain complete throughout.
- No permanent exemptions.

## 5. Wazuh

Security/audit events per `docs/EVENT_SCHEMAS.md` §3: authentication failures, unauthorised
actions, policy changes, approval decisions, suspicious client state, egress-node security
events, suppression mismatches, and all break-glass use. **Wazuh never receives URL or hostname
content** — including for default sessions. Delivery is a local hop from the on-premises relay
(ADR-0006); no tunnel or public log endpoint is involved.

## 6. SigNoz

Operational telemetry per `docs/EVENT_SCHEMAS.md` §5: service health, latency,
tunnel/session establishment, egress capacity, component errors, integration health. A scrub
processor removes URL/hostname-shaped attributes before export; scrubber activity is itself a
metric (leak canary). AC-014 verifies with content scans.

## 7. Retention

Operating values set by the owner (D-09, 2026-08-31), forming the formal proposal for
ratification:

| Class | Retention |
|---|---|
| C3 hostname telemetry | **180 days** |
| C1/C2 governance audit + session metadata | **5 years** |
| C5 operational telemetry | **90 days** |
| C6 justification references | with C1 (5 years) |

**C3 is enforced; the rest is not.** M4-9 built the enforcement for hostname telemetry and left
the other classes alone, deliberately, because enforcement is not symmetrical across them:

| Class | Enforced by | State |
|---|---|---|
| C3 hostname telemetry | `TelemetryRetentionService`, swept every 6h | **Mechanism exists. Off unless configured** (see below) |
| C1/C2 governance audit | — | Not enforced; needs its own ADR (below) |
| C5 operational telemetry | SigNoz retention | SigNoz's own configuration, not this platform's |
| C6 justification references | with C1 | Not enforced |

**The C3 mechanism ships switched off.** `Mina:Telemetry:Retention:HostnameRetentionDays` has no
default, and unset means nothing is deleted. That is not an oversight: 180 days is a proposal
awaiting the ratification this section already requires, and deleting an analyst's browsing record
one day earlier than the approved period is as much a data-protection failure as keeping it a year
too long. Setting the value is a deployment decision with a name against it, and the platform logs
at Warning on every start where it is unset, so "not enforced" is a stated condition rather than an
absence someone has to notice. **A production deployment without this value set does not meet the
retention commitment.**

Deletion is itself audited (`telemetry_retention_applied`, EVENT_SCHEMAS §2), recording the cutoff
and the counts. Deletion is the one action in the platform whose evidence deletes itself: without
that event, a purged period and a period in which nothing was recorded look the same afterwards.

**C1/C2 governance audit is not enforced and is not scheduled to be.** The trail is append-only and
hash-chained, and its exports are anchors in write-once storage, so deleting from it has to be
designed rather than scheduled — an unanchored gap is indistinguishable from tampering. The same
reasoning applies to the audit export container: a storage lifecycle policy that expired old
anchors would be C1 deletion by another route, and the immutability policy on that container is
there precisely to refuse it. Both need their own ADR and DPO sign-off before any code is written.
Until then C1/C2 accumulates, which is the safe direction for a 5-year retention class in its first
year of operation.

Per REQUIREMENTS §5 these require legal/data-protection ratification before production; that
sign-off remains a production-gate item. No permanent exemptions.
