# Security review — 2026-09-01

A multi-lens review of the whole codebase (ten independent lenses: fail-closed behaviour,
suppression enforcement, authorisation, audit integrity, certificates and mTLS, destination leakage,
persistence, IaC, test quality, and docs-vs-code). 46 findings were raised. The verification stage
was cut short by an infrastructure limit, so the highest-severity findings were verified by hand
against the code; the remainder are listed below as unverified.

## Fixed in this pass

| # | Severity | Finding | Fix |
|---|---|---|---|
| 1 | critical | The agent accepted **any** certificate issued by Mina's CA as the egress server — no name check, no purpose check. Every endpoint holds a session client certificate from that CA with its private key, so a redirected connection could be terminated by an impostor and research traffic read in clear. | `MtlsTunnelConnectionFactory` now treats a name mismatch as fatal and requires a serverAuth application policy. Two tests (impostor session certificate, wrong-host server certificate) were confirmed to fail without the fix. |
| 2 | critical | Approvals and denials made in the **management UI** were never written to the audit chain — the UI registered a null audit sink, and the UI is how approvals are actually made. | The UI now uses `PersistentSensitiveSessionAuditSink` with a real `AuditWriter` and store. Tests assert an approval and a denial each land in the chain with approver and request. |
| 3 | critical | The SigNoz scrubber skipped attributes whose value was not a `string`. The agent logs its CONNECT target as a struct, so research destinations reached the exporter — the exact leak the scrubber exists to stop (AC-014). | Both processors now inspect non-string values, and traces iterate `TagObjects`. Tests reproduce the struct-valued attribute for logs and spans. |
| 4 | high | Any authenticated user — including a plain analyst — could read the management UI's Sessions and Overview screens, disclosing every colleague's UPN, device id, region, and who was under an approved suppression. | Both screens now require the approver role. A test asserts an analyst receives 403 and sees no other analyst's identity. |
| 5 | high | The scrubber missed upper-case host names (`EXAMPLE.ORG`) and IPv6 literals. | Pattern extended: the final label may be uniformly upper or lower case, and an IPv6 branch requiring at least three colon separators (so clock times and ISO timestamps are untouched). |
| 6 | high | A client-supplied `region` reached a metric dimension and an audit field unvalidated: unbounded cardinality, a possible destination in operational telemetry, and — since audit precedes the action — a region long enough to overflow the audit payload let a caller **stop their own denial being recorded**. | `RegionName.IsWellFormed` bounds shape and length at both API boundaries before metrics or audit see the value. |

## Confirmed but not yet fixed

- **high — node identity is not bound to a region.** `NodeEndpoints` takes the region from the URL
  and body; the node policy is a single region-agnostic role; ingest never compares `batch.Region`
  to `session.Region`. Any node can read another region's allowlist and post telemetry against
  another region's sessions. THREAT_MODEL B4 names this control ("API scopes the node identity to
  its own region's allowlist") and it is not implemented.
- **high — the sidecar tails a file Envoy never writes.** Envoy is configured with
  `StdoutAccessLog`; the sidecar reads `/var/log/mina/envoy-access.log`; nothing connects them. As
  deployed, no hostname telemetry would ship at all.
- **high — suppressed sessions' hostnames remain in Envoy's own access log** on the node.
  LOGGING_AND_PRIVACY §4 says the egress node stops recording hostnames for a suppressed session; on
  the node itself it does not. Either apply suppression at Envoy or state plainly that the node log
  is short-lived, access-controlled, and not the telemetry of record.
- **high — a control-plane HTTP timeout permanently stops the agent's protected-path worker.** An
  HTTP timeout surfaces as `TaskCanceledException`, which escapes the worker's catch filter and
  breaks its loop. It fails closed, but never recovers without a service restart.
- **high — suppression expiry is two transactions.** The request is marked ended and committed, then
  the session revoke commits separately; a failure between them leaves an expired approval with a
  live session still in sensitive mode, past the approved window (contrary to D-06).
- **medium — device compliance is inferred from the presence of a `deviceid` claim**, which
  indicates Entra registration, not Intune compliance, while ARCHITECTURE §4 says the control plane
  validates compliance. Either check a real compliance signal or correct the document.
- **medium — retention is documented as implemented configuration** (LOGGING_AND_PRIVACY §7) but no
  retention code exists anywhere.
- **medium — WORM anchors are written but never compared back to the chain**, so the divergence
  detection the tamper-evidence design rests on is not implemented.
- **medium — `EfAuditEventStore` maps every `DbUpdateException` to a sequence conflict**, so a
  genuine database error becomes a silent retry.
- **low — session ownership returns 403 for another user's session and 404 for a missing one**,
  creating the existence oracle the code's own comment says it avoids.

Roughly thirty lower-ranked findings from the same review remain unverified.

## Test gaps worth closing

- No test would catch removing `require_client_certificate` from the Envoy configuration; the
  client-authentication assertion covers the in-process stand-in only.
- No test asserts that a governance action **fails** when its audit write fails, so
  "no action proceeds unlogged" is claimed but unproven.
