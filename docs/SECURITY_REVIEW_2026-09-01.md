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

## Fixed in the second pass

| # | Severity | Finding | Fix |
|---|---|---|---|
| 7 | high | Node identity was not bound to a region: the region came from the URL and body, the node policy was one region-agnostic role, and ingest never compared `batch.Region` to `session.Region`. Any node could read another region's allowlist and write browsing history against another region's analysts — the scoping THREAT_MODEL B4 names as the mitigation. | Nodes now carry a per-region grant (`Mina.Node.<region>` app role, assignable to a stamp's managed identity); both node endpoints refuse a region the caller was not granted, and a bare node role is entitled to nothing. Ingest rejects any item whose session belongs to a different region and raises `telemetry_region_mismatch` (high). |
| 8 | high | The sidecar tailed `/var/log/mina/envoy-access.log` while Envoy logged to stdout, so as deployed **no hostname telemetry would ever ship**. | Envoy now writes the access log to that file. The config-validation script, the interop test and the demo were all updated to follow it. |
| 9 | high | A control-plane HTTP timeout permanently stopped the agent's protected-path worker: the timeout arrives as `TaskCanceledException`, escaped the catch filter and broke the loop. It failed closed but never recovered without a restart. | The worker and the renewal path now treat a cancellation that is *not* the shutdown token as a transient failure: the path closes and the next tick retries; a renewal timeout drops the session, as a refusal does. |
| 10 | high | Suppression expiry was two transactions — the approval ended and committed, then the session revoke committed separately — so a failure in between left an expired approval with a live session still suppressed, past the window an approver granted (D-06). | An explicit `IUnitOfWork` commits the approval change and the session change together; activation, which likewise touches both, uses it too. |
## Confirmed but not yet fixed

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

## Deliberate residual risk

**Suppressed sessions' destinations still appear in Envoy's own access log on the node.** Envoy has
no per-session suppression (that is M2-3), so it logs every CONNECT authority; suppression is
applied by the sidecar before anything leaves the node and enforced again by the control plane.
The log is therefore a **short-lived buffer, not the telemetry of record** — mode 0750 directory,
consumed continuously by the sidecar. This does not match LOGGING_AND_PRIVACY §4 as written, which
says the node stops recording hostnames for a suppressed session. Eliminating it needs suppression
at Envoy itself; until then the document should be corrected to describe what actually happens, and
that correction is a decision for the project owner rather than something to change silently.

## Test gaps worth closing

- No test would catch removing `require_client_certificate` from the Envoy configuration; the
  client-authentication assertion covers the in-process stand-in only.
- No test asserts that a governance action **fails** when its audit write fails, so
  "no action proceeds unlogged" is claimed but unproven.
