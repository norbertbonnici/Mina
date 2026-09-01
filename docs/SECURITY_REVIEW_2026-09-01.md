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

All remaining findings have now been verified: 26 were put to an independent skeptic reading the
code as it stands after the fixes above; 14 survived and 12 were refuted. After merging duplicates,
eleven distinct defects remain, listed below. Nothing that survived breaches a stated security
property directly — there is no open-proxy path, no route to corporate networks, no way for
suppression to engage without a distinct approver, and no governance action that proceeds unlogged.

## Verified and outstanding

### Fix before production

1. **HIGH — the suppression expiry sweeper stops the whole control plane.**
   `SensitiveSessionExpiryService.cs:36` catches only `InvalidOperationException` and
   `TimeoutException`, but the swept path throws `AuditWriteException` and `DbUpdateException` /
   `DbUpdateConcurrencyException` — and optimistic concurrency makes that conflict *expected*, since
   the sweeper and the agent's renewal write the same row. `BackgroundServiceExceptionBehavior`
   defaults to `StopHost`, so the escape takes down session issuance and renewal with it, and the
   deterministic ordering of due rows turns it into a crash loop. Widen the filter to any
   non-shutdown exception and isolate each request inside the sweep loop.

2. **MEDIUM — WORM anchoring is claimed but never computed, compared, or monitored.**
   `AuditChainVerifier` reads only the database, and `IAuditExportSink` has no read method, so no
   caller *could* compare an export to the chain: a privileged writer who rewrites the rows and
   recomputes the hashes forward gets `intact` from `/api/audit/verify`. Separately, `ExportAsync`
   anchors from the sink's high-water mark and treats an empty read as "nothing new", so a database
   restore silently stops anchoring for good with no log, event or metric. **Correct the claims in
   `AuditExportService.cs`, `Persistence/README.md` and `AuditEndpoints.cs` now**; add read-back and
   a tip check before go-live. The mechanism only has teeth once the sink is genuinely write-once,
   which needs the Azure immutable-blob container that `infra/terraform` does not yet define.

3. **MEDIUM — Envoy's admin interface is reachable *through the tunnel*.**
   Admin binds `127.0.0.1:9901`, and the forward proxy has no destination policy — `domains: ["*"]`
   with a bare `connect_matcher`, and nothing in the agent or sidecar constrains the CONNECT
   authority. A holder of a live session certificate can `CONNECT 127.0.0.1:9901` and reach
   `/config_dump`, `/certs` or `/quitquitquit`. The same gap puts IMDS (`169.254.169.254`) in reach
   on a node intended to carry a managed identity with Key Vault access. NSGs cannot help: neither
   address is subject to them. Move admin to a Unix socket, and raise a follow-up for an
   Envoy-enforced destination deny-list — fixing only the admin listener leaves IMDS open.

4. **MEDIUM — one oversized hostname discards a whole telemetry batch.** Nothing bounds hostname
   length on the ingest path, the column is `nvarchar(253)`, and the repository saves the batch in
   one unit of work — while the sidecar drops a failed batch by design. A local process using the
   agent's loopback proxy can therefore blind a node's hostname telemetry without manager approval
   and without the suppression audit trail. Bound it at ingest, exactly as `RegionName` now does.

5. **LOW — `JustificationReference` is unbounded against an `nvarchar(128)` column**, giving a 500
   where every other malformed input gives a 400. One line in the aggregate.

6. **LOW — retention is documented as implemented and is not.** Correct
   `LOGGING_AND_PRIVACY.md:74` and give retention an owning backlog row. Do not build a deletion job
   over the audit schema without its own ADR: C1 is hash-chained precisely so deletion is detectable.

### Fix when convenient

- **`EfAuditEventStore` relabels every `DbUpdateException` as a sequence conflict**, retrying a hard
  database fault five times and reporting the wrong cause. Fail-closed, so diagnostics only.
- **403/404 existence oracle** on session endpoints, contradicting the service's own comment. Ids are
  unguessable and probing is audited; a one-line consistency fix.
- **Expiry of a never-activated approval revokes the analyst's live, never-suppressed session.**
  Errs fail-closed, but teaches analysts to avoid the approved workflow. Gate the revoke on
  `request.ActivatedAt is not null`.
- **Undecided requests never lapse and the approver queue has no limit** — the only unbounded query
  in the codebase.
- **`MaxDuration` is unvalidated** and `RequestedDuration` is a SQL `time` column, so a configured
  window of 24 hours or more fails at the database rather than at startup.

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
