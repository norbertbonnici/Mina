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
## Fixed in the third pass (the "before production" set)

| # | Severity | Finding | Fix |
|---|---|---|---|
| 11 | high | The expiry sweeper's catch filter named two exception types the path does not throw, so the one it does — a concurrency conflict on a row the agent is renewing — escaped. `BackgroundServiceExceptionBehavior` defaults to `StopHost`, so an ordinary conflict took session issuance down with it, and the deterministic ordering of due rows made it a crash loop. | The loop now catches anything that is not shutdown. The sweep was also restructured to expire each approval in **its own scope and unit of work**: a per-request `try`/`catch` over a shared context isolates nothing, because a rejected `SaveChanges` leaves the failed change tracked and every later commit in the sweep re-attempts it. Three tests, one of which fails against the old shared-scope design. |
| 12 | medium | WORM anchoring was claimed in three places but never computed or compared. `IAuditExportSink` had no read method, so nothing *could* compare an export to the chain: a writer who rewrote the rows and recomputed the hashes forward got `intact` from `/api/audit/verify`. `ExportAsync` also treated a store behind its own anchors as "nothing new". | `AuditAnchorVerifier` re-renders each anchored range from the current chain and compares it against the bytes in storage, and against the hash the chain records for them. Reported by `/verify` as separate fields, never folded into `Intact`. Export now raises `AuditAnchorException` when the store ends below the anchors. The render format is shared between writing and verifying so a formatting change cannot masquerade as tampering. A test performs the wholesale rewrite: the chain check passes, the anchor check catches it. |
| 13 | medium | Envoy's admin interface bound `127.0.0.1:9901` and the forward proxy had no destination policy, so a live session certificate could `CONNECT 127.0.0.1:9901` for `/config_dump`, `/certs` or `/quitquitquit` — and reach IMDS at `169.254.169.254` for managed-identity tokens to this node's Key Vault. | Admin moved to a Unix socket (`RuntimeDirectory=mina`, mode 0600), which is not addressable through CONNECT at all. An RBAC filter additionally denies loopback, link-local, RFC 1918, CGNAT and IPv6-literal authorities, and logs the refusal. Five interop cases against a real Envoy confirm the denial; the residual (a public name resolving into private space) needs a host firewall — backlog M4-10. |
| 14 | medium | Nothing bounded hostname length at telemetry ingest against an `nvarchar(253)` column, and the batch is one unit of work the sidecar discards on failure — so a local process could blind a node's telemetry with no approval and no audit trail. | Ingest rejects over-length hostnames per item and counts them (`Rejected`, surfaced in the node response and as a metric dimension), leaving the rest of the batch to record. |
| 15 | low | `JustificationReference` was unbounded against an `nvarchar(128)` column, giving a 500 where every other malformed input gives a 400 — and, since audit precedes the action, an event for a request that never existed. | Bounded in the aggregate, with the EF configuration pointing at the same constant. |
| 16 | low | Retention was documented as implemented configuration; no retention code exists. | `LOGGING_AND_PRIVACY.md` §7 now states plainly that the values are decided and not enforced, and that C1/C2 audit deletion needs its own ADR and DPO sign-off because removing events from an anchored, append-only chain is indistinguishable from tampering. Backlog M4-9 owns enforcement. |

Also corrected in this pass: the test CA fixture was anchored one day before "now", so tests driving
fixed clocks began failing purely because the calendar advanced. Widened.

## Fixed in the fourth pass

Investigating the remainder turned up two defects the review had not found, both of the same shape:
appending an audit event flushes the shared `DbContext`, so the *order* of a mutation, its audit
write and the commit decides whether a failure can leave them apart.

| # | Severity | Finding | Fix |
|---|---|---|---|
| 17 | high | **The expiry path could record an approval as ended while its session stayed live and suppressed.** The audit write flushed the unit of work, committing the expiry, and left the session revoke for a second commit. If that commit failed, the approval was `Ended` — and the due query filters on `Approved`/`ActiveSuppressed`, so no later sweep could ever pick it up again. A permanent D-06 and AC-011 breach, with a `sensitive_expired` event asserting a termination that never happened. The second-pass "one commit" fix (#10) did not close this, and its comment claimed it had. | The revoke is sequenced **before** the audit write, so the event and both state changes are one transaction. Proven with a command interceptor that fails `UPDATE Sessions`: the test fails against the old ordering with `request=Ended, session=Active`. |
| 18 | high | **A suppression mismatch could be stored without its audit event.** `AggregateSuppressedAsync` committed the traffic summary and only then wrote the critical threat-N5 event, so a failing audit write lost the detection while keeping the data — a governance action proceeding unlogged, which line 56 of this document claimed was impossible. | Audit first, then store. The test fails against the old ordering. |
| 19 | medium | `EfAuditEventStore` relabelled every `DbUpdateException` as a sequence conflict, so a hard database fault was retried five times and reported as contention. | Classified by asking the database the actual question — is a row with that sequence now present? — rather than matching provider error numbers, which would have required this project to reference both drivers and would still be guessing which constraint fired. `AuditWriter` now surfaces every non-contention failure as one `AuditWriteException`. |
| 20 | medium | **No options validation anywhere in the solution** — not one use of `ValidateOnStart`. A suppression window of 24 hours or more failed at the database when an analyst first used it; a window of zero silently refused every request, disabling an approved governance workflow with no error. | `AddValidatedMinaOptions` binds and validates the shared options at startup, in the Application project so the API and the management UI cannot drift. Also bounds `LeaseTtl` (which is the session certificate's lifetime) and rejects an approver role equal to the analyst role. |
| 21 | low | The 403/404 existence oracle, contradicting the service's own comment. Wider than recorded: the same shape sat on `activate` and `cancel`, and `cancel` checked state before ownership, so a non-requester could tell a decided request from an undecided one by the 409. | A non-owner and a missing id now answer identically — same status, same empty body, same content type — on all four routes. The internal denial reasons stay distinct, so the audit trail still records `NotSessionOwner`. `CancelAsync` checks ownership before state, matching `ActivateAsync`. |
| 22 | low | The approver queue and the expiry sweep were unbounded reads, the only queries whose size an ordinary user controls; the overview screen materialised every pending request to display a count. | Both bounded. The queue reads one more row than the page and reports `hasMore` in the API and as a banner on the approvals screen — a silent cap would let a flood push a genuine request out of an approver's sight, trading a memory defect for an approval-integrity one. The count is now a `COUNT(*)`. |

**Test gaps closed.** A real Envoy now proves an uncertificated client cannot tunnel through the
committed config, paired with a meta-test that rewrites `require_client_certificate` to `false` and
asserts the probe *does* get through — so the guard cannot silently stop guarding. The assertion is
that no tunnel is established, not that a particular exception is thrown: under TLS 1.3 the server
finishes the handshake before judging the client, so the refusal arrives on the first read.
`AuditGatesGovernanceActionsTests` proves the fail-closed property by making the audit insert fail
at the database.

## Confirmed and now resolved by decision

- **medium — device compliance was inferred from the presence of a `deviceid` claim**, which
  indicates Entra registration, not Intune compliance. Resolved by **D-13**: the control plane now
  requires a Conditional Access authentication context (`acrs`) when one is configured, answering a
  claims challenge otherwise, and the misleading names are gone — `DeviceCompliant` is
  `DeviceBound`, and `DeviceNotCompliant` is `DeviceNotBound`. The check is implemented and tested
  but **inert until the tenant defines the auth context and binds a compliant-device policy to it**
  (M2-1), and the agent cannot answer a challenge until the WAM broker lands (M2-4). Until then,
  compliance rests on Conditional Access alone and a missing policy is undetectable — which is what
  makes M2-1 a production gate rather than a convenience.

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

All five items in this section were closed in the fourth pass, except the two that are decisions:

- **Expiry of a never-activated approval revoked the analyst's live, never-suppressed session.**
  Resolved by **D-06a** (2026-09-01): termination now applies only to an approval that was actually
  activated. An approval that lapsed unused suppressed nothing, so there is no suppressed activity
  to stop, and ending a normally logged session taught analysts to avoid the approved workflow.
  ADR-0003 and PHASE0_DECISIONS record the amendment.
- **Undecided requests never lapse.** The queue is now bounded, which was the defect; whether a
  request should *lapse* is a workflow policy with no security consequence — per ADR-0003 the TTL
  anchors at approval, so a stale request approved later still gets a full fresh window, and a
  request whose session has ended cannot be activated at all. Still open, still the owner's call.

### Corrections to this document

Two claims made above were wrong when written and are corrected here rather than quietly edited:

- "no governance action that proceeds unlogged" (the summary above) was **false** for the
  suppression-mismatch path until finding #18 was fixed. It is now true and, for the first time,
  tested.
- "probing is audited", given as the reason the existence oracle was only low severity, was true
  only of hits. A lookup *miss* is recorded nowhere, and per **D-15** that stays as it is: making it
  symmetric would give an authenticated user a lever on an append-only store whose rows cannot be
  deleted under current policy (M4-9). The severity rating stands on the ids being unguessable, not
  on probing being audited.

## Resolved by decision D-14: the session allowlist is not enforced at the node

Found while building the client-authentication test, and left exactly as it is because CLAUDE.md
requires a code-versus-documentation conflict to be surfaced rather than settled.

`egress-node/envoy/envoy-bootstrap.yaml` admits **any unexpired certificate that chains to the
internal CA**. It has no per-session check of any kind. The node sidecar does pull a session
allowlist, but uses it only to decide whether to withhold destinations for a suppressed session —
never to admit or refuse a tunnel.

Three documents say otherwise:

| Document | Claim |
|---|---|
| `docs/ARCHITECTURE.md` (failure modes) | "Open proxy \| Envoy requires platform mTLS **+ live session**" |
| `docs/ARCHITECTURE.md` (failure modes) | "Session revoked/expired \| … **node drops the allowlist entry ⇒ tunnel refused**" |
| `docs/THREAT_MODEL.md` (B-series) | "Egress node becomes open proxy \| mTLS **+ session allowlist**" |

The consequence is about revocation latency, not open-proxy exposure: an unauthenticated scanner
still gets nothing (now proven against a real Envoy). But revoking a session today means *declining
to renew* it, so the already-issued certificate keeps working until it expires — up to the lease
TTL, about 60 minutes. `docs/ARCHITECTURE.md` §4 describes revocation as "effective in seconds via
the push channel, ≤30 s via pull", and `docs/BACKLOG.md` M2-3 records push-based fast revocation as
outstanding while saying "the pull interval bounds the window today". For admission it does not: the
certificate TTL does.

**D-14 (2026-09-01, project owner): correct the documents.** ARCHITECTURE §4 and its failure-mode
table, and the THREAT_MODEL B-series row, now state that revocation is bounded by the certificate
TTL and that the allowlist governs suppression rather than admission. Node-side enforcement, which
would bring revocation down to the push/pull interval, stays available as backlog M4-11.

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
