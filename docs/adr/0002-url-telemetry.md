# ADR-0002: URL telemetry collection method

- Status: **Accepted 2026-08-31** — Option 1: hostname-level telemetry at the egress, no TLS
  interception (D-01)
- Date: 2026-08-31
- Decision owners: FIAU platform owner, security architecture, data protection
- Related: `docs/LOGGING_AND_PRIVACY.md`, ADR-0001, ADR-0003

## Context

Default sessions must record the approved level of URL/hostname telemetry; approved sensitive
sessions suppress it. For HTTPS, the URL *path and query* are inside the encrypted stream: an
egress layer sees at most the hostname. Full URLs therefore require either browser-side
collection or TLS interception. TLS interception must not be introduced silently (hard
requirement), and suppression must be enforced by the control/logging plane, not a client toggle.

A material privacy observation for FIAU: URL paths and query strings frequently embed the
*subjects of research* (names, usernames, account IDs, search terms). Full-URL telemetry is
therefore substantially more sensitive than hostname telemetry — it can reconstruct who is being
investigated, not just where analysts browse. This weighs on retention, access control, and the
choice below.

## Options analysed

### Option 1 — Hostname-level telemetry at the egress, no TLS interception (**recommended for MVP**)

Under the ADR-0001 proxy architecture, every research connection reaches the egress proxy as an
explicit `CONNECT host:port` (HTTPS) or absolute URI (plain HTTP). The egress node logs
`{session, timestamp, hostname, port, bytes, duration}` per connection. Plain-HTTP full URLs are
normalised to hostname-level for consistency. Egress DNS query logs corroborate.

| Dimension | Assessment |
|---|---|
| Visibility | Hostname/domain + port + volume/timing. No paths, no queries. |
| Bypass resistance | **Strong** — collection is server-side in the data path; the endpoint cannot influence it. Unaffected by ECH/encrypted SNI because the `CONNECT` target is explicit. |
| Privacy impact | Lowest of the three. Reveals destinations, not content or search terms. |
| Endpoint complexity | None beyond ADR-0001. |
| Operational burden | Low — log pipeline from Envoy to the audit store. |
| Failure modes | Egress logging outage ⇒ telemetry gap (alertable, fail-safe for audit: sessions can be refused if the audit pipeline is down — policy choice). |
| Suppression fit | **Clean** — control plane flips a per-session flag on the node; hostnames are never recorded for suppressed sessions. Wholly server-side. |

### Option 2 — Browser-originated full-URL telemetry

A force-installed extension in the research browser (or an equivalent browser reporting channel)
reports full navigation URLs to the endpoint agent/control plane.

| Dimension | Assessment |
|---|---|
| Visibility | Full URLs including path/query; page-level navigation detail. |
| Bypass resistance | **Moderate** — client-side origin. Force-install prevents casual removal, but a tampered/killed reporting path yields silent gaps; requires heartbeat + server-side gap detection tied to connection logs (compare Envoy connection counts vs reported navigations). |
| Privacy impact | High — captures subject identifiers and search terms; strict retention/access control and DPO involvement required (materially increased data collection ⇒ explicit approval trigger). |
| Endpoint complexity | Extension + native-messaging or agent channel; per-profile activation logic; update/signing lifecycle. |
| Operational burden | Medium-high: extension lifecycle, schema evolution, gap reconciliation. |
| Failure modes | Silent under-reporting is the dangerous one (mitigated only detectively). Startup race: navigations before the extension initialises may be missed. |
| Suppression fit | Requires **dual enforcement**: control plane instructs client to stop *and* authoritatively drops/never-persists anything that still arrives (ADR-0003). URLs may transit during teardown — handled by server-side drop. |

### Option 3 — TLS interception at the egress

Enterprise CA trusted by the research context; egress decrypts, logs full URLs, re-encrypts.

| Dimension | Assessment |
|---|---|
| Visibility | Full URLs and, implicitly, capability to see full content. |
| Bypass resistance | Strong for what it decrypts; certificate-pinned apps/sites break or bypass. |
| Privacy impact | **Highest** — capability overshoot (content access, not just URLs); significant legal/works-council/DPO surface; key custody for the interception CA becomes a crown-jewel asset. |
| Endpoint complexity | CA trust distribution scoped to the research context only (hard, given instance-global trust stores — the CA would be trusted machine-wide). |
| Operational burden | High: CA lifecycle, breakage triage, HSM/key custody, incident exposure. |
| Failure modes | Interception outage breaks all research browsing; a compromised interception CA is catastrophic. |
| Suppression fit | Possible but the decryption capability itself remains — suppression of *logging* does not suppress *capability*, which is the governance problem. |

## Recommendation

**Adopt Option 1 for MVP.** It satisfies FR-008/FR-009 with the strongest tamper resistance,
the lowest privacy footprint, zero additional endpoint surface, and a clean server-side
suppression story. Revisit Option 2 as a separately approved enhancement only if investigative
practice demonstrates that hostname-level records are insufficient; that revisit requires DPO
review because it materially increases data collection. **Option 3 is not recommended** at any
phase of this project as scoped; if it is ever tabled, it needs its own ADR with legal sign-off.

## Approval

**Option 1 approved by the project owner on 2026-08-31** (D-01 in `docs/PHASE0_DECISIONS.md`).
Any future move to Option 2 or 3 requires a new ADR and triggers the CLAUDE.md stop conditions
(materially increased data collection / TLS interception) plus DPO involvement.
