# Event Schemas — Wazuh and SigNoz

Status: Phase 0 — Proposed. Versioned; breaking changes bump `schema` and require a doc update.

## 1. Separation rule

- **Wazuh** receives security/audit events only. **No URL or hostname content, ever** — not
  even in default (non-suppressed) sessions. Hostname telemetry lives in the control-plane
  audit store; Wazuh gets governance facts about sessions, not browsing content.
- **SigNoz** receives operational telemetry only. A scrub processor drops/redacts any
  URL/hostname-shaped attribute before export (AC-014).

## 2. Common envelope (audit/security events)

```json
{
  "schema": "mina.audit.v1",
  "event_id": "8c9f6f7e-…",
  "event_type": "session_started",
  "severity": "info | notice | warning | high | critical",
  "occurred_at": "2026-08-31T14:07:02.113Z",
  "environment": "dev | test | prod",
  "component": "control-plane | egress-node | endpoint-agent | management-ui | platform",
  "region": "westeurope | null",
  "user":    { "upn": "analyst@example.org", "oid": "…" },
  "device":  { "entra_device_id": "…", "intune_device_id": "…" },
  "session": { "id": "…", "mode": "normal | sensitive" },
  "data":    { }
}
```

`user`/`device`/`session` are null where not applicable (e.g. platform events). `data` carries
the per-type payload below. Transport to Wazuh: JSON from the on-premises relay, a local hop since ADR-0006 (the ADR-0005
tunnel path is superseded); one event per record; at-least-once with `event_id` de-duplication.

## 3. Audit/security event catalogue

| event_type | Severity | Emitted by | data payload (key fields) |
|---|---|---|---|
| authz_denied | warning | control-plane | `reason` — one of `NotAuthorisedRole`, `DeviceNotBound`, `AuthenticationContextRequired`, `RegionNotSelectable`, `NotSessionOwner`; plus region where known |
| auth_success / auth_failure | — | *not emitted* | Token validation happens in the Entra middleware, which raises nothing into this chain. Sign-in successes and failures live in Entra's own sign-in logs; correlate there, not here |
| session_started | info | control-plane | region, egress_ip_prefix, client_cert_serial |
| session_renewed | info | control-plane | cert_serial_old/new |
| session_ended | info | control-plane | reason (user, browser_closed, tunnel_lost) |
| session_revoked | high | control-plane | actor, reason |
| session_expired | info | control-plane | Written by the session expiry sweeper when a lease lapses without the analyst ending the session |
| region_selected | info | control-plane | region; rejected attempts → authz_denied |
| region_rejected | warning | control-plane | requested unapproved region |
| sensitive_requested | notice | control-plane | justification_ref, requested_minutes |
| sensitive_approved | notice | control-plane | approver_upn, ttl_minutes, expires_at |
| sensitive_denied | notice | control-plane | approver_upn, reason_ref |
| sensitive_activated | notice | control-plane | node_ack: bool |
| sensitive_suppression_ack | info | egress-node | session id, flag state |
| sensitive_suppression_mismatch | **critical** | control-plane | expected vs node state (threat N5); `discarded_items` |
| telemetry_region_mismatch | high | control-plane | a node claimed a region for a session issued in a different one; `claimed_region`, `session_region`, `discarded_items` |
| telemetry_unattributable | warning | control-plane | telemetry for a session id the control plane has no record of; `discarded_items` |
| sensitive_expired | notice | control-plane | terminated_session: bool |
| role_assignment_observed | notice | control-plane | drift vs expected groups (periodic) |
| client_tamper_suspected | high | endpoint-agent | indicator (wfp_rule_missing, unmanaged_browser_instance, foreign_proxy_client, flag_mismatch) |
| agent_health_degraded | warning | endpoint-agent | subsystem |
| node_security_event | high | egress-node | wazuh-agent native findings passthrough ref |
| open_proxy_probe_detected | warning | egress-node | source IP, count (unauthenticated connects) |
| telemetry_retention_applied | info | control-plane | `data_class` (C3), `cutoff`, `hostnames_deleted`, `suppressed_summaries_deleted`. Written only by passes that actually deleted something. Deletion is the one action whose own evidence disappears, so without this event a purged period and a period that recorded nothing look identical afterwards |
| telemetry_viewed | notice | control-plane | `viewer_upn`, `target_analyst_upn` (or `all` when the query is unscoped to one analyst), `range_from`, `range_to`, `session_count_returned`. Written once per browsing-data-review query, server-side, regardless of which endpoint or client made it (planned: M3-8). Never carries a hostname — the payload proves *that* C3 was read and by whom, not *what* was read, matching threat N10 |
| audit_trail_viewed | notice | management-ui | `events_returned`, `events_before_filter`, `severity_filter`, `component_filter`. Written once per query against the `/audit` management screen (M3-2), the same "record that the trail was read, and by whom" precedent `telemetry_viewed` set — reading the audit trail is itself a privileged operation (`AuditEndpoints`' own remark), so an administrator's own review of it is a governance fact worth recording, not exempt from the trail it belongs to |
| region_change_requested | notice | management-ui | `kind`, `region`, `justification`. An admin asked for a region to be added/removed/activated/deactivated (ADR-0008 Option C) — captures intent only, no region list changes yet |
| region_change_dismissed | notice | management-ui | `kind`, `region`, `reason`. The request was declined rather than pursued — superseded, mistaken, or otherwise not going to happen |
| policy_changed | high | control-plane/management-ui | policy key, old→new, actor (region list, TTLs, retention config). First real producer: an admin confirming a region change request (ADR-0008 Option C) was actually applied through the reviewed deploy script — `policy_key` = `Mina:Regions:Approved`/`Active`, `region`/`kind` for what changed, `resolution_note` for how (e.g. which deploy). Catalogued since before M3-2 and emitted by nothing until this |
| audit_export_completed | info | control-plane | export range, hash (WORM anchor) |
| audit_pipeline_degraded | high | control-plane | backlog size |
| ca_rotation_status | info / warning / **critical** | control-plane | `urgency` (Healthy/Warning/Critical), `daysRemaining`, `vault`. Written by `mina-ca rotation-check --report-sql` (M4-2) — a periodic, system-originated check (no user/device/session, same shape as `telemetry_retention_applied`/`role_assignment_observed`) of how close the internal CA certificate (M2-2c) is to expiry. Severity tracks the tool's own `RotationUrgency`: Healthy→info, Warning→warning, Critical→critical — an unrotated CA past the critical threshold is a looming loss of the platform's session-issuance capability, the same order of consequence as `sensitive_suppression_mismatch`. Nothing schedules the check itself yet; see `docs/OPERATIONS.md`'s "Internal CA rollover" runbook |
| break_glass_signin | **critical** | platform (Entra export) | account, source |
| break_glass_azure_action | **critical** | platform (activity-log export) | principal, operation, resource |
| admin_action | notice | management-ui/control-plane | action, target |

Wazuh side: rules map severities (`high`→level 10+, `critical`→level 13+ suggested), with
correlation rules for: repeated `authz_denied` per user/device (note that a
`reason` of `AuthenticationContextRequired` is a routine Conditional Access step-up, not a refusal —
correlate on challenges that never convert into a `session_started`); sensitive_suppression_mismatch
(page immediately); any break_glass_*; client_tamper_suspected clusters; ca_rotation_status at
Critical severity (page immediately — the same "act now, not eventually" urgency as the other events
in this list, not a routine warning).

## 4. Hostname telemetry record (audit store only — never Wazuh/SigNoz)

```json
{
  "schema": "mina.hostname.v1",
  "session_id": "…",
  "occurred_at": "…",
  "hostname": "example.org",
  "port": 443,
  "bytes_up": 12345,
  "bytes_down": 67890,
  "duration_ms": 5120,
  "protocol": "connect | http"
}
```

Suppressed sessions produce instead per-interval:
`{"schema":"mina.hostname.suppressed.v1","session_id":"…","interval_start":"…","connection_count":n,"bytes_total":n}`.

## 5. SigNoz (OTLP) inventory

**Resource attributes:** `service.name` (mina-control-plane | mina-management-ui |
mina-egress-node | mina-endpoint-agent), `deployment.environment`, `mina.region`.

**Metrics** (prefix `mina_`):

| Metric | Type | Labels | Purpose |
|---|---|---|---|
| active_sessions | gauge | region | capacity/health |
| session_establish_duration_seconds | histogram | region, result | SLO: establishment success/latency |
| session_establish_failures_total | counter | region, reason | alerting |
| tunnel_disconnects_total | counter | region, reason | protected-path failures |
| proxy_connect_errors_total | counter | region, class | egress health |
| node_allowlist_sync_age_seconds | gauge | region, node | control↔data sync health |
| approval_workflow_duration_seconds | histogram | outcome | governance ops |
| audit_forward_lag_seconds | gauge | sink (wazuh, worm) | audit pipeline health |
| telemetry_scrub_drops_total | counter | — | scrubber activity (leak canary) |
| egress_node_cpu / _memory / _conn_count | gauge | node | capacity |
| control_plane_http_request_duration_seconds | histogram | route, code | service SLO |

**Traces:** `SessionEstablish` (agent→API→CA-issue→node-push), `SensitiveSessionWorkflow`,
`NodeConfigSync`. Span attributes must not include hostnames/URLs (scrubber enforced).

**Logs:** structured service logs, scrubbed; no research content.

## 6. Delivery and buffering

Endpoint agent → control plane over the authenticated API (batched, non-blocking; drops
operational — never audit — data under backpressure). Nodes buffer locally (disk-bounded) when
the published control-plane endpoint is unreachable; `audit_pipeline_degraded` fires past thresholds. Control-plane audit
writes are synchronous with the action they record: if the audit store is unavailable,
governance actions fail closed (the action does not proceed unlogged).

That guarantee comes from the transactional store, not from ordering alone, and it is not uniform
across the paths. Where the aggregate is already tracked — approve, deny, cancel, activate, expire,
renew, end — the audit append flushes the pending mutation with it, so the event and the state
change share one transaction and neither survives without the other. On the two **create** paths
(session issue, suppression request) the entity is not yet tracked when the event is written, so the
event commits first and the row is written by a second save: a failure in between leaves an event
for something that does not exist. That is over-recording, which is the deliberate direction here —
an audit trail that claims too much is recoverable, one that claims too little is not. `tests/integration/Mina.ControlPlane.Persistence.Tests/AuditGatesGovernanceActionsTests.cs`
holds it by making the audit insert fail. It does **not** hold for the in-memory development
stores, which hold aggregates by reference — a mutation is visible there the moment it is made,
with no transaction to roll back. Those stores are for local development only and the host logs a
warning at startup when it is using them; no conclusion about fail-closed behaviour should be drawn
from a run against them.
