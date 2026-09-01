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
  "user":    { "upn": "analyst@fiaumalta.org", "oid": "…" },
  "device":  { "entra_device_id": "…", "intune_device_id": "…" },
  "session": { "id": "…", "mode": "normal | sensitive" },
  "data":    { }
}
```

`user`/`device`/`session` are null where not applicable (e.g. platform events). `data` carries
the per-type payload below. Transport to Wazuh: JSON over the D-05 relay path; one event per
record; at-least-once with `event_id` de-duplication.

## 3. Audit/security event catalogue

| event_type | Severity | Emitted by | data payload (key fields) |
|---|---|---|---|
| auth_success | info | control-plane | roles, token device claims present |
| auth_failure | warning | control-plane | reason (invalid_token, no_role, device_noncompliant), source IP |
| authz_denied | warning | control-plane | attempted action, required role |
| session_started | info | control-plane | region, egress_ip_prefix, client_cert_serial |
| session_renewed | info | control-plane | cert_serial_old/new |
| session_ended | info | control-plane | reason (user, browser_closed, tunnel_lost) |
| session_revoked | high | control-plane | actor, reason |
| session_expired | notice | control-plane | — |
| region_selected | info | control-plane | region; rejected attempts → authz_denied |
| region_rejected | warning | control-plane | requested unapproved region |
| sensitive_requested | notice | control-plane | justification_ref, requested_minutes |
| sensitive_approved | notice | control-plane | approver_upn, ttl_minutes, expires_at |
| sensitive_denied | notice | control-plane | approver_upn, reason_ref |
| sensitive_activated | notice | control-plane | node_ack: bool |
| sensitive_suppression_ack | info | egress-node | session id, flag state |
| sensitive_suppression_mismatch | **critical** | control-plane | expected vs node state (threat N5) |
| sensitive_expired | notice | control-plane | terminated_session: bool |
| policy_changed | high | control-plane | policy key, old→new, actor (region list, TTLs, retention config) |
| role_assignment_observed | notice | control-plane | drift vs expected groups (periodic) |
| client_tamper_suspected | high | endpoint-agent | indicator (wfp_rule_missing, unmanaged_browser_instance, foreign_proxy_client, flag_mismatch) |
| agent_health_degraded | warning | endpoint-agent | subsystem |
| node_security_event | high | egress-node | wazuh-agent native findings passthrough ref |
| open_proxy_probe_detected | warning | egress-node | source IP, count (unauthenticated connects) |
| audit_export_completed | info | control-plane | export range, hash (WORM anchor) |
| audit_pipeline_degraded | high | control-plane | backlog size |
| break_glass_signin | **critical** | platform (Entra export) | account, source |
| break_glass_azure_action | **critical** | platform (activity-log export) | principal, operation, resource |
| admin_action | notice | management-ui/control-plane | action, target |

Wazuh side: rules map severities (`high`→level 10+, `critical`→level 13+ suggested), with
correlation rules for: repeated auth_failure per user/device; sensitive_suppression_mismatch
(page immediately); any break_glass_*; client_tamper_suspected clusters.

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
the relay is unreachable; `audit_pipeline_degraded` fires past thresholds. Control-plane audit
writes are synchronous with the action they record: if the audit store is unavailable,
governance actions fail closed (the action does not proceed unlogged).

That guarantee comes from the transactional store, not from ordering alone. The audit append and
the state change it describes share one database transaction, so neither survives without the
other; `tests/integration/Mina.ControlPlane.Persistence.Tests/AuditGatesGovernanceActionsTests.cs`
holds it by making the audit insert fail. It does **not** hold for the in-memory development
stores, which hold aggregates by reference — a mutation is visible there the moment it is made,
with no transaction to roll back. Those stores are for local development only and the host logs a
warning at startup when it is using them; no conclusion about fail-closed behaviour should be drawn
from a run against them.
