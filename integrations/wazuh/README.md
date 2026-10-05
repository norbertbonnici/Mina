# Wazuh integration

Delivery of the audit chain to Wazuh (M3-5, AC-013) and the rules that turn a delivered line into
an alert. The delivery code itself lives in `control-plane` (`Mina.ControlPlane.Application.Audit`,
`Mina.ControlPlane.Api.Infrastructure`), the same way `WazuhDeliveryService`/
`WazuhDeliveryBackgroundService` mirror `AuditExportService`/`AuditExportBackgroundService`'s own
shape — this directory holds what does not belong in that codebase: the rules Wazuh itself loads.

## The one rule

**Wazuh receives security/audit events only, never URL or hostname content — not even for a
default (non-suppressed) session.** Nothing here has to enforce that: `WazuhEventFormat` only ever
forwards `AuditEvent.Data`, the same payload the audit chain already stores, and that payload is
proven hostname-free at the source by `SensitiveSessionHygieneTests` and
`TelemetryIngestServiceTests` (M3-4/M3-7). Wazuh getting no destinations is a property of what is
sent, not of anything filtered here.

## How delivery works

`WazuhDeliveryService` reads new events from the audit chain since its own watermark (the same
incremental-read-since-last-position shape `AuditExportService` already uses for the WORM anchor,
just without that service's write-once/anchor-back-into-the-chain concerns — Wazuh delivery has no
tamper-evidence role, it is a downstream SIEM feed), renders each as the EVENT_SCHEMAS §2 envelope
(`WazuhEventFormat`, one JSON object per line), and hands the batch to `IWazuhEventSink`.

`FileSystemWazuhEventSink` — the only implementation so far — appends to a single, ever-growing
file and records its watermark in a sibling `.watermark` file, written only *after* the append
succeeds. Delivery is at-least-once by design (EVENT_SCHEMAS §2): a crash between the append and
the watermark write re-delivers the same batch next pass rather than silently dropping it, and
Wazuh de-duplicates on `event_id` — a redelivered line is a harmless duplicate, a dropped one is a
missed security event, so the ordering only ever risks the safe side.

`WazuhDeliveryBackgroundService` runs this on a timer, gated by the same lease pattern
(`IBackgroundLeaseStore`) `AuditExportBackgroundService` already uses — two instances delivering
the same range would double-append every line to the event file.

**Off unless configured.** `Mina:Wazuh:Delivery:EventFilePath` unset means the background service
still runs every tick but delivers nothing — the same "unset is safe" posture as
`Mina:Telemetry:Retention` and `Mina:ManagementUi:OfficeHours`, since a real path is
environment-specific and unknown in dev/test. The host logs a startup warning
(`StartupLog.WazuhDeliveryDisabled`) rather than silently doing nothing.

```json
"Mina": {
  "Wazuh": {
    "Delivery": {
      "EventFilePath": "/var/ossec/mina/wazuh-events.jsonl",
      "BatchSize": 500,
      "Interval": "00:00:30"
    }
  }
}
```

## Reaching Wazuh (ADR-0006 — the local hop)

The control plane sits in the on-premises Proxmox DMZ VLAN; Wazuh is reached as one of the narrow flows
ADR-0006 §"Binding constraints" 2 permits crossing that boundary — a local network hop, not the
Check Point tunnel ADR-0005 originally proposed and ADR-0006 superseded (`docs/PHASE0_DECISIONS.md`
D-05). Point `EventFilePath` at a location the Wazuh agent co-located with (or reachable from) that
host can read, and configure that agent's own `ossec.conf`:

```xml
<localfile>
  <log_format>json</log_format>
  <location>/var/ossec/mina/wazuh-events.jsonl</location>
</localfile>
```

With `log_format` set to `json`, Wazuh parses every top-level field of a well-formed JSON line
itself — `event_type`, `severity`, `data`, and so on are directly available to rules via
`<field name="...">` with **no custom decoder required**. `rules/mina_rules.xml` is written against
exactly that.

### The DMZ proxy host (M4-14)

The published node-facing listener's nginx writes one JSON line per request to
`/var/log/nginx/mina-node.access.json` (schema `mina.proxy.v1`; the format is in
`infra/terraform/modules/control-plane-onprem/templates/proxy.cloud-init.yaml.tftpl`). It carries
the recovered node address, route, status, rate-limiter verdict and whether the source is one of
the egress stamps' NAT prefixes — never a request body or a research hostname. A Wazuh agent on
that host reads it with the same `json` shape:

```xml
<localfile>
  <log_format>json</log_format>
  <location>/var/log/nginx/mina-node.access.json</location>
</localfile>
```

`rules/mina_rules.xml`'s `mina_proxy` group is written against those fields. Installing the agent
on the proxy host is part of M3-5, not of the proxy module; until then the same lines go to SigNoz
through the collector the module installs when `otlp_endpoint` is set.

## Rules (`rules/mina_rules.xml`)

Custom rule ids `100500`–`100530`, group `mina_audit`. Confidence varies and is called out per rule
in the file itself:

- **Severity floor** (`100501`–`100505`, high confidence): plain field matches mapping
  `info/notice/warning/high/critical` to Wazuh levels `3/5/7/10/13`, EVENT_SCHEMAS §3's own
  suggested mapping.
- **`sensitive_suppression_mismatch`** (`100510`) and **`break_glass_*`** (`100511`): critical, no
  threshold — EVENT_SCHEMAS §6 says both should page immediately, not wait for a pattern.
- **Repeated `authz_denied`** (`100520`/`100521`) and **`client_tamper_suspected` clustering**
  (`100530`): correlation rules using `<same_field>` against a dotted JSON path
  (`user.oid`, `device.entra_device_id`). This is the part **not yet validated against a live
  Wazuh instance** — whether a nested JSON object's fields are addressable that way, rather than
  needing an explicit flattening decoder first, depends on the Wazuh version actually deployed.
  `100520` explicitly keeps `AuthenticationContextRequired` (a routine Conditional Access step-up,
  not a refusal — EVENT_SCHEMAS §6's own caveat) out of the correlation in `100521`, rather than
  correlating on it and training operators to ignore the resulting noise.

## Not done yet

**Validation against a live Wazuh instance.** Everything above is written against documented Wazuh
4.x syntax and this project's own delivered envelope shape, not confirmed by actually watching an
alert fire — the same honesty note `integrations/signoz/README.md` carries for its dashboards.
Before relying on this in production: deliver a real batch, inspect the actual JSON line Wazuh
receives, and confirm the correlation rules' field paths resolve as written.

**A dedicated relay host in `environments/dev-onprem`.** ARCHITECTURE §9 lists a "telemetry relay"
as its own on-premises component; this milestone built the delivery *code* and the *rules*, not a
Terraform-provisioned host for them to run on. `EventFilePath` can point anywhere reachable from
wherever the control plane and a Wazuh agent actually end up co-located — provisioning that host is
separate infrastructure work, not gated on anything here.
