# SigNoz integration

Operational telemetry — service health, latency, capacity — exported over OTLP. `Mina.Observability`
holds the wiring, the metric definitions, and the scrub processors.

## The one rule

**SigNoz must never receive the destinations analysts reached.** Those are data class C3
(LOGGING_AND_PRIVACY §3): they live in the telemetry store with their own retention and access
controls, and an operational dashboard is not an investigative tool. AC-014 is the check that this
holds.

Two processors enforce it, on the trace and log pipelines, added before any exporter so they run
whatever is exported and whoever adds it later. There is deliberately **no configuration switch to
turn them off**: a pipeline that could be pointed at analysts' destinations by flipping a setting is
exactly the accident the requirement exists to prevent.

What gets removed:

- Attributes whose name is known to carry a destination (`url.full`, `server.address`,
  `network.peer.address`, `mina.hostname`, …) — redacted wholesale, whatever the value, because an
  IP or an opaque id under one of those keys is no more shareable than a name.
- Any other attribute value, or any text inside a log message, that *looks* like a destination — a
  URL, a `host:port`, an IPv4 address, or a bare domain name. This is what catches an attribute
  nobody thought to deny-list.

What survives: service names, regions, environments, route templates, status codes, and ordinary
log text. The pattern requires a domain's last label to be lower-case, so `example.org` is redacted
while `Mina.ControlPlane.Api` and `System.InvalidOperationException` are not, and common file
suffixes are excluded so a message about `appsettings.json` still reads.

The trade-off is deliberate: a redacted operational attribute is an inconvenience, a leaked
destination is not recoverable. IPv4 addresses go too, including internal ones — losing `127.0.0.1`
from a log line costs little beside letting a research target through.

### The endpoint agent is the component that matters most

The agent proxies research traffic, so it necessarily knows every destination and names them in its
own debug logging (`Tunnel established to {Target}`). That is the most realistic leak path into
SigNoz, and it is covered by a test that emits exactly that log line and asserts the exporter never
sees the hostname.

## The leak canary

`mina_telemetry_scrub_drops_total{signal}` counts what the scrubber removed. A non-zero value is not
a breach — it means the scrubber worked — but it says something upstream is putting destinations
into operational telemetry, which is worth fixing at the source rather than relying on the scrubber
forever. **A sudden climb is the alert worth having.**

## Metrics

| Metric | Type | Dimensions | For |
|---|---|---|---|
| `mina_session_establish_duration_seconds` | histogram | region | Session issuance latency (SLO) |
| `mina_session_establish_failures_total` | counter | region, reason | Refusals and failures |
| `mina_approval_workflow_duration_seconds` | histogram | outcome | How long approvals take to decide |
| `mina_suppression_mismatches_total` | counter | region | Nodes still sending suppressed destinations |
| `mina_telemetry_items_total` | counter | region, outcome | Ingest volume by outcome |
| `mina_telemetry_scrub_drops_total` | counter | signal | Leak canary |
| ASP.NET Core + runtime instrumentation | various | — | Request duration, GC, threads |

Every dimension is a platform fact — region, outcome, reason. None is derived from what an analyst
reached.

Resource attributes: `service.name`, `deployment.environment`, `mina.region`.

## Configuration

```json
"Mina": {
  "Observability": {
    "OtlpEndpoint": "http://signoz-collector.internal:4317",
    "ServiceName": "mina-control-plane-api",
    "Environment": "prod",
    "Region": "westeurope"
  }
}
```

With no `OtlpEndpoint` the instrumentation still runs — including the scrubbers — but nothing is
exported. That is the local-development default.

## Suggested alerts

- `mina_telemetry_scrub_drops_total` rising — something is putting destinations into operational
  telemetry.
- `mina_suppression_mismatches_total > 0` — a node is collecting under an approved suppression
  (also a critical audit event; see EVENT_SCHEMAS).
- `mina_session_establish_failures_total` by `reason` — a spike in `DeviceNotBound` or
  `RegionNotSelectable` usually means a policy or stamp problem, not user error.
- `AuthenticationContextRequired` needs a **rate**, not a threshold, and must not be alerted at
  `> 0`. Once `Mina:Session:RequiredAuthContextId` is set, a claims challenge is a normal step in
  the protocol: a client whose cached token predates the requirement is challenged once, re-acquires
  with the claim, and succeeds. Expect roughly one per analyst per token lifetime as a baseline. The
  signal worth alerting on is a client that is challenged repeatedly without ever succeeding — i.e.
  challenges rising while `mina_sessions_established_total` does not — which is what a device
  failing the compliance policy actually looks like. Each challenge is also an `authz_denied` audit
  event, so the same caveat applies to anyone reading the audit chain: a challenge is not a refusal.
- Session establishment p95 latency, and control-plane request duration, against the SLOs in
  `docs/OPERATIONS.md`.

## Not done yet

**Dashboards.** Building and exporting SigNoz dashboard JSON needs a reachable SigNoz instance to
validate against; shipping an unvalidated dashboard file would be guessing. The metric inventory and
alert expressions above are what a dashboard is assembled from.

**Delivery path.** This paragraph named the Check Point site-to-site tunnel (ADR-0005) and a
network-team precondition; both are stale, corrected here 2026-09-07 while scoping M3-5. ADR-0006
superseded ADR-0005 the day after this file was first written: the control plane moved on premises,
so reaching Wazuh and SigNoz is a local hop from the same DMZ segment, no tunnel and no rule-scoping
precondition involved (see `docs/adr/0006-on-premises-control-plane.md` §10.3, `docs/PHASE0_DECISIONS.md`
D-05's superseded note). What is still genuinely open is unchanged from before: a reachable SigNoz
instance to validate dashboards against.
