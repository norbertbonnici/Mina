# ADR-0005: Telemetry delivery to Wazuh/SigNoz over the existing Check Point site-to-site tunnel

- Status: **Accepted 2026-08-31; SUPERSEDED by ADR-0006 (2026-09-01).** Not because its constraints
  were violated — they were not, and ADR-0006 deliberately preserved the property constraint 1
  protects — but because the problem it solved no longer exists. The telemetry relay is now on
  premises alongside Wazuh and SigNoz, so delivery is a local hop and the Check Point tunnel is not
  used by this platform at all. D-05's open precondition (network-team confirmation of Check Point
  rule scoping) accordingly leaves the critical path. Retained for the record of what was decided
  and why. Originally accepted (directed by project owner, D-05); Check Point rule scoping to
  be confirmed with the FIAU network team before implementation (M3-5/6)
- Date: 2026-08-31
- Related: `docs/ARCHITECTURE.md` §10, `docs/EVENT_SCHEMAS.md`, `docs/LOGGING_AND_PRIVACY.md`

## Context

Wazuh (security/audit) and SigNoz (operational telemetry) are organisation-hosted. Phase 0
offered two delivery shapes (corp-pull vs DMZ-push) on the assumption of no existing
connectivity. The owner has clarified that a **Check Point site-to-site VPN already links the
corporate network with Azure**. Using it avoids new internet-facing log endpoints on either
side.

## Decision

Deliver platform telemetry to the on-prem receivers **over the existing site-to-site tunnel**,
from the control-plane telemetry relay only, under these binding constraints:

1. **Research egress stamps stay off this path entirely.** Egress VNets are never peered or
   routed to the corp-connected hub; their NSGs keep denying all RFC1918/corp destinations.
   Egress nodes deliver telemetry only to the control-plane relay over public TLS, exactly as
   designed. CLAUDE.md non-negotiable #4 (no route from research egress nodes into internal
   corporate networks) is **unchanged** by this ADR.
2. Only the **relay subnet** of the control-plane VNet gets routing toward corp, and only to
   the Wazuh and SigNoz receiver addresses/ports (syslog-TLS / OTLP). Enforced twice: Azure
   NSG/UDR on the relay subnet, and the Check Point policy on the tunnel.
3. No corp-initiated flows into the Mina control plane are added by this ADR (established
   return traffic only). Management access to the platform remains via Entra-authenticated
   public endpoints, not the tunnel.
4. Relay buffering and delivery-lag alerting per `docs/EVENT_SCHEMAS.md` §6 absorb tunnel
   outages; audit governance writes remain synchronous and unaffected (they land in SQL first).

## Alternatives considered

Corp-side puller over the internet (zero corp-inbound; rejected as redundant given the tunnel);
push to a DMZ collector over the internet (new inbound exposure; rejected for the same reason).

## Security/privacy consequences

This adds a narrowly scoped route from the control plane into the corporate network — a
CLAUDE.md stop-condition item, decided explicitly by the owner here. The mitigations are the
constraints above; the residual trust is in the Check Point policy being scoped as specified,
which is why network-team confirmation is a named precondition. Wazuh still receives no
URL/hostname content, and SigNoz traffic passes the scrub processor before leaving the relay.

## Operational consequences

Telemetry availability now depends on tunnel health → add tunnel-path delivery-lag alerting to
the OPERATIONS monitoring set and a "telemetry tunnel down" entry to the runbook list.

## Approval

Approved by the project owner, 2026-08-31, in the D-05 decision round. Implementation blocked
until the network team confirms the Check Point rule set matching constraints 2–3.
