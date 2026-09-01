# ADR-0006: On-premises control plane in the FIAU Proxmox cluster

- Status: **Accepted 2026-09-01** (directed by the project owner). Supersedes the Azure-hosted
  control plane described in ARCHITECTURE §3.2, and amends ADR-0005 constraint 1.
- Date: 2026-09-01
- Related: `docs/ARCHITECTURE.md` §3.2/§4/§10, `docs/THREAT_MODEL.md`, `docs/adr/0005-telemetry-delivery.md`,
  `CLAUDE.md` non-negotiable property 4, decisions D-16…D-18

## Context

Phase 0 placed the whole control plane in Azure: API and management UI on App Service, Azure SQL
for sessions/approvals/audit/telemetry, Key Vault for the CA signing key, and managed identities
throughout. Egress stamps were separate Azure deployments that reached the control plane over
public TLS and were forbidden any route toward corporate networks.

The project owner has directed that the management platform — the portal, its web server, its logs
and the SQL database — be hosted on premises in the FIAU's Proxmox cluster. Because the control-plane
API and the management UI share one database, this necessarily moves the API as well.

## Decision

**The Mina control plane runs on premises in the FIAU Proxmox cluster.** That comprises the
control-plane API, the management portal, SQL Server, and the platform's own service logs. The
Azure egress stamps are unchanged and remain in Azure.

Three supporting decisions were taken with it:

1. **SQL Server is Azure Arc-enabled** so the control plane authenticates to it with Entra
   authentication and no stored credential (D-17). The "no client secrets anywhere in the product"
   property of ARCHITECTURE §4 is preserved rather than traded away.
2. **The CA signing key stays in Azure Key Vault, and audit export anchors stay in Azure immutable
   blob storage** (D-18). These are the two guarantees that need hardware or platform enforcement
   and that a general-purpose Proxmox VM cannot provide: a signing key on a VM disk is not
   equivalent to a Key Vault key, and tamper-evidence anchored to a filesystem the same
   administrator controls is not evidence. The control-plane hosts are themselves Arc-enabled, so
   they use their Arc system-assigned managed identity to reach both — again with no stored secret.
3. **Egress nodes call the on-premises control plane directly** over the existing Check Point
   site-to-site tunnel (D-16). This is the part that changes a stated non-negotiable, below.

### Amendment to CLAUDE.md non-negotiable property 4

CLAUDE.md states: *"No route from research egress nodes into internal corporate networks unless a
future, separately approved ADR explicitly changes this."* **This ADR is that change, and it is
narrow.** Egress nodes are permitted exactly one flow toward the corporate side: node-initiated
TLS to the control plane's node-facing endpoint. Everything else stays denied.

The permission is bounded by all of the following, which are binding:

1. **DMZ termination.** The control plane is deployed in a dedicated Proxmox DMZ VLAN, not on the
   corporate LAN. That segment is treated as reachable by a compromised egress node and is
   firewalled from the corporate LAN accordingly; only the flows this platform needs (Entra sign-in,
   Wazuh, SigNoz, Arc/Key Vault/Storage egress, and administrator access to the portal) cross that
   boundary, each explicitly permitted.
2. **One destination, one port.** Egress-stamp subnets may reach exactly one control-plane virtual
   address on 443/TCP. Enforced twice, as ADR-0005 already requires of the relay path: Azure NSG and
   UDR on the egress subnets, and Check Point policy on the tunnel. No other corporate destination
   is reachable from an egress subnet, and the existing blanket deny for RFC1918 and corporate CIDRs
   otherwise stands.
3. **Split listeners.** The node-facing API and the management portal are separate listeners with
   separate exposure. The node-facing listener carries only the node endpoints (session allowlist
   and telemetry ingest) and is the only thing reachable from the egress path. The portal, the audit
   read API and every administrative endpoint are reachable only from corporate workstations, never
   from the egress path. A compromised node must not be able to load the approvals screen.
4. **Node identity unchanged.** Nodes continue to authenticate with the per-region
   `Mina.Node.<region>` app role. A bare node role remains entitled to nothing, and region scoping
   continues to be enforced server-side.
5. **No corporate-initiated flows to nodes.** Established return traffic only. Nothing on the
   corporate side dials an egress node.

## Consequences

### This is a security regression, stated plainly

Before this ADR, a fully compromised egress node had no network path to any FIAU system: it could
speak to the public internet and to a public Azure endpoint, and nothing else. THREAT_MODEL treated
egress-host compromise as contained by that fact. After this ADR, a compromised node can reach one
TLS port on one DMZ address. The constraints above reduce that to a narrow, authenticated, monitored
surface, but they do not restore the previous property: the blast radius of node compromise now
includes whatever that endpoint can be made to do.

The mitigations are the split listeners (constraint 3), which keep the reachable surface to two
endpoint families rather than the whole platform, and the DMZ placement (constraint 1), which stops
"reached the control plane" from meaning "reached the corporate network". Both must be verified as
deployed, not assumed — see the acceptance work in the backlog.

### Availability

Session issuance and renewal now depend on the Proxmox cluster and the tunnel. Leases are about 60
minutes and renewal requires the control plane, so a cluster or tunnel outage stops all research
browsing within one lease period. This is the platform failing closed, which is correct, but the
dependency is new: Azure App Service and Azure SQL provided platform-managed availability, and the
equivalent is now the FIAU's to provide. Backup, restore, patching and cluster HA move to the FIAU
infrastructure team (OPERATIONS).

### Data residency — the change is favourable here

Session records, approval records, hostname telemetry and the audit chain now reside on FIAU
infrastructure rather than in an Azure region. For a financial intelligence unit that is a
meaningful improvement in the privacy posture, and it simplifies the data-protection position that
LOGGING_AND_PRIVACY has to defend. Only two categories leave the premises: the CA signing key,
which never leaves Key Vault because it is generated and used there, and audit export anchors,
which are hash-chained governance records containing no URL or hostname content.

### Cost

The Azure control-plane footprint — App Service plans, Azure SQL, and the associated networking —
disappears from the cost model, replaced by Key Vault and immutable blob storage, which are small.
The egress stamp is unchanged and remains the dominant Azure cost. Proxmox capacity, licensing and
operational effort become FIAU-side costs that COST_MODEL does not attempt to price.

### More than one instance is now a design question

App Service ran one instance, so nothing in the platform had to decide what happens when two copies
run at once. A Proxmox HA pair runs everything twice, and three things behave differently:

- **The ephemeral development CA is per process.** Two instances would issue session certificates
  from two different authorities, and an Envoy node trusting one would reject every session issued
  by the other. The startup guard above already prevents this outside Development, which is another
  reason the guard is part of this move rather than a later tidy-up.
- **The audit export is not obviously safe to run twice.** Both instances compute the same range and
  one loses the write-once race; the loss is logged and swallowed. With a shared sink that is
  merely wasted work, but with per-instance filesystem sinks it would leave one node's chain
  permanently unanchored while the host reports healthy — and `/api/audit/verify` would report the
  other instance's anchors as missing, which reads exactly like tamper evidence. A
  `Mina:Hosting:RunBackgroundServices` switch lets one instance be designated. It is a blunt
  instrument: the correct answer is a lease the instances contend for so failover does not depend on
  an operator moving a setting, and that is backlog M6-10.
- **The suppression expiry sweep is safe to run twice**, because each approval is expired in its own
  unit of work and the loser of a race gets a concurrency conflict the sweeper already handles.

### Configuration delivery becomes a security control

App Service settings and Key Vault references are replaced by configuration on a VM. The control
plane currently falls back to in-memory stores when no connection string is present and always
registers a development certificate authority, guarded only by a startup warning. On Azure that was
unlikely to be hit; with configuration delivered by hand or by a provisioning tool to a VM, a
mistyped setting would silently produce a "production" control plane with in-memory storage and a
signing key that regenerates on every restart. Startup must therefore refuse to run outside
Development without a real store and a real CA. This is scheduled with the move, not after it.

## Alternatives considered

**Publish the node-facing API from the DMZ instead of routing nodes over the tunnel.** The node
endpoints would be reachable at an internet-facing FIAU DMZ address, exactly as they are reachable
at an Azure address today. Egress nodes would keep talking to a public HTTPS endpoint and would
gain **no route into corporate networks at all**, so CLAUDE.md non-negotiable 4 would survive intact
and this ADR would not need to amend it. The cost is an internet-facing listener on FIAU
infrastructure, which needs the same treatment any DMZ service gets. **This is the recommended
alternative if the owner is willing to publish that one endpoint**, because it achieves the same
on-premises hosting with a strictly smaller change to the threat model. It was not chosen.

**Portal and SQL on premises with the API left in Azure.** Preserves non-negotiable 4 without a DMZ
listener, but makes every session issuance depend on an Azure-to-corporate SQL flow and reintroduces
the question of how an Azure-hosted API authenticates to an on-premises database. Not chosen.

**A thin Azure node-facing gateway in front of an on-premises control plane.** Preserves
non-negotiable 4 by keeping the nodes' counterparty in Azure. Rejected as a new component to build,
operate and secure for a property the DMZ-publish alternative achieves without one.

**Keeping everything in Azure.** The status quo ante; does not meet the owner's requirement.
