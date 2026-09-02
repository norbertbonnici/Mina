# ADR-0006: On-premises control plane in the FIAU Proxmox cluster

- Status: **Accepted 2026-09-01** (directed by the project owner). Supersedes the Azure-hosted
  control plane described in ARCHITECTURE §3.2.
- Date: 2026-09-01
- Related: `docs/ARCHITECTURE.md` §3.2/§4/§10, `docs/THREAT_MODEL.md`, `docs/adr/0005-telemetry-delivery.md`,
  `CLAUDE.md` non-negotiable property 4, decisions D-16…D-18

> **Revision note.** An earlier form of this ADR, committed the same day, had egress nodes reach the
> control plane over the Check Point site-to-site tunnel, which would have amended CLAUDE.md
> non-negotiable property 4. The owner reversed that within the day in favour of the alternative
> below. The record is kept because the reasoning matters: routing research egress into corporate
> networks was considered explicitly and declined, and property 4 stands unamended.

## Context

Phase 0 placed the whole control plane in Azure: API and management UI on App Service, Azure SQL for
sessions/approvals/audit/telemetry, Key Vault for the CA signing key, and managed identities
throughout. Egress stamps were separate Azure deployments that reached the control plane over public
TLS and were forbidden any route toward corporate networks.

The project owner has directed that the management platform — the portal, its web server, its logs
and the SQL database — be hosted on premises in the FIAU's Proxmox cluster. Because the control-plane
API and the management UI share one database, this necessarily moves the API as well, which raises
the question the earlier draft of this ADR got wrong: if the control plane is inside the FIAU
network, how do the Azure egress nodes reach it?

## Decision

**The Mina control plane runs on premises in the FIAU Proxmox cluster**, comprising the
control-plane API, the management portal, SQL Server, and the platform's own service logs. The Azure
egress stamps are unchanged.

**Egress nodes reach the control plane at an internet-facing address published from the FIAU DMZ.**
Nothing about the nodes' network posture changes: they call a public HTTPS endpoint, exactly as they
call an Azure one today. They gain no route into corporate networks, and
**CLAUDE.md non-negotiable property 4 stands unamended** — egress stamp NSGs continue to deny RFC1918
and corporate space outright, and the Check Point tunnel is not used by this platform at all.

Three supporting decisions were taken with it:

1. **SQL Server is Azure Arc-enabled** (D-17) so the control plane authenticates with Entra
   authentication and no stored credential, preserving the "no client secrets anywhere in the
   product" property of ARCHITECTURE §4.
2. **The CA signing key stays in Azure Key Vault and audit export anchors stay in Azure immutable
   blob storage** (D-18). These are the two guarantees that need hardware or platform enforcement
   and that a general-purpose Proxmox VM cannot provide: a signing key on a VM disk is not
   equivalent to a Key Vault key, and tamper-evidence anchored to a filesystem the same
   administrator controls is not evidence. The control-plane hosts are Arc-enabled, so they reach
   both with their Arc system-assigned managed identity — again with no stored secret.
3. **The node-facing API and the management portal are separate listeners with separate exposure**,
   and this is now load-bearing rather than defence in depth. The node-facing listener is published
   to the internet and carries only the session allowlist and telemetry ingest endpoints. The
   portal, the audit read API and every administrative endpoint are served on a corporate-facing
   listener only, never on the published one.

### Binding constraints

1. **Split listeners, enforced by binding, not by routing.** The two listeners bind separate ports
   and the reverse proxy publishes only the node-facing one. An endpoint that is not mapped on the
   published listener cannot be reached from the internet even if the proxy is misconfigured. On the
   published listener the rule is **default deny**: an endpoint that has not declared which listener
   it belongs to is refused there. That is not tidiness — ASP.NET Core substitutes a metadata-less
   synthetic endpoint when a path matches a route but the method does not, so serving undeclared
   endpoints let a wrong-method request enumerate the entire management route table, and its verbs,
   from the internet. The deny is one-directional: the corporate listener keeps normal framework
   behaviour, because it is not the exposure being defended.
2. **DMZ placement.** The control plane sits in a dedicated Proxmox DMZ VLAN, firewalled from the
   corporate LAN. Only the flows the platform needs cross that boundary: SQL (co-located in the same
   segment), Wazuh and SigNoz delivery, outbound Entra/Arc/Key Vault/Storage, and administrator
   access to the portal from corporate workstations.
3. **The published endpoint is treated as internet-exposed infrastructure.** TLS certificate from a
   public CA, rate limiting, and the same monitoring and patching discipline any published FIAU
   service gets. Optionally source-restricted to the Azure egress stamps' known NAT prefixes, which
   is cheap because those addresses are static and already known to the platform (D-07 records the
   equivalent restriction for the Azure ingress).
4. **Node identity unchanged.** Nodes authenticate with the per-region `Mina.Node.<region>` app
   role; a bare node role is entitled to nothing and region scoping is enforced server-side.
5. **Egress stamps keep their blanket corporate deny.** No peering, no gateway, no UDR toward
   corporate space. AC-017 continues to assert that all RFC1918 and corporate destinations are
   unreachable from a node, and remains a blanket assertion rather than an allowlist.

## Consequences

### What is traded, stated plainly

The platform previously published one internet-facing endpoint, in Azure. It now publishes one
internet-facing endpoint, in the FIAU DMZ. The exposure class is the same; what changes is where a
compromise of that endpoint lands — an Azure subscription before, a FIAU DMZ segment now. That is a
real difference and it is why constraints 1 and 2 exist: the published listener carries two endpoint
families and nothing else, and the segment it runs in is firewalled from the corporate LAN.

Compared with the tunnel route this ADR declined, the difference is larger and in the platform's
favour: there, a compromised *egress node* would have had a routed path into corporate networks. A
node is a machine whose entire job is to make connections to arbitrary places on the internet on
behalf of analysts, which makes it the least trustworthy component in the system. Keeping it on the
public side of the FIAU perimeter is worth publishing an endpoint for.

### Availability

Session issuance and renewal now depend on the Proxmox cluster and on the published endpoint being
reachable. Leases are about 60 minutes and renewal requires the control plane, so an outage stops
research browsing within one lease period. That is the platform failing closed, which is correct,
but the dependency is new: App Service and Azure SQL provided platform-managed availability and the
equivalent is now the FIAU's to provide. Backup, restore, patching and cluster HA move to the FIAU
infrastructure team.

Note what this does *not* depend on any more: the Check Point tunnel. Mina no longer uses it. Wazuh
and SigNoz are now a LAN hop from the control plane rather than a tunnel crossing, so ADR-0005's
delivery problem disappears rather than changing shape, and D-05's open precondition — network-team
confirmation of Check Point rule scoping — leaves the critical path.

### Data residency — the change is favourable

Session records, approval records, hostname telemetry and the audit chain now reside on FIAU
infrastructure rather than in an Azure region. For a financial intelligence unit that is a
meaningful improvement, and it simplifies the position LOGGING_AND_PRIVACY has to defend. Only two
categories leave the premises: the CA signing key, which never leaves Key Vault because it is
generated and used there, and audit export anchors, which are hash-chained governance records
carrying no URL or hostname content.

### Cost

The Azure control-plane footprint — App Service plans, Azure SQL and the associated networking —
leaves the Azure bill, replaced by Key Vault and immutable blob storage, which are small. The egress
stamp is unchanged and becomes the dominant Azure cost. Proxmox capacity, SQL Server licensing and
operational effort become FIAU-side costs that COST_MODEL does not price.

### More than one instance is now a design question

App Service ran one instance, so nothing had to decide what happens when two copies run at once. A
Proxmox HA pair runs everything twice, and three things behave differently:

- **The ephemeral development CA is per process.** Two instances would issue session certificates
  from two different authorities, and an Envoy node trusting one would reject every session issued
  by the other. The startup guard prevents this outside Development.
- **The audit export is not obviously safe to run twice.** Both instances compute the same range and
  one loses the write-once race; the loss is logged and swallowed. With a shared sink that is wasted
  work, but with per-instance filesystem sinks it would leave one node's chain permanently unanchored
  while the host reports healthy — and `/api/audit/verify` would report the other instance's anchors
  as missing, which reads exactly like tamper evidence. `Mina:Hosting:RunBackgroundServices`
  designates one instance; the correct answer is a contended lease, backlog M4-23.
- **The suppression expiry sweep is safe duplicated**, because each approval expires in its own unit
  of work and the loser of a race gets a concurrency conflict the sweeper already handles.

### Configuration delivery becomes a security control

App Service settings and Key Vault references are replaced by configuration on a VM. The control
plane previously fell back to in-memory stores when no connection string was present and always
registered a development certificate authority, guarded only by a startup warning. On Azure that was
unlikely to be hit; with configuration delivered by hand or by a provisioning tool to a VM, a
mistyped setting would silently produce a "production" control plane with in-memory storage and a
signing key that regenerates on every restart. Startup therefore refuses to run outside Development
without a real store, a real CA and a real audit sink.

## Alternatives considered

**Egress nodes reaching the control plane over the Check Point tunnel.** Briefly accepted and
reversed the same day. It would have required amending CLAUDE.md non-negotiable property 4, given a
compromised egress node a routed path into the FIAU network, converted AC-017 from a blanket
assertion into an allowlist assertion, and required infrastructure that does not exist: the egress
stamp's single subnet consumes the entire VNet CIDR, so there is no room for a `GatewaySubnet`, and
an NSG allow rule grants permission rather than reachability — a hub VNet, peering and a UDR would
all have been needed. Rejected in favour of publishing one endpoint.

**Portal and SQL on premises with the API left in Azure.** Preserves property 4 without publishing
anything, but makes every session issuance depend on an Azure-to-corporate SQL flow and reintroduces
the question of how an Azure-hosted API authenticates to an on-premises database. Not chosen.

**A thin Azure node-facing gateway in front of an on-premises control plane.** Also preserves
property 4, by keeping the nodes' counterparty in Azure. Rejected as a component to build, operate
and secure for a property that publishing one endpoint achieves without one.

**Keeping everything in Azure.** The status quo ante; does not meet the owner's requirement.
