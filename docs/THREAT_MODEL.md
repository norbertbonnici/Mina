# Threat Model

Status: **Phase 0 expansion — Proposed** (baseline retained and extended; expand again whenever
the architecture changes)
Scope: architecture per `docs/ARCHITECTURE.md` (ADR-0001 Option C/C2, ADR-0002 Option 1, hybrid
hosting per ADR-0006 — revised 2026-09-02).

## 1. Method

STRIDE per trust boundary (boundaries as listed in ARCHITECTURE/§ trust boundaries of the
original baseline), plus scenario analysis for the required cases and FIAU-specific abuse
cases. Each threat maps to mitigations and to the test that proves the mitigation
(`docs/TEST_STRATEGY.md`, `docs/ACCEPTANCE_CRITERIA.md`).

## 2. Assets (unchanged baseline + additions)

Analyst identity and Entra tokens; managed endpoint and privileged agent; session credentials
(client certs, internal CA key in Key Vault); the on-premises control plane (Proxmox DMZ VLAN, its
published node-facing endpoint, SQL Server) and the Azure egress nodes; the Arc managed identities
of the control-plane hosts; public egress IPs (and their **reputation**); URL/hostname telemetry; sensitive-session requests/justifications;
audit records; management and break-glass credentials; IaC/CI/CD/signing material;
**subject-inference data** (any data from which research subjects can be inferred — hostnames,
justification text, timing patterns).

## 3. Threat actors (unchanged baseline)

External attacker; malicious website; compromised endpoint; stolen token/session; malicious or
curious authorised analyst; malicious insider/administrator; compromised Azure workload or
dependency; compromised on-premises host or Proxmox/hypervisor administrator (ADR-0006);
supply-chain attacker. Added: **research target performing counter-surveillance**
(observes visits, probes egress IPs, attempts correlation).

## 4. Boundary analysis (STRIDE highlights)

### B1. Analyst ↔ privileged endpoint components (agent, WFP, IPC)
- **E (EoP):** named-pipe command abuse → agent performs privileged action for unauthorised
  caller. *Mitigate:* SDDL-restricted pipe, per-message authorisation in agent, no
  config-driven code paths, signed binaries, Intune-managed config only. *Test:* IPC fuzz +
  privilege boundary tests.
- **T (Tamper):** analyst strips launch flags or edits profile. *Mitigate:* C2 WFP
  default-block makes flag-stripping inert; agent detects unmanaged research-browser
  instances. *Test:* manual-launch leak test.
- **S (Spoof):** foreign process connects to loopback proxy to ride the tunnel (local open
  proxy). *Mitigate:* peer-PID → image-path/user-data-dir verification; per-session proxy
  port; refuse when no session. *Test:* rogue-client connect attempt.

### B2. Research context ↔ ordinary applications
- **I (Info disclosure):** research profile data (cookies, history) exits via corporate egress
  through a mis-launched browser. *Mitigate:* C2 network containment; profile data
  minimisation (no sync). *Test:* AC-002/AC-004 negative paths.
- Ordinary apps accidentally captured: impossible by construction (nothing else references the
  proxy/rules). *Test:* AC-002.

### B3. Endpoint ↔ Azure ingress
- **S:** stolen client cert reused elsewhere. *Mitigate:* 60-min TTL and renewal requiring a fresh
  device-bound Entra token; the certificate carries its session id in a SAN URI, which attributes
  its traffic but is **not checked for admission** — the node has no session allowlist enforcement
  (D-14), so a stolen certificate works until it expires. The TTL is therefore the whole of this
  mitigation, not a backstop to it. *Test:* token/cert expiry tests; a revocation-latency test must
  measure against the lease TTL (see M4-11 if that is to change).
- **D (DoS):** ingress flooding. *Mitigate:* 443-only, optional corp-CIDR allowlist, LB/NSG,
  autoscale headroom, alerting. *Test:* load test + alert check.

### B4. Data plane ↔ control plane
- **T:** compromised node lies about telemetry or ignores suppression flags. *Mitigate:*
  nodes are least-privilege (managed identity scoped to read-allowlist/write-telemetry only),
  immutable/rebuildable, monitored (Wazuh agent); suppression state is logged both at control
  plane (authoritative) and node ack; discrepancy alerting. *Test:* suppression e2e + node
  integrity monitoring.
- **E:** node's managed identity abused to read governance data. *Mitigate:* API scopes the
  node identity to its own region's allowlist + telemetry ingest only. *Test:* RBAC boundary
  tests.
- **I/E (published endpoint, ADR-0006):** the node-facing listener is internet-exposed from the
  FIAU DMZ, so an attacker probes it for the portal, the audit read API or the route table.
  *Mitigate:* split listeners discriminated by the accepting port, default deny for undeclared
  endpoints (a wrong-method request cannot enumerate the management routes), the check running
  before authentication; the reverse proxy has no server block for the management port; per-host
  firewall admits the node port only from the proxy; public-CA TLS, rate limiting, optional source
  restriction to the stamps' static NAT prefixes; the DMZ is firewalled from the corporate LAN.
  *Test:* listener-separation suite (M4-16) + external scan of the published endpoint.
- **D:** loss of the published endpoint stops allowlist pulls, telemetry and session renewal.
  Fails closed within one lease period — availability, not safety (OPERATIONS runbook).

### B5. Control plane ↔ Entra
- **S:** forged/replayed tokens. *Mitigate:* standard validation (issuer, audience, signing,
  lifetime), device claims required, CA compliant-device policy. *Test:* tampered-token suite.
- **R (Repudiation):** disputed approvals. *Mitigate:* immutable audit export (WORM), approver
  identity + timestamps in every transition, Wazuh forwarding. *Test:* audit completeness.

### B6. Platform ↔ Wazuh/SigNoz
- **I:** sensitive URLs leak into observability. *Mitigate:* Wazuh path carries no
  URL/hostname content by design; SigNoz path has a scrub processor; schema review gate.
  *Test:* AC-014 leak scan of exported telemetry.
- **D:** integration outage hides security events. *Mitigate:* local buffering, delivery-lag
  metrics + alerts; policy option to refuse new sessions if the audit write path is down.

### B7. Analyst ↔ manager/approver roles
- **E:** self-approval or role confusion. *Mitigate:* server-side rejection of
  requester==approver; app-role checks in API not UI; periodic access review. *Test:*
  authorisation matrix tests.
- Collusion (approver rubber-stamps): governance issue — mitigated by audit visibility,
  approval-rate reporting to management, no permanent exemptions.

### B8. Normal admin ↔ break glass
- **E/T:** break-glass creds abused silently. *Mitigate:* vaulted offline custody, sign-in +
  activity-log export → high-severity Wazuh alerts, post-use review runbook, PIM approval for
  the RBAC group. *Test:* break-glass alerting drill (AC-015).
- **Gap (ADR-0006):** the Azure RBAC group cannot reach a Proxmox-hosted API, portal or database,
  so the on-premises plane has no break-glass mechanism yet — backlog M4-21.

### B9. On-premises control plane ↔ Azure retained services (Key Vault, immutable blob)
- **S/E:** a compromised control-plane host uses its Arc managed identity to sign certificates or
  read anchors. *Mitigate:* identity scoped to sign/get on the CA key and write on the anchor
  container only; Key Vault and storage firewalls admit only the control plane's egress addresses;
  CA key use and anchor access recorded in Log Analytics (M4-24); ARM-level tamper (immutability
  policy removal, vault purge) needs the subscription activity-log export (M4-26). *Test:* RBAC
  boundary tests; alert drill on anomalous signing volume.
- **T (on-premises administrator):** a Proxmox or SQL administrator alters audit rows or VM disks.
  *Mitigate:* hash-chained audit trail anchored in write-once Azure storage the same administrator
  does not control — D-18 exists for exactly this — and `/api/audit/verify`. *Test:* audit
  completeness against anchors; tamper-then-verify.
- **D:** Arc agent failure removes SQL authentication and Key Vault access at once, with no stored
  credential to fall back on by design. Fails closed; OPERATIONS runbook.

## 5. Required scenarios (baseline retained, responses updated to the design)

| Threat | Design response |
|---|---|
| Protected path fails, Edge falls back to normal IP | Fixed proxy (no DIRECT) + loopback gated on session + C2 WFP block; automated kill-tunnel e2e (AC-004) |
| DNS bypass exposes org resolver/IP | Hostname-in-CONNECT ⇒ egress-side resolution; WFP blocks direct 53/DoH from research binary; DNS canary test (AC-005) |
| IPv6 bypasses IPv4 tunnel | No local resolution; WFP blocks direct v6; IPv4-only egress at MVP; dual-stack tests (AC-006) |
| WebRTC exposes address/path | IP-handling policy + WFP UDP block + mDNS obfuscation; harness test (AC-007) |
| Analyst disables logging locally | Telemetry originates at egress node, not endpoint; nothing to disable client-side (ADR-0002 Opt 1) |
| Analyst obtains suppression without approval | Server-side state machine; activation requires APPROVED record, approver ≠ requester (AC-010) |
| Approval never expires | TTL mandatory; expiry ends the approval always, and terminates the session when suppression was activated (D-06a); scheduler + clock-skew tests (AC-011) |
| Egress node becomes open proxy | mTLS against the internal CA; no unauthenticated listener; destination deny-list for private/link-local space; external scans (AC-016). The node does **not** check a session allowlist before admitting a tunnel, so a revoked session's certificate works until it expires (≈60 min) — backlog M4-11 |
| Egress node reaches internal networks | NSG/route deny + no peering + automated probes (AC-017). Unchanged by ADR-0006, which deliberately declined the tunnel route: the on-premises control plane is reached at a published DMZ endpoint over the public internet, so this stays a blanket denial rather than becoming an allowlist |
| Entra token stolen | Short session certs renewable only with fresh device-bound tokens. Revocation is refusal to renew, so the exposure window is the lease TTL (≈60 min) — **not** ≤30 s: the node performs no allowlist check before admitting a tunnel (D-14, M4-11) |
| Egress host compromised | Minimal hardened image, no inbound mgmt from internet, least-privilege identity, Wazuh agent, disposable rebuild from IaC. Blast radius is unchanged by ADR-0006: the node's reachable set is still the public internet plus one published control-plane endpoint, which is what it was when that endpoint was in Azure. What the endpoint exposes is bounded by the split listeners — the published listener carries only allowlist and telemetry ingest, never the portal or the audit read API |
| Audit logs altered/deleted | Append-only writes, WORM export, restricted principals, Wazuh forwarding (tamper evidence). Since ADR-0006 the store is on FIAU infrastructure and the anchors are in Azure immutable storage, so an on-premises administrator cannot make an alteration unanchored (D-18); anchor access is itself logged (M4-24) |
| Published control-plane endpoint used to reach the portal, audit API or admin routes | Split listeners enforced by accepting port with default deny; the proxy has no management-port server block; host firewall; 404 before authentication (ADR-0006 constraint 1, M4-16) — see B4 |
| Break-glass abused | §4/B8 |
| Dependency compromised | SBOM + lockfiles (NuGet, container images, Envoy builds), pinned versions, scanning in CI, signed artefacts (SR-012) |

## 6. Additional scenarios identified in Phase 0

| # | Threat | Response |
|---|---|---|
| N1 | **Cross-investigation correlation:** targets observe the small set of egress IPs and correlate visits across analysts/cases | Accepted MVP risk (documented to analysts); region selection gives coarse separation; post-MVP IP rotation (Phase 5) is the real mitigation; never present platform as anonymity |
| N2 | **Egress IP reputation/blocklisting** (targets or CDNs block/flag Azure IPs) | Operational monitoring, region switch as workaround, IP-prefix headroom for replacement; note some sites treat cloud IPs with suspicion — inherent limitation |
| N3 | Malware on endpoint uses analyst's live session to browse via research egress | Loopback PID checks raise the bar (not absolute — malware could inject into the browser); compensations: compliant-device requirement (EDR), telemetry attribution to device, hostname audit anomalies |
| N4 | Justification text contains operational secrets, leaks via approval UI/notifications | Guidance: reference case numbers, not content; approver UI access-controlled; justifications classified as subject-inference data (LOGGING_AND_PRIVACY data classes) |
| N5 | Suppression-flag failure open (node keeps logging during approved sensitive session) | Node ack + control-plane verification; alert on discrepancy; defined incident handling (purge mis-collected records under DPO procedure) |
| N6 | Terraform state exposes secrets/topology | Remote state in access-controlled storage with encryption; no secrets in state (managed identities/Key Vault); state access audited |
| N7 | CI/CD compromise ships malicious agent (signed) to all analyst endpoints | Protected branches, review gates, isolated signing (cert in HSM/KV, signing step approval-gated), SBOM diff alerts; Intune rollout rings |
| N8 | Envoy CVE on the exposed listener | 443-only + mTLS-first handshake limits pre-auth surface; fast-patch pipeline (rebuild stamp); CVE watch |
| N9 | Admin quietly widens region list or policy | Policy changes are audited high-visibility events to Wazuh; IaC + PR review for infra-level change |
| N10 | Hostname telemetry itself becomes a surveillance tool against analysts | Purpose limitation + access control on telemetry schema; access to telemetry is itself audited; retention minimised (D-09) |
| N11 | Time-of-check gaps at browser startup (traffic before proxy/rules ready) | C2 rules are persistent (pre-exist launch); agent spawns browser only after listener up; startup capture test |
| N12 | Endpoint DNS cache/prefetch leaks research names before proxying | Browser prefetch/preconnect disabled via flags for research instance; WFP DNS block for the binary; verify in Phase 1 |
| N13 | Proxmox API token or the on-premises Terraform state exposed (ADR-0006) | Token read from the environment only — never a variable, tfvars or state; state in the same access-controlled Azure storage as the Azure environments (N6); cloud-init carries no secrets |
| N14 | DMZ segment compromised via the published endpoint lands inside the FIAU perimeter | DMZ VLAN firewalled from the corporate LAN with only the platform's flows crossing; the endpoint carries two route families and nothing else; treated as internet-exposed infrastructure (patching, monitoring, rate limiting). Preferred over the tunnel alternative, where a compromised *egress node* would have had a routed corporate path |

## 7. Residual risks (accepted, to be re-reviewed at production gate)

1. N1/N2 (correlation, cloud-IP reputation) — inherent until rotation; documented limitation.
2. C1-only residual (if C2 rejected): manual research-profile launch leak — detective controls.
3. Browser-process compromise rides the tunnel as the analyst (N3) — bounded by EDR/compliance.
4. AAAA-only destinations unreachable (IPv4-only egress at MVP).
5. Control-plane outage pauses new sessions and stops renewals within one lease period
   (availability, not safety). Since ADR-0006 that availability is the FIAU's to provide: one of
   each host today (M4-15), HA and backup/restore in M4-22.

## 8. Security testing required

Baseline list retained (DNS, IPv4/IPv6, WebRTC, tunnel/control failure, region authz,
open-proxy scans, RFC1918 reachability, suppression authz/expiry, role boundaries, break-glass
alerting, token expiry/revocation) — concretised with tooling, environments and evidence
mapping in `docs/TEST_STRATEGY.md`. Additions from §6: rogue loopback client, IPC fuzzing,
startup-capture, prefetch-leak, suppression fail-open discrepancy, SigNoz/Wazuh content-leak
scans, signing/SBOM pipeline checks; from ADR-0006: listener separation on the published endpoint,
external scan of that endpoint, Arc identity scope, tamper-then-verify against the anchors.
