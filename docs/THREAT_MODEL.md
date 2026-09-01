# Threat Model

Status: **Phase 0 expansion — Proposed** (baseline retained and extended; expand again whenever
the architecture changes)
Scope: architecture per `docs/ARCHITECTURE.md` (ADR-0001 Option C/C2, ADR-0002 Option 1).

## 1. Method

STRIDE per trust boundary (boundaries as listed in ARCHITECTURE/§ trust boundaries of the
original baseline), plus scenario analysis for the required cases and FIAU-specific abuse
cases. Each threat maps to mitigations and to the test that proves the mitigation
(`docs/TEST_STRATEGY.md`, `docs/ACCEPTANCE_CRITERIA.md`).

## 2. Assets (unchanged baseline + additions)

Analyst identity and Entra tokens; managed endpoint and privileged agent; session credentials
(client certs, internal CA key); Azure control plane and egress nodes; public egress IPs (and
their **reputation**); URL/hostname telemetry; sensitive-session requests/justifications;
audit records; management and break-glass credentials; IaC/CI/CD/signing material;
**subject-inference data** (any data from which research subjects can be inferred — hostnames,
justification text, timing patterns).

## 3. Threat actors (unchanged baseline)

External attacker; malicious website; compromised endpoint; stolen token/session; malicious or
curious authorised analyst; malicious insider/administrator; compromised Azure workload or
dependency; supply-chain attacker. Added: **research target performing counter-surveillance**
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
- **S:** stolen client cert reused elsewhere. *Mitigate:* 60-min TTL, renewal requires fresh
  Entra token (device-bound WAM/PRT), cert bound to session ID, node allowlist revocation.
  *Test:* token/cert expiry + revocation tests.
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

## 5. Required scenarios (baseline retained, responses updated to the design)

| Threat | Design response |
|---|---|
| Protected path fails, Edge falls back to normal IP | Fixed proxy (no DIRECT) + loopback gated on session + C2 WFP block; automated kill-tunnel e2e (AC-004) |
| DNS bypass exposes org resolver/IP | Hostname-in-CONNECT ⇒ egress-side resolution; WFP blocks direct 53/DoH from research binary; DNS canary test (AC-005) |
| IPv6 bypasses IPv4 tunnel | No local resolution; WFP blocks direct v6; IPv4-only egress at MVP; dual-stack tests (AC-006) |
| WebRTC exposes address/path | IP-handling policy + WFP UDP block + mDNS obfuscation; harness test (AC-007) |
| Analyst disables logging locally | Telemetry originates at egress node, not endpoint; nothing to disable client-side (ADR-0002 Opt 1) |
| Analyst obtains suppression without approval | Server-side state machine; activation requires APPROVED record, approver ≠ requester (AC-010) |
| Approval never expires | TTL mandatory, expiry terminates session, scheduler + clock-skew tests (AC-011) |
| Egress node becomes open proxy | mTLS against the internal CA; no unauthenticated listener; destination deny-list for private/link-local space; external scans (AC-016). The node does **not** check a session allowlist before admitting a tunnel, so a revoked session's certificate works until it expires (≈60 min) — backlog M4-11 |
| Egress node reaches internal networks | NSG/route deny + no peering + automated probes (AC-017) |
| Entra token stolen | Short session certs renewable only with fresh device-bound tokens; revocation ≤30 s at node |
| Egress host compromised | Minimal hardened image, no inbound mgmt from internet, least-privilege identity, Wazuh agent, disposable rebuild from IaC |
| Audit logs altered/deleted | Append-only writes, WORM export, restricted principals, Wazuh forwarding (tamper evidence) |
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

## 7. Residual risks (accepted, to be re-reviewed at production gate)

1. N1/N2 (correlation, cloud-IP reputation) — inherent until rotation; documented limitation.
2. C1-only residual (if C2 rejected): manual research-profile launch leak — detective controls.
3. Browser-process compromise rides the tunnel as the analyst (N3) — bounded by EDR/compliance.
4. AAAA-only destinations unreachable (IPv4-only egress at MVP).
5. Control-plane outage pauses new sessions (availability, not safety).

## 8. Security testing required

Baseline list retained (DNS, IPv4/IPv6, WebRTC, tunnel/control failure, region authz,
open-proxy scans, RFC1918 reachability, suppression authz/expiry, role boundaries, break-glass
alerting, token expiry/revocation) — concretised with tooling, environments and evidence
mapping in `docs/TEST_STRATEGY.md`. Additions from §6: rogue loopback client, IPC fuzzing,
startup-capture, prefetch-leak, suppression fail-open discrepancy, SigNoz/Wazuh content-leak
scans, signing/SBOM pipeline checks.
