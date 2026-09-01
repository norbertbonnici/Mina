# Architecture

Status: **Approved direction (D-01…D-04, 2026-08-31)** — implementation may proceed through
M0–M2; the steering design remains conditional on the M1-5 verification register (§13), and the
open decisions in `docs/PHASE0_DECISIONS.md` gate their referenced milestones.
Date: 2026-08-31

The approved choices: steering/transport per **ADR-0001** (Option C, variant C2, mTLS HTTP/2
transport), URL telemetry per **ADR-0002** (Option 1, hostname-at-egress, no TLS interception),
sensitive sessions per **ADR-0003**, .NET stack per **ADR-0004**.

## 1. Objective

Give authorised FIAU analysts a governed research-browsing path from Intune-managed Windows 11
endpoints whose public egress uses approved Azure EU addresses, while every other application on
the endpoint keeps ordinary corporate routing. Controlled attribution separation with full
governance — not anonymity, not a VPN into the corporate network, never an open proxy.

## 2. Architecture summary

```mermaid
flowchart LR
    subgraph EP["Managed Windows 11 endpoint"]
        RB["Research browser<br/>(dedicated Edge context)"]
        TRAY["Tray UI<br/>(status, region, requests)"]
        AG["Mina endpoint agent<br/>(SYSTEM service, signed)"]
        RB -- "fixed proxy 127.0.0.1" --> AG
        TRAY -- "ACL'd named pipe" --> AG
        OTHER["All other apps / ordinary Edge"]
    end

    OTHER -- "normal corporate egress (unchanged)" --> INET1[(Internet)]

    subgraph AZC["Azure — control plane (per env)"]
        API["Control-plane API<br/>(ASP.NET Core)"]
        UI["Management UI<br/>(Blazor)"]
        SQL[("Azure SQL<br/>sessions, approvals, audit")]
        KV["Key Vault<br/>(internal CA key, secrets)"]
        RELAY["Telemetry relay<br/>(Wazuh/SigNoz forwarding)"]
    end

    subgraph AZE["Azure — egress stamp (per approved EU region)"]
        LB["Public LB :443<br/>(ingress IP)"]
        ENV["Envoy VMSS<br/>mTLS + HTTP/2 CONNECT"]
        NAT["NAT Gateway<br/>static egress IP prefix"]
    end

    AG -- "1. Entra auth (WAM) + session request" --> API
    AG -- "2. mTLS HTTP/2 tunnel" --> LB --> ENV -- SNAT --> NAT --> INET2[(Internet<br/>research targets)]
    API <-- "session allowlist, suppression flags,<br/>hostname telemetry return" --> ENV
    ENTRA["Microsoft Entra ID<br/>+ Conditional Access + Intune compliance"] --- API
    ENTRA --- AG
    UI --- API
    API --- SQL
    API --- KV
    RELAY --> WZ["Wazuh (org)"]
    RELAY --> SN["SigNoz (org)"]
```

Two Azure planes, deliberately separated:

- **Control plane** (one per environment): session issuance, policy, approvals, audit store,
  management UI, internal CA, telemetry forwarding. Never carries research traffic.
- **Egress data plane** (one stamp per approved region): authenticated proxy nodes behind a
  public ingress IP, SNATing to dedicated static egress IPs. Never stores governance state;
  holds only ephemeral session allowlists pushed/pulled from the control plane.

## 3. Components

### 3.1 Endpoint (Intune-managed)

| Component | Form | Role |
|---|---|---|
| Endpoint agent | .NET Worker Service, runs as SYSTEM, Authenticode-signed, Intune Win32 app | Entra auth via WAM broker; session establishment/renewal; loopback proxy; mTLS tunnel client; WFP enforcement rules (variant C2); research-browser launch; local tamper monitoring |
| Tray/status UI | Per-user WPF app (`Mina.EndpointAgent.Tray`, **built**) | FR-006: protected/unprotected state, selected region, logging mode; region selection; sensitive-session request; talks to agent over named pipe ACL'd to the interactive user |
| Research browser | Dedicated Edge context per ADR-0001 C-enf decision (recommended: distinct-image-path Edge + dedicated user-data-dir) | The only thing that uses research egress |
| Edge integration | Shortcut/launch config + hardening flags (+ policies where instance-scoping allows) | Locks proxy, disables QUIC/DoH, forces WebRTC proxy behaviour for the research instance |

Endpoint enforcement design (variant C2, recommended):

1. Agent installs WFP rules for the research browser image path: **permit** loopback to the
   agent's proxy port; **block** all other outbound IPv4 and IPv6, including UDP/53, DoH to
   arbitrary resolvers, and WebRTC UDP. Rules exist whenever the agent is installed — not just
   during sessions — so a manually launched research browser has no network path at all.
2. The Mina shortcut starts the tray UI → agent authenticates and establishes the session →
   agent spawns the research browser with locked flags (`--user-data-dir`, `--proxy-server=127.0.0.1:<port>`,
   QUIC/DoH/WebRTC hardening flags; exact names pinned in Phase 1).

   > **Open question (raised building the tray, 2026-09-01).** The agent runs as SYSTEM in session
   > 0, and a service cannot spawn a process onto the interactive desktop without duplicating the
   > logged-on user's token (`WTSQueryUserToken` → `DuplicateTokenEx` → `CreateProcessAsUser`).
   > Three ways out, and the choice is security-relevant enough not to be made in passing:
   >
   > - **(a) Agent spawns via token duplication** — keeps the flag set in signed SYSTEM code where
   >   a user-mode process cannot influence it, at the cost of a privileged token operation in the
   >   agent.
   > - **(b) Tray spawns it** — no privileged token work, and the flags still live in signed code
   >   the analyst cannot edit, but a tampered tray could launch the research browser image with a
   >   different command line. WFP and the proxy peer check still bound what that browser reaches,
   >   so the flags are defence in depth either way.
   > - **(c) The Intune-deployed shortcut spawns it** with the flags baked in and the agent only
   >   supplying the port — which reintroduces a fixed, predictable port.
   >
   > Until this is decided, neither the agent nor the tray launches the browser, and the tray panel
   > offers no launch button. Nothing else in the tray depends on the answer.
3. The loopback proxy accepts connections only from the expected browser process (peer PID →
   image path + user-data-dir check) and only while an authenticated session exists. Otherwise
   it refuses — combined with fixed-proxy-no-fallback this is the fail-closed core (FR-007).
4. Named-pipe IPC: SDDL restricted (SYSTEM + interactive user read/write); all
   privileged operations validated server-side in the agent; no secrets in user-readable config
   (SR-006). **Built** — see `endpoint-agent/README.md` for the DACL, the `FirstPipeInstance`
   squat check, the frame and idle bounds, and which operations are re-validated.
5. Agent self-monitoring: reports tamper indicators (WFP rule removal attempts, unexpected
   research-browser instances, proxy-port probes from foreign processes) as security events.

### 3.2 Control plane (on premises, FIAU Proxmox cluster — ADR-0006)

Since ADR-0006 the control plane runs on the FIAU's own infrastructure, in a **dedicated DMZ VLAN**
rather than on the corporate LAN. That placement is a control, not a detail: egress nodes can reach
one endpoint in this segment, so it is treated as reachable by a compromised node and firewalled
from the corporate LAN accordingly.

- **Control-plane API** (ASP.NET Core on Linux, Kestrel behind the DMZ reverse proxy): session
  issuance/renewal/termination; region policy; sensitive-session state machine; internal-CA
  certificate issuance (signing key in Key Vault, never exported); node config distribution; audit
  event write path. **Two listeners with different exposure** (ADR-0006 constraint 3): the
  node-facing listener carries only the allowlist and telemetry-ingest endpoints and is the only
  surface reachable from the egress path; the portal, audit read and administrative endpoints are
  reachable only from corporate workstations.
- **Management UI** (Blazor static server rendering, same host family): approvals, session/health/
  audit visibility, region policy administration. Entra sign-in, app-role authorisation,
  Conditional Access (compliant device) enforced at the Entra layer. No longer internet-reachable,
  which removes it from the D-07 ingress rationale.
- **SQL Server on Proxmox, Azure Arc-enabled** (D-17): sessions, approvals, policy, audit events,
  hostname telemetry (separate schema; see §10). Arc enablement is what keeps Entra authentication
  and therefore the "no client secrets" property; encryption at rest and backup are now FIAU's to
  configure rather than platform-managed.
- **Azure Key Vault** (remains in Azure, D-18): internal CA key and Envoy server certificate
  material. Reached outbound from the control-plane hosts using their Arc-enabled server managed
  identity, so no credential is stored on premises either.
- **Azure immutable blob storage** (remains in Azure, D-18): audit export anchors. On-premises
  storage the same administrator controls cannot make an anchor tamper-evident.

Both hosts must supply what App Service used to: forwarded-header handling behind the reverse
proxy, a persisted Data Protection key ring, and configuration that is verified at startup — a
missing connection string now refuses the host rather than selecting an in-memory store.
- **Telemetry relay**: forwards audit/security events to Wazuh and OTLP telemetry to SigNoz
  (network path is decision D-05, §10.3).

### 3.3 Egress data plane (Azure, per approved region)

- **Public Standard Load Balancer** with one static **ingress** public IP, TCP 443 only.
  Optionally source-restricted to FIAU's corporate egress CIDRs (decision D-07).
- **Envoy on Linux VMSS** (2+ instances): terminates mTLS (platform internal CA; the client
  certificate must chain to that CA and be unexpired — Envoy does **not** check a session
  allowlist, so admission is by certificate validity alone; see the revocation note in §4 and
  backlog M4-11), terminates HTTP/2, serves CONNECT, applies the destination deny-list for
  private and link-local space, opens upstream connections, and emits per-connection hostname
  telemetry. Suppression is applied by the sidecar and the control plane, not by Envoy, which has
  no per-session policy of any kind.
  Hardened minimal image, rebuilt from IaC/pipeline, no inbound management from the internet
  (Azure-native management path only).
- **NAT Gateway** with a static public IP prefix (e.g. /30): the **egress** identity analysts
  appear from. Deliberately distinct from the ingress IP.
- **Node sidecar** (small, may be .NET): pulls session allowlist/suppression flags from the
  control-plane API every ~30 s using its managed identity — polling only; there is no push
  channel, and the pull interval bounds how quickly a *suppression* flag reaches the node, not how
  quickly a session stops being admitted. It ships Envoy telemetry to the control plane/relay and
  runs the Wazuh agent.
- **NSG/route posture**: outbound to Internet allowed; outbound to RFC1918, Azure service tags
  for corp-peered ranges, and the corporate public CIDRs **denied**; no VNet peering to
  anything except (optionally) the control-plane VNet for config — and even that is
  API-over-TLS, not routed reachability, if D-05 resolves to relay-in-control-plane.

## 4. Identity and access

- **Entra applications**: one enterprise app for the platform with app roles
  `Mina.Analyst`, `Mina.Approver`, `Mina.Admin`, group-assigned. Endpoint agent registered as a
  public client using the WAM broker (silent SSO from the existing Windows session — FR-002);
  management UI as a confidential client; egress node sidecars and control plane use Azure
  managed identities (no client secrets anywhere in the product).
- **Conditional Access**: policy targeting the Mina app requiring compliant (Intune) device and
  the org's MFA baseline. Device identity/compliance is evaluated at token issuance via the
  WAM/PRT flow; the control plane records the device ID per session (FR-003, SR-007).

  What the control plane can and cannot see, stated exactly, because the distinction has been
  misread before: an Entra access token carries **no Intune compliance claim**. A `deviceid` claim
  proves the device is Entra-*registered* and that the token came from a device-bound flow — a
  registered device that is actively failing its compliance policy emits the same claim. The
  control plane therefore refuses a token that is not device-bound (`DeviceNotBound`), which is a
  real control but not a compliance check.

  Compliance is proved by **Conditional Access authentication context**. An auth context (say `c1`)
  is defined in the tenant, a CA policy granting on "device marked as compliant" is bound to it, and
  `Mina:Session:RequiredAuthContextId` is set to that value. Entra then emits the id in the token's
  `acrs` claim only when that policy was actually satisfied, and the control plane requires it —
  answering `401` with a `WWW-Authenticate: Bearer error="insufficient_claims"` challenge otherwise,
  so a compliant device steps up silently from its PRT. This is fail-closed and self-verifying in a
  way the `deviceid` check is not: delete, mis-scope or add an exclusion to the policy and the claim
  stops arriving and sessions stop being issued.

  A challenge is a protocol step, not a refusal, and it is recorded as an `authz_denied` audit event
  with reason `AuthenticationContextRequired` like any other denial. Operators and anyone reading
  the trail should expect a baseline of these once the requirement is on: a device that cannot
  comply shows up as challenges that never convert into an established session, not as the presence
  of challenges. Over-recording is the deliberate direction for the audit trail, so the event is
  kept rather than suppressed.

  **Deployment prerequisite.** The setting is empty by default because it has a tenant-side
  precondition (the auth context and the policy bound to it, backlog M2-1). Setting it before that
  exists refuses every session — the safe direction, but a deployment step rather than a default.
  The endpoint agent must also answer the challenge by re-acquiring with `.WithClaims(...)`; the
  current agent uses a configured-token stand-in and cannot, so this lands with the WAM broker in
  M2-4. Until both are in place, compliance is enforced by Conditional Access alone and the
  platform cannot detect a missing policy.
- **Session lease model**: Entra access tokens are minutes-to-an-hour artefacts; research
  sessions need tighter control. The control plane therefore issues its own **session-bound
  client certificate** (TTL ≈ 60 min, renewable only with a fresh valid Entra token) plus a
  session record with state. Revocation = stop renewing. The certificate already
  issued stays valid until its TTL elapses, so the revocation window today is that TTL (≈60 min);
  the node's allowlist governs suppression, not admission, and pushing a removal to nodes does not
  currently refuse an established or re-offered certificate. Node-side allowlist enforcement, which
  would bring revocation down to the push/pull interval, is backlog M4-11. No CAE dependency.
- No local passwords, no separate credential store, break-glass excepted (§12).

```mermaid
sequenceDiagram
    participant U as Analyst
    participant T as Tray UI
    participant A as Agent (SYSTEM)
    participant E as Entra ID (+CA)
    participant C as Control plane
    participant X as Egress node (Envoy)
    U->>T: Launch Mina, pick approved region
    T->>A: Start session (named pipe)
    A->>E: Silent token via WAM broker (existing session)
    E-->>A: Access token (user, roles, device claims)
    A->>C: POST /sessions {region, CSR} + token
    C->>C: Authorise: role, region approved, device-bound token (+ CA auth context when configured)
    C-->>A: Session ID + client cert (60 min) + egress endpoint
    X->>C: Pull session allowlist (~30 s, suppression flags only)
    C->>C: Audit: session_started → Wazuh
    A->>X: mTLS HTTP/2 tunnel (client cert)
    A->>A: Open loopback proxy, then spawn research browser
    loop while browsing
        A->>C: Renew (fresh WAM token) before cert expiry
    end
    U->>T: End session (or browser closed / tunnel lost)
    A->>C: DELETE /sessions/{id}
    C->>X: Remove session → connections dropped
```

## 5. Traffic path and fail-closed behaviour

Research request path: browser → `CONNECT host:443` to loopback proxy → agent multiplexes over
the mTLS HTTP/2 session → Envoy authorises the session, resolves the hostname via the Azure
resolver, connects out via NAT Gateway → target sees the approved egress IP (AC-003).

Fail-closed (FR-007, AC-004) is layered — every failure lands on "no traffic", never "wrong path":

| Failure | Behaviour |
|---|---|
| Tunnel drops / egress unreachable | Agent closes the loopback listener; browser gets proxy errors; fixed proxy config cannot fall back to DIRECT; agent retries and surfaces state in tray |
| Agent killed / crashes | Loopback proxy gone ⇒ browser has no path; C2 WFP rules persist independently of the agent process, so even flag-stripped launches stay contained |
| Session revoked / expired | Control plane stops renewal; the already-issued certificate keeps working until it expires, so the revocation window is the lease TTL (≈60 min), not the allowlist refresh interval. The node's allowlist governs suppression, not admission — Envoy admits any unexpired certificate chaining to the internal CA. Loopback closes when the agent's renewal is refused. Node-side allowlist enforcement is backlog M4-11 |
| Control plane down | Existing sessions continue until cert expiry (bounded), no new sessions; policy: certificates are short so exposure is capped |
| Research browser launched outside the agent | C2: WFP allows only loopback ⇒ nothing works until a session exists; C1 fallback: detective controls only (ADR-0001) |

## 6. Leak controls

| Vector | Control | Verified by |
|---|---|---|
| DNS | Proxied requests carry hostnames; resolution happens at egress via Azure resolver; research browser's direct UDP/TCP 53 and DoH blocked by WFP (C2) and DoH disabled by flags; corporate resolvers never see research names | DNS canary test (authoritative-server observation), AC-005 |
| Fallback to corporate egress | Fixed proxy, no DIRECT; loopback closed unless session live; WFP default-block for research binary | Kill-tunnel e2e test, AC-004 |
| IPv6 | No local resolution (no AAAA path); WFP blocks direct IPv6 from research binary; egress is IPv4-only at MVP (NAT GW limitation — AAAA-only sites unreachable; accepted, documented) | Dual-stack leak tests, AC-006 |
| WebRTC | Browser IP-handling forced to proxy-only/non-proxied-UDP-disabled for the research instance; C2 WFP blocks its UDP anyway; mDNS ICE obfuscation remains default | WebRTC harness page, AC-007 |
| QUIC/HTTP3 | Disabled for the research instance (flag/policy); WFP blocks UDP/443 regardless | Network capture during e2e, AC-006/007 |
| Ordinary apps captured by mistake | Only the research image path has WFP rules; only the research instance has the proxy config; nothing else references the agent | Negative-path test: normal Edge/apps exit via corp IP, AC-002 |
| Open proxy | Envoy requires platform mTLS (a client certificate chaining to the internal CA); LB exposes 443 only; optional source-CIDR restriction. Note this authenticates the *platform*, not a particular live session — see the revocation row | External open-proxy scan, AC-016; real-Envoy client-authentication test |
| Egress → corp | NSG/route denies RFC1918 + corp CIDRs from egress subnets; no peering to corp | Automated reachability probes from nodes, AC-017 |

## 7. Session and sensitive-session lifecycle

Session states: `ESTABLISHING → ACTIVE → (RENEWING) → ENDED | REVOKED | EXPIRED`.
Sensitive-session overlay per ADR-0003:

```mermaid
stateDiagram-v2
    [*] --> NORMAL
    NORMAL --> REQUESTED: analyst request (justification + duration)
    REQUESTED --> DENIED: approver denies
    REQUESTED --> APPROVED: approver (≠ requester) approves, TTL set
    REQUESTED --> CANCELLED: analyst withdraws
    APPROVED --> ACTIVE_SUPPRESSED: control plane activates; nodes pick the flag up on next pull
    ACTIVE_SUPPRESSED --> ENDED_EXPIRED: TTL expiry ⇒ session terminated (D-06a: activated only)
    ACTIVE_SUPPRESSED --> ENDED_EXPIRED: analyst ends early
    DENIED --> NORMAL
    CANCELLED --> NORMAL
    ENDED_EXPIRED --> NORMAL: analyst may start a fresh normal session
```

All transitions are control-plane operations, audited, Wazuh-forwarded. During
`ACTIVE_SUPPRESSED`, egress nodes record no hostnames for the session — only
suppression markers, aggregate counters, and the mandatory metadata set (ADR-0003).

## 8. Azure resource design

Environments `dev`, `test`, `prod` as separate Terraform states (and ideally subscriptions);
naming `rg-mina-<plane>-<env>[-<region>]`.

**Control plane (per env):**

| Resource | Notes |
|---|---|
| Resource group `rg-mina-core-<env>` | |
| App Service plan (Linux P1v3; dev: B-series) + 2 apps (API, UI) | VNet-integrated; managed identities |
| Azure SQL Database (GP serverless; prod: provisioned GP) | Private endpoint; TDE; audit + telemetry schemas |
| Key Vault (RBAC, purge protection) | Internal CA key (non-exportable), certs, integration secrets |
| VNet + subnets (app-integration, private-endpoints, relay) | No peering to corp |
| Storage account (immutable/WORM container) | Periodic signed audit export for tamper evidence |
| Log Analytics workspace | Platform diagnostics; Entra/Azure activity export for break-glass alerting |
| Telemetry relay (small VM or Container App) | Wazuh/SigNoz forwarding per D-05 |

**Egress stamp (per approved region, per env):**

| Resource | Notes |
|---|---|
| Resource group `rg-mina-egress-<env>-<region>` | |
| VNet + egress subnet + NSG | Outbound deny RFC1918 + corp CIDRs; inbound 443 only |
| Standard public LB + 1 static ingress IP | TCP 443 → Envoy |
| Linux VMSS (2 × D2as_v5; dev: 1 × B2s) | Hardened image, Envoy + sidecar + Wazuh agent; no public per-instance IPs |
| NAT Gateway + public IP prefix /30 | Static approved egress IPs; headroom for post-MVP rotation |

Approved region list (D-08, decided 2026-08-31): `westeurope`, `northeurope`,
`germanywestcentral`, `francecentral`. Analysts can select only regions with an **active**
stamp: dev/MVP runs one (`westeurope`); production launches with **one active stamp** (D-11),
with further approved regions activated on demand (~€240/mo each, COST_MODEL).

## 9. Capacity and availability

50 concurrent analysts browsing is small: plan ~2–10 Mbps sustained aggregate per region with
bursts; 2 × D2as_v5 Envoy nodes are comfortably over-provisioned (headroom + N+1). Azure SQL at
GP serverless handles the write rates (hostname telemetry est. < 10 events/s aggregate).
Scale-out is VMSS instance count; scale-up is SKU. NAT GW SNAT ports are a non-issue at this
scale (64k/IP × 4 IPs).

Availability posture per D-11 (2026-08-31): production launches with a single active egress
region, so a full region outage pauses research browsing (fail-closed — never a leak) until
another approved region's stamp is activated from IaC. This is an accepted availability
trade-off, revisited when usage justifies a standing second stamp; node-level HA within the
stamp (2+ instances, zones optional) still applies in production.

## 10. Audit and telemetry

### 10.1 Stores and flows

- **Audit events** (governance: auth results, session lifecycle, approvals, policy/admin
  actions, break-glass): written synchronously by the control plane to SQL, exported to the
  WORM container on schedule, forwarded to **Wazuh**. Wazuh receives *security/audit* events
  only — never URL/hostname content.
- **Hostname telemetry** (ADR-0002 Option 1): Envoy → sidecar → control-plane ingest →
  SQL telemetry schema. Correlated with user/device/session (AC-009). Retention configurable,
  TBD by DPO (D-09). Suppression enforced at the node (§7).
- **Operational telemetry**: OpenTelemetry from control plane, agent (non-sensitive), and
  nodes → **SigNoz** via OTLP. A scrub processor strips URLs/hostnames from anything bound for
  SigNoz (AC-014); dashboards per `docs/OPERATIONS.md`.

### 10.2 Event schemas

Defined in `docs/EVENT_SCHEMAS.md` (envelope, event catalogue, severities, Wazuh mapping,
SigNoz metric/trace inventory).

### 10.3 Reaching org-hosted Wazuh/SigNoz (decided — ADR-0005)

Delivery uses the organisation's **existing Check Point site-to-site tunnel** between the
corporate network and Azure (D-05, 2026-08-31), under ADR-0005's binding constraints: only the
control-plane **relay subnet** routes toward corp, only to the Wazuh/SigNoz receiver
addresses/ports, enforced both by Azure NSG/UDR and the Check Point policy; no corp-initiated
flows into the platform are added. **Egress stamps stay entirely off this path** — their VNets
are never peered or routed to the corp-connected hub, so the "no route from research egress into
corporate networks" invariant (SR-001, CLAUDE.md #4) is unchanged. Egress nodes deliver
telemetry only to the control-plane relay over public TLS. Check Point rule scoping is
confirmed with the network team before M3-5/6.

## 11. Network invariants → enforcement mapping

| Invariant | Enforced by |
|---|---|
| Ordinary apps never use research egress | Proxy config + WFP rules exist only for the research browser image/instance |
| Protected traffic never falls back to ordinary egress | Fixed proxy no-DIRECT; loopback gated on live session; C2 WFP default-block |
| Research egress reaches exactly one corporate address | Scoped exception (ADR-0006): NSG + UDR permit one control-plane host and port, everything else in corporate space denied; Check Point policy enforces the same set independently; automated probes assert both the permitted flow and the denials (AC-017) |
| Management endpoints authenticated, and unreachable from the egress path | Entra + Conditional Access on UI/API; the portal and audit read are not served on the node-facing listener at all (ADR-0006 constraint 3); nodes authenticate with a per-region app role |
| No public unauthenticated proxy/forwarder | mTLS-only Envoy listener; 443-only LB; optional source-CIDR allowlist; external scans (AC-016) |

## 12. Break glass (management-only)

Proposed definition (decision D-10): break glass = regaining *administrative* control of the
platform when the normal path (Entra sign-in + management UI) is unavailable. It is composed of
existing enterprise mechanisms — **no application backdoor exists**:

- Two cloud-only Entra emergency-access accounts (org standard practice), excluded from the CA
  policies that could lock admins out, credentials vaulted offline under management custody,
  sign-in monitored: any use → high-severity Wazuh event via the Entra sign-in log export
  (AC-015, SR-009).
- Azure RBAC emergency group (PIM-eligible, approval-gated) able to operate the platform
  directly (e.g. disable an egress region by stopping the VMSS/LB) when the control plane is
  down. All activity-log events for these principals → high-severity Wazuh events.
- Analyst-facing componentry contains no break-glass code paths, credentials, or configuration.
- Every use triggers the post-use review runbook (`docs/OPERATIONS.md`).

## 13. Phase 1 verification register

The load-bearing Windows/Edge behaviours this design assumes are listed in ADR-0001
(§ Verification register) and must be prototype-verified before ADR-0001 is Accepted. Any
failure there returns this document to Proposed for rework — do not build past it.

## 14. References

Requirements: `docs/REQUIREMENTS.md` · Threats: `docs/THREAT_MODEL.md` · Logging:
`docs/LOGGING_AND_PRIVACY.md` · Events: `docs/EVENT_SCHEMAS.md` · Cost: `docs/COST_MODEL.md` ·
Tests: `docs/TEST_STRATEGY.md` · Backlog: `docs/BACKLOG.md` · Decisions: `docs/PHASE0_DECISIONS.md`
