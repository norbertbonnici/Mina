# Phase 0 — Decision Log

Status: **All Phase 0 decisions (D-01…D-12) are decided** — D-01…D-04 on 2026-08-31 (initial
gate), D-05…D-12 on 2026-08-31 (owner Q&A round) — and six post-Phase-0 decisions (D-13…D-18) were
taken on 2026-09-01, of which D-16…D-18 (ADR-0006) move the control plane on premises. D-05's open
precondition (network-team confirmation of Check Point rule scoping) is **closed as moot**: ADR-0006
superseded ADR-0005 and no Mina component uses the tunnel. Retention values (D-09) still require
DPO/legal ratification before production per REQUIREMENTS §5.

## Decisions taken

| ID | Decision | Outcome | Date / by |
|---|---|---|---|
| D-01 | URL telemetry method (ADR-0002) | **Option 1 — hostname-level at egress, no TLS interception.** Options 2/3 only via a future ADR + DPO approval | 2026-08-31, project owner |
| D-02 | Steering/transport architecture (ADR-0001) | **Option C** — agent + loopback proxy + mTLS HTTP/2 CONNECT to Envoy | 2026-08-31, project owner |
| D-03 | Enforcement variant (ADR-0001 C-enf) | **C2** — distinct research-browser image path + SYSTEM WFP rules; channel trade-off accepted (A4). Final confirmation against M1-5 prototype evidence; C1 remains the documented fallback | 2026-08-31, project owner |
| D-04 | Phase 1 PoC build | **Approved** — one test region + lab within the dev cost envelope (≤ €150/mo) | 2026-08-31, project owner |
| D-05 | Wazuh/SigNoz delivery path (ADR-0005) | **Over the existing Check Point site-to-site tunnel**, relay-subnet-scoped; egress stamps stay entirely off that path. *Precondition:* network team confirms Check Point rule scoping before M3-5/6. **Superseded 2026-09-01 by D-16/ADR-0006**: the relay is on premises, delivery is a local hop, the precondition is moot | 2026-08-31, project owner |
| D-06 | Sensitive-session expiry behaviour (ADR-0003) | **Expiry terminates the session**; analyst may start a fresh normal session immediately | 2026-08-31, project owner |
| D-06a | Scope of D-06 termination | **Amended: expiry terminates the session only when suppression was activated.** An approval that lapsed without being used suppressed nothing, so there is no suppressed activity to stop; the analyst's normally logged session is left alone. Approval, denial, expiry and the unused-approval case are all still audited | 2026-09-01, project owner |
| D-07 | Egress-stamp ingress restriction | **Corporate egress CIDRs + a short named extra-IP allowlist** (e.g. admin/test connections). No general roaming at MVP (A3 refined accordingly). Maintained as reviewed tfvars | 2026-08-31, project owner |
| D-08 | Approved region list | **westeurope, northeurope, germanywestcentral, francecentral.** Analysts can select only regions with an active stamp; dev/MVP: westeurope; further stamps activate on demand | 2026-08-31, project owner |
| D-08a | Amendment: dev/PoC region | **Adds spaincentral, dev/PoC only.** The dev Azure subscription's offer type blocks every mainstream VM family (Bsv2, Dsv5) in all four D-08 regions — confirmed via the Microsoft.Compute/skus API and a failed self-service quota request (`ResourceNotAvailableForOffer`), and the subscription has no paid support plan to escalate through the standard ticket path. spaincentral is the one region found where a same-class family (Standard_B2as_v2, Bas_v2 — AMD, same 2 vCPU/8GiB size as the originally-targeted B2s) is unrestricted for this subscription outside availability zone 2, and the dev stamp deploys non-zonal by default. Production region selection is unaffected by this — this is a subscription-level workaround for the dev PoC's own capacity dead-end, not a change to the four production-candidate regions | 2026-09-04, project owner |
| D-09 | Retention periods | **Hostname telemetry 180 days · governance audit 5 years · operational telemetry 90 days** — set by owner as operating values and the formal proposal; DPO/legal ratification required before production (REQUIREMENTS §5) | 2026-08-31, project owner |
| D-10 | Break-glass definition (ARCHITECTURE §12) | **As designed**: two cloud-only Entra emergency-access accounts (CA-excluded, vaulted offline) + PIM-gated Azure RBAC emergency group; critical Wazuh alerting + post-use review; no application backdoor | 2026-08-31, project owner |
| D-11 | Production scale / cost envelope | **One active production egress region first** (≈ €600–1,100/mo indicative); second region deferred until demand shows — availability trade-off recorded in ARCHITECTURE §9. *Azure envelope revised by ADR-0006 — App Service and Azure SQL leave the bill, on-premises costs are FIAU-side; see COST_MODEL §2* | 2026-08-31, project owner |
| D-12 | .NET stack details (ADR-0004) | **Confirmed in full**: .NET 10 LTS, ASP.NET Core API, Blazor Server UI, EF Core + SQL Server (Azure SQL at the time; SQL Server on Proxmox, Arc-enabled, since D-17), Envoy data plane | 2026-08-31, project owner |

## Assumptions

| ID | Assumption | Status |
|---|---|---|
| A1 | Wazuh/SigNoz on-prem with no public ingress | **Superseded twice**: by D-05/ADR-0005 (deliver over the Check Point tunnel), then by ADR-0006, under which the relay is on premises and Wazuh/SigNoz need neither public ingress nor the tunnel — the assumption's intent holds again |
| A2 | ~50 concurrent users; growth modest | Open — capacity/cost model input |
| A3 | Analysts use Mina only from the corporate network at MVP | **Refined by D-07**: corp network + a short named extra-IP allowlist |
| A4 | Secondary Edge channel acceptable on managed endpoints | **Implied accepted via D-03**; re-confirm with M1-5 evidence |
| A5 | Corporate firewall permits outbound 443 from endpoints to egress ingress IPs | Open — verify before M2 rollout |
| A6 | FIAU holds a usable code-signing certificate for the agent | Open — needed by M2-5 |
| A7 | Test Entra tenant/Intune ring available for M1/M2 | Open — schedule dependency |
| A8 | Analysts briefed: governed attribution separation, **not anonymity** | Open — comms/training before rollout |

## Inputs needed to run the PoC (D-04 execution)

1. Azure subscription + tenant IDs for dev (and `az login` on the working machine).
2. Ingress CIDR allowlist for dev (D-07: corp egress CIDRs + named extras).
3. SSH public key for node admin access in dev.
4. Later (M2): test-tenant details (A7), corp public CIDRs for the egress deny-list, signing cert (A6).
5. On premises (M4-14…M4-28, ADR-0006): Proxmox API endpoint and token (environment variables only, never
   tfvars or state), node and datastore names, DMZ bridge/VLAN id/addressing, corporate management
   CIDRs, the public DNS name and public-CA certificate for the published node-facing endpoint, and
   the control plane's public egress addresses for the Key Vault and storage firewalls
   (`control_plane_egress_cidrs` in `environments/dev`).

## Objective / non-goal validation (CLAUDE.md Phase 0 step 2)

The stated objective is sound and internally consistent with the non-goals; no requirement
conflicts were found across the authoritative docs. Two clarifications were folded into the
design rather than challenged: (1) "Microsoft Edge is the protected research browser" is
treated as firm, which is why C3 is only listed conditionally; (2) "fail closed" is interpreted
as *no traffic rather than wrong-path traffic, including during agent failure* — reflected in
ARCHITECTURE §5.

## Decisions taken 2026-09-01

| ID | Question | Decision | Provenance |
|---|---|---|---|
| D-13 | How the control plane evidences device compliance | **Add the Conditional Access authentication-context (`acrs`) check.** The `deviceid` claim proves registration only; requiring an auth context is the one mechanism by which the API can demand that a compliant-device policy was satisfied for the presenting token. Opt-in via `Mina:Session:RequiredAuthContextId`, with a claims challenge so compliant devices step up silently. Tenant prerequisite tracked in M2-1, agent side in M2-4 | 2026-09-01, project owner |
| D-14 | Node-side session allowlist versus documentation | **Correct the documentation.** Envoy admits any unexpired certificate chaining to the internal CA; the allowlist governs suppression, not admission, so revocation is bounded by the certificate TTL (≈60 min). ARCHITECTURE and THREAT_MODEL now say so. Node-side enforcement remains available as backlog M4-11 | 2026-09-01, project owner |
| D-15 | Auditing session-id lookup misses | **Leave as is.** Only a non-owner attempt on an existing session is audited. Recording misses would give an authenticated user a lever on an append-only store whose rows cannot be deleted under current policy (M4-9) | 2026-09-01, project owner |

## Decisions taken 2026-09-01 (on-premises move)

| ID | Question | Decision | Provenance |
|---|---|---|---|
| D-16 | Where the control plane runs, and how egress nodes reach it | **On premises in the FIAU Proxmox cluster** — portal, web server, service logs and SQL Server; egress stamps stay in Azure. Nodes reach it at an **internet-facing endpoint published from the FIAU DMZ**, so they gain no corporate route and CLAUDE.md non-negotiable 4 stands unamended. The owner first directed the Check Point tunnel route and reversed it the same day once the trade was set out; ADR-0006 records both | 2026-09-01, project owner |
| D-17 | How the control plane authenticates to SQL | **Azure Arc-enable SQL Server** so Entra authentication works with no stored credential, preserving the "no client secrets anywhere in the product" property | 2026-09-01, project owner |
| D-18 | Where the CA signing key and audit anchors live | **Both stay in Azure** — Key Vault for the signing key, immutable blob storage for export anchors. Proxmox offers no HSM and no write-once store, and both guarantees depend on hardware or platform enforcement. Reached outbound from the Arc-enabled control-plane hosts using their Arc managed identity | 2026-09-01, project owner |

## Standing stop-conditions (unchanged by any decision above)

Production deployment approval; any TLS interception; any route from **research egress nodes**
into corporate networks (ADR-0005, which touched only the control-plane relay path, is itself
superseded — no Mina component uses the tunnel); permanent logging
exemptions; weakening Conditional Access/device compliance; new third-party SaaS dependencies.

**One of these was approached and not taken.** On 2026-09-01 the on-premises move (D-16) was first
directed in a shape that would have routed research egress nodes into corporate networks. The owner
reversed it the same day in favour of publishing the control plane's node-facing endpoint from the
DMZ, so the stop-condition was not exercised and property 4 stands unamended. Recorded because a
reviewer should be able to see that the condition did its job.

## D-19: node-side session admission (M4-11), superseding D-14

D-14 (2026-09-01) chose to document the certificate TTL (≈60 min) as the revocation bound at the
node, because at the time Envoy admitted any unexpired certificate chaining to the internal CA with
no session check. Node-side enforcement was recorded as optional backlog (M4-11).

**D-19 (2026-09-02, project owner: "go ahead with fail closed"): implement it, fail closed.** Envoy
now consults the node sidecar (`ext_authz`, gRPC over a Unix socket) for every CONNECT and admits
only a session the control plane currently lists for this region; the sidecar refusing to answer —
down, unreachable, or its session view too old to trust — refuses every tunnel rather than falling
back to certificate validity. This reverses D-14's premise and the documents D-14 corrected now need
correcting again; see ARCHITECTURE §3.3/§4/§5/§11, THREAT_MODEL B3/B4/§5/residual-risk-1, ADR-0006
Availability, OPERATIONS, TEST_STRATEGY, EVENT_SCHEMAS, egress-node/README.

**The resulting bounds, precisely, because "fail closed" is not by itself a number:**
- **A new tunnel for a revoked or unknown session** is refused once the node's session view no
  longer lists it — within one refresh interval (`AllowlistRefreshInterval`, default 15 s), or
  immediately if the session was never listed (refusal does not wait on a poll).
- **A new tunnel for a session issued since the node's last refresh** — the cold-start case, where
  certificate-only admission had no gap and view-based admission would otherwise introduce one — is
  covered by a refresh-on-miss: an unknown session id triggers one bounded, coalesced refresh before
  the check answers, so the first tunnel of a session is not routinely refused for up to a poll
  interval.
- **An already-open tunnel does not close on revocation.** `ext_authz` decides per CONNECT stream;
  Envoy does not re-run it on an established connection, and this change does not add a connection
  duration cap to force one. A long-lived tunnel — a large download, a websocket, a persistent
  HTTP/2 connection to the destination — opened before revocation keeps carrying traffic until the
  browser or the destination closes it. **This is a known, accepted gap, not an oversight**: capping
  connection duration to close that gap trades off against interrupting exactly the kind of
  long-running research task (a large export, a slow site) the platform exists to support, and
  picking a cap is a UX/security trade the owner should make deliberately rather than have set as a
  side effect of this change. Recorded as a residual limitation (THREAT_MODEL) and a follow-up row
  (BACKLOG M4-11 remaining) rather than decided here.
- **A control-plane partition in which the control plane is up but nodes cannot reach it** — the
  case where revocation matters, since a control plane that is genuinely down cannot revoke anything
  either — degrades new-tunnel admission to refusal after `AdmissionMaxViewAge` (default 5 min,
  chosen as roughly twenty missed refreshes: long enough that a proxy restart or one rate-limited
  response on the published endpoint does not take a node's admission out, short enough to bound the
  partition case meaningfully below the ~60 min this superseded). Past that the node fails closed
  entirely — refusing sessions it still lists, not only ones it has lost — which is the existing
  "platform fails closed" property (CLAUDE.md #2), reached sooner than before (was: the lease TTL,
  ~60 min) rather than differently.

**Node health becomes sidecar health.** A node whose sidecar cannot be reached refuses 100% of
tunnels (503) while still accepting TCP on the tunnel port, so the load balancer's probe moved from
TCP-on-8443 to HTTP against a health listener that is 200 only while the admission path is healthy
(egress-stamp module, `azurerm_lb_probe.envoy`).

**This makes the sidecar load-bearing while it has no production packaging.** cloud-init installs no
sidecar binary today (BACKLOG M4-27, blocking): until it exists, a node built from this configuration
refuses all research browsing, which is fail-closed and correctly so, but is the explicit reason
M4-27 gates any environment beyond local/Docker-validated testing.

## D-19a: open-tunnel duration cap (M4-11 remaining), amending D-19

D-19 explicitly left one bound undecided: admission is checked per CONNECT, not on an established
connection, so a tunnel already open when its session is revoked keeps carrying traffic until it
closes on its own — bounded only by whatever the tunnel protocol itself does, not by anything Mina
enforces. D-19 recorded picking a cap for this as "a UX/security trade the owner should make
deliberately," not a default to set as a side effect of that change.

**D-19a (2026-09-04, project owner: 60 minutes): cap it at the same ~60-minute bound that governed
every tunnel before D-19 existed, not tighter.** `max_stream_duration: 3600s` on the tunnel
listener's HTTP connection manager (`egress-node/envoy/envoy-bootstrap.yaml`) resets every tunnel's
stream at that age, admitted or not; the next CONNECT is a fresh stream and gets a fresh `ext_authz`
check like any other new tunnel. Offered as 15 min (tightest — closest to the ~15 s new-tunnel
revocation bound), 30 min, or 60 min; the owner chose 60 min because it does not newly increase the
platform's accepted worst case — a revoked session's already-open tunnel is now bounded by the same
window the certificate/lease TTL bounded every tunnel by before D-19 — while a shorter cap would
trade directly against interrupting the long-running research tasks (a large download, a slow site)
the platform exists to support, which is exactly the trade D-19 declined to make silently.

**The first implementation of this was wrong, and only actually running it against a real Envoy
caught it.** `max_connection_duration`, not `max_stream_duration`, was the first thing tried — it
reads as the obvious fit ("cap how long a *connection* may last"). Against a real Envoy it logs
`max connection duration reached` exactly on schedule, then waits for the connection's active stream
to finish before closing anything. A CONNECT tunnel's one stream *is* the traffic this cap exists to
bound, so by construction it does not end on its own before the cap should act — the config would
have shipped changing nothing, silently, while reading as if it worked. `An_admitted_tunnel_is_force_closed_once_the_connection_duration_cap_elapses`
caught it immediately: a 2 s test override left the tunnel open past a 20 s poll window.
`max_stream_duration` resets the stream itself at the configured age regardless of activity — the
right primitive, and incidentally the narrower blast radius too, since the agent multiplexes many
browser tabs as separate streams over one shared mTLS connection to the node (ADR-0001 C-tx): a
stream reset ages out one tab's tunnel, not every tab sharing that connection the way a connection
close would have. Re-run against the fix, the same test passes in 3 s (matching its 2 s override),
and the full real-Envoy transport suite (24 tests, including large-payload and full-tunnel
byte-flow checks) stays green — the change does not disturb ordinary tunnel operation.

**What this does and does not change:**
- Applies uniformly to every tunnel on every node, revoked or not — Envoy has no mechanism to reset
  only the stream belonging to one revoked session; the only lever is a stream-age cap on the whole
  listener. A session that is never revoked still has each of its tunnels cut at 60 minutes and must
  reconnect.
- Reconnection is transparent for most traffic (a fresh page load, an HTTP range request resuming a
  download) but not guaranteed for all of it — a long-lived WebSocket or a protocol with no resume
  semantics of its own simply drops and the analyst notices. Accepted as part of the same trade.
- Does not change the ~15 s bound for a revoked session's *new* tunnels (D-19) or the 5-minute
  `AdmissionMaxViewAge` partition bound — this is additive, closing only the "already open" gap
  those left.
- THREAT_MODEL residual risk 6 is updated from "not closed, accepted" to "bounded at 60 min,
  accepted" rather than removed: the gap is smaller, not gone, and the trade-off keeping it open is
  unchanged. See ARCHITECTURE §4/§5, `EnvoySessionAdmissionTests` for the real-Envoy test proving the
  cap resets an open tunnel's stream on age alone, session still admitted throughout — verified
  green against a real Envoy 2026-09-04 (BACKLOG M4-11).

## D-20: where the internal CA's certificate lives, and who may create it (M2-2c)

D-18 settled that the CA *signing key* stays in Azure Key Vault. Implementing it surfaced a
question D-18 did not answer: a signing key is not a certificate authority. Something has to hold
the CA certificate — the self-signed document that says this key may sign certificates — and
something has to create it in the first place. Key Vault cannot: its own certificate objects are
always end-entity (basic constraints assert cA=false), so the one thing that cannot be stored as a
Key Vault *certificate* is a CA certificate.

**Decision (2026-09-04): the CA certificate is a Key Vault secret beside the key, and only an
operator can write it.**

- **Stored as a secret** (`mina-internal-ca-certificate`, PEM) in the same vault as the signing key
  (`mina-internal-ca`). It is public material — every egress node and endpoint holds a copy as its
  trust root — so the secret's value is integrity, not confidentiality: one RBAC-controlled,
  diagnostics-logged place that already has the right consumers pointed at it. The alternative,
  shipping the certificate as a file alongside the application, would have put the trust root in
  configuration management with no record of who changed it.
- **Created by an operator tool, not by the control plane.** `mina-ca bootstrap`
  (`control-plane/tools/Mina.Ca`) drives a self-signing request through the vault's sign operation
  and writes the result. The running API is granted Key Vault *Crypto User* and *Secrets User* — it
  can sign and it can read, and it can do neither of the two things that would let it change what
  the platform trusts. A service that can mint its own root of trust can replace the root of trust,
  and avoiding one operator command is not worth that.
- **Refuses to overwrite.** Replacing the certificate is a CA rollover (M4-2), not a bootstrap:
  every certificate issued under the old root stops validating the moment nodes reload. The tool
  requires `--replace` to do it and says so.
- **The version is pinned.** The signer binds to the versioned key identifier, so rotating the key
  in the vault does not silently change what signs — the certificate/key match check fails at
  startup instead, which is the loud version of the same event.

**What this does not decide:** the CA's lifetime (5 years by default, an argument to the tool, not
yet an owner decision), and how the certificate reaches egress nodes — `mina-fetch-certs.sh` still
has no implementation, and the Envoy *server* certificate it also needs has no issuance path yet.
Both belong with M4-2 and the node-provisioning work, not here.

**Bootstrapped in dev 2026-09-04**, against `kv-mina-dev-spc-cp`: the CA certificate exists in the
vault (`CN=Mina Internal CA`, SHA-256 `D5CE4EE5…B8F4E0`, valid to 2031-09-03), a session certificate
issued from a real CSR verifies against it with OpenSSL, and the vault's diagnostics record every
signature. The `--replace` guard was confirmed by re-running the bootstrap and being refused. The
live control plane still runs the development CA until its deployment sets `Mina:Pki:KeyVaultUri` —
which is safe to do at any time, because no egress node currently holds a trust root at all
(BACKLOG M2-2d).

**In service on the live control plane 2026-09-04.** The on-premises API was redeployed with
`Mina:Pki:KeyVaultUri` set and now loads the CA at startup as its own Azure Arc managed identity
(`mina-dev-cp-app`) — `KeyGet` then `SecretGet` in the vault's diagnostics, no credential stored on
the host. D-18's "reached outbound from the Arc-enabled control-plane hosts using their Arc managed
identity" is, from this point, something the platform does rather than something it intends.
