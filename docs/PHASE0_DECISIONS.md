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
