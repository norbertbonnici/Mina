# Phase 0 — Decision Log

Status: **All Phase 0 decisions (D-01…D-12) are decided** — D-01…D-04 on 2026-08-31 (initial
gate), D-05…D-12 on 2026-08-31 (owner Q&A round). One named precondition remains open on D-05
(network-team confirmation of Check Point rule scoping, blocking M3-5/6 implementation only).
Retention values (D-09) still require DPO/legal ratification before production per
REQUIREMENTS §5.

## Decisions taken

| ID | Decision | Outcome | Date / by |
|---|---|---|---|
| D-01 | URL telemetry method (ADR-0002) | **Option 1 — hostname-level at egress, no TLS interception.** Options 2/3 only via a future ADR + DPO approval | 2026-08-31, project owner |
| D-02 | Steering/transport architecture (ADR-0001) | **Option C** — agent + loopback proxy + mTLS HTTP/2 CONNECT to Envoy | 2026-08-31, project owner |
| D-03 | Enforcement variant (ADR-0001 C-enf) | **C2** — distinct research-browser image path + SYSTEM WFP rules; channel trade-off accepted (A4). Final confirmation against M1-5 prototype evidence; C1 remains the documented fallback | 2026-08-31, project owner |
| D-04 | Phase 1 PoC build | **Approved** — one test region + lab within the dev cost envelope (≤ €150/mo) | 2026-08-31, project owner |
| D-05 | Wazuh/SigNoz delivery path (ADR-0005) | **Over the existing Check Point site-to-site tunnel**, relay-subnet-scoped; egress stamps stay entirely off that path. *Precondition:* network team confirms Check Point rule scoping before M3-5/6 | 2026-08-31, project owner |
| D-06 | Sensitive-session expiry behaviour (ADR-0003) | **Expiry terminates the session**; analyst may start a fresh normal session immediately | 2026-08-31, project owner |
| D-06a | Scope of D-06 termination | **Amended: expiry terminates the session only when suppression was activated.** An approval that lapsed without being used suppressed nothing, so there is no suppressed activity to stop; the analyst's normally logged session is left alone. Approval, denial, expiry and the unused-approval case are all still audited | 2026-09-01, project owner |
| D-07 | Egress-stamp ingress restriction | **Corporate egress CIDRs + a short named extra-IP allowlist** (e.g. admin/test connections). No general roaming at MVP (A3 refined accordingly). Maintained as reviewed tfvars | 2026-08-31, project owner |
| D-08 | Approved region list | **westeurope, northeurope, germanywestcentral, francecentral.** Analysts can select only regions with an active stamp; dev/MVP: westeurope; further stamps activate on demand | 2026-08-31, project owner |
| D-09 | Retention periods | **Hostname telemetry 180 days · governance audit 5 years · operational telemetry 90 days** — set by owner as operating values and the formal proposal; DPO/legal ratification required before production (REQUIREMENTS §5) | 2026-08-31, project owner |
| D-10 | Break-glass definition (ARCHITECTURE §12) | **As designed**: two cloud-only Entra emergency-access accounts (CA-excluded, vaulted offline) + PIM-gated Azure RBAC emergency group; critical Wazuh alerting + post-use review; no application backdoor | 2026-08-31, project owner |
| D-11 | Production scale / cost envelope | **One active production egress region first** (≈ €600–1,100/mo indicative); second region deferred until demand shows — availability trade-off recorded in ARCHITECTURE §9 | 2026-08-31, project owner |
| D-12 | .NET stack details (ADR-0004) | **Confirmed in full**: .NET 10 LTS, ASP.NET Core API, Blazor Server UI, EF Core + Azure SQL, Envoy data plane | 2026-08-31, project owner |

## Assumptions

| ID | Assumption | Status |
|---|---|---|
| A1 | ~~Wazuh/SigNoz on-prem with no public ingress~~ | **Superseded**: an existing Check Point site-to-site tunnel links corp and Azure → D-05/ADR-0005 |
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
| D-16 | Where the control plane runs | **On premises in the FIAU Proxmox cluster** — portal, web server, service logs and SQL Server. Egress stamps stay in Azure. Egress nodes reach the control plane directly over the Check Point tunnel, which **reaches the CLAUDE.md stop-condition on routes into corporate networks**; approved by the owner and recorded in ADR-0006 with binding constraints | 2026-09-01, project owner |
| D-17 | How the control plane authenticates to SQL | **Azure Arc-enable SQL Server** so Entra authentication works with no stored credential, preserving the "no client secrets anywhere in the product" property | 2026-09-01, project owner |
| D-18 | Where the CA signing key and audit anchors live | **Both stay in Azure** — Key Vault for the signing key, immutable blob storage for export anchors. Proxmox offers no HSM and no write-once store, and both guarantees depend on hardware or platform enforcement. Reached outbound from the Arc-enabled control-plane hosts using their Arc managed identity | 2026-09-01, project owner |

## Standing stop-conditions (unchanged by any decision above)

Production deployment approval; any TLS interception; any route from **research egress nodes**
into corporate networks (ADR-0005 touches only the control-plane relay path); permanent logging
exemptions; weakening Conditional Access/device compliance; new third-party SaaS dependencies.

**One of these was reached and approved.** "Any route from research egress nodes into corporate
networks" was exercised on 2026-09-01 by D-16 and is governed by ADR-0006's constraints. It is
recorded here rather than removed from the list: the condition still applies to any *further*
route, and a reviewer should be able to see that it was reached deliberately rather than eroded.
