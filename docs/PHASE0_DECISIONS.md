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

## Standing stop-conditions (unchanged by any decision above)

Production deployment approval; any TLS interception; any route from **research egress nodes**
into corporate networks (ADR-0005 touches only the control-plane relay path); permanent logging
exemptions; weakening Conditional Access/device compliance; new third-party SaaS dependencies.
