# Implementation Backlog

Status: Phase 0 — Proposed. Milestones map to `docs/IMPLEMENTATION_PLAN.md` phases; every story
lists the requirement/criterion it serves. Sizes: S ≤ 1 day, M ≤ 3 days, L ≤ 1–2 weeks.

## M0 — Foundations (immediately after Phase 0 approval)

| ID | Story | Refs | Size |
|---|---|---|---|
| M0-1 | Repo scaffolding per CLAUDE.md layout; CI skeleton (build, unit, lint, tfsec, SBOM) — **done 2026-08-31** (solution + projects build warning-free, 21 domain tests, locked-mode NuGet restore, CI + dependabot in place) | SR-011/012 | M |
| M0-2 | Terraform remote state + `environments/dev` bootstrap (RGs, naming, tagging) — **code done & validated 2026-08-31**; state-storage bootstrap awaits Azure credentials (PHASE0_DECISIONS "Inputs needed") | AC-018 | M |
| M0-3 | Canary infrastructure: IP echo, DNS canary zone, external scan host — **echo + DNS canary code done 2026-08-31**; scan host + deployment land with the M1 lab | TEST §2 | M |

## M1 — Egress proof of concept (Phase 1)

| ID | Story | Refs | Size |
|---|---|---|---|
| M1-1 | Terraform egress stamp module (VNet, NSG, LB, VMSS, NAT GW + prefix) in one test region — **module written & validated 2026-08-31**; apply pending PoC inputs | AC-017/018 | L |
| M1-2 | Hardened node image + Envoy mTLS/CONNECT config + build pipeline — **config done & validated 2026-08-31** (`egress-node/envoy`, validated against Envoy 1.39.1, interop-proven); hardened/pinned image build still to do | AC-016 | L |
| M1-3 | Internal CA + cert issuance — **done 2026-08-31** as a real, tested library (`Mina.ControlPlane.Pki`: CA + session-bound client certs, 12 tests). Key-Vault-backed signing is the M2 swap | — | S |
| M1-4 | Agent transport core: loopback CONNECT proxy + mTLS tunnel client + peer gate — **done & tested 2026-08-31** (`Mina.EndpointAgent/Proxy`, 6 transport tests incl. real-Envoy interop, fail-closed proven). WAM-broker auth + host wiring land in M2 with control-plane cert issuance | FR-002 (proof) | L |
| M1-5 | **ADR-0001 verification register**: C1 vs C2 prototypes, flag/policy pinning, startup capture, WFP behaviour — produce evidence, finalise ADR. **Blocked: needs a Windows 11 lab machine.** Transport items (3, 6) partially evidenced | ADR-0001 | L |
| M1-6 | Leak suites v1 (fallback, DNS, IPv6, WebRTC, startup) against PoC — canary code exists (M0-3); suites need the Windows lab + a live stamp | AC-004..007 | L |
| M1-7 | Open-proxy external scan + RFC1918 probes automated — need a live stamp (PoC apply) | AC-016/017 | M |
| **Gate** | ADR-0001 accepted (or reworked) on PoC evidence — transport evidence in; Windows enforcement evidence outstanding | | |

## M2 — Identity and endpoint integration (Phase 2)

| ID | Story | Refs | Size |
|---|---|---|---|
| M2-1 | Entra enterprise app, app roles, group assignment; CA policy (compliant device) in test tenant | FR-003, SR-007 | M |
| M2-2 | Control-plane API core: session issuance/renewal/termination, region policy, CSR-based session-cert signing — **core done & tested 2026-08-31** (domain session aggregate + RegionPolicy, `SessionService`, Entra-wired ASP.NET Core endpoints; 44 new tests incl. 9 API integration tests via WebApplicationFactory). **Remaining:** EF Core/Azure SQL repository (in-memory now) and **Key-Vault-backed CA** (ephemeral dev CA now) | FR-004/005, AC-008 | L |
| M2-3 | Node sidecar: allowlist sync (pull + push), suppression flags plumbing | AC-010 prep | M |
| M2-4 | Production-grade agent: service + tray UI (state, region, FR-006), IPC hardening, tamper telemetry | SR-006 | L |
| M2-5 | Intune packaging: signed agent Win32 app, research-browser install/config, shortcut | SR (Intune/signing) | M |
| M2-6 | Authorisation matrix + token/cert security tests | B3/B5 | M |
| **Demo** | AC-001/002/003 pass on a managed test device | | |

## M3 — Governance and telemetry (Phase 3)

| ID | Story | Refs | Size |
|---|---|---|---|
| M3-1 | Sensitive-session state machine + approvals API (self-approval rejection, TTL, expiry-terminates) | FR-009..012 | L |
| M3-2 | Management UI: approvals, sessions, health, audit views, region admin | FR-013 | L |
| M3-3 | Audit pipeline: synchronous writes, WORM export, event catalogue emission | AC-013 | M |
| M3-4 | Hostname telemetry ingest + suppression enforcement at node + mismatch alerting | AC-009/012, N5 | M |
| M3-5 | Wazuh delivery over the Check Point S2S per ADR-0005 (precondition: network-team rule confirmation) + rules/severity mapping | AC-013 | M |
| M3-6 | SigNoz OTLP export + scrub processor + dashboards | AC-014 | M |
| M3-7 | Sensitive-session + telemetry-hygiene test suites | AC-010..014 | M |

## M4 — Production hardening (Phase 4)

| ID | Story | Refs | Size |
|---|---|---|---|
| M4-1 | Region-activation drill: stand up a second approved region from IaC on demand (D-11: no standing second stamp at launch) | HA | M |
| M4-2 | Key/cert/secret rotation automation; CA rollover procedure | SR-005 | M |
| M4-3 | Backup/restore (SQL, KV), stamp rebuild drill, rollback procedure | OPERATIONS | M |
| M4-4 | Patch/vuln management cadence; CVE fast-path for Envoy/node image | N8 | M |
| M4-5 | Break-glass implementation (emergency accounts, PIM group, alert wiring) + drill | AC-015 | M |
| M4-6 | Runbooks + SLOs + alerts per OPERATIONS.md; on-call handover pack | OPERATIONS | M |
| M4-7 | External penetration test + findings remediation | Phase 4 | L |
| M4-8 | Full evidence bundle mapped to ACCEPTANCE_CRITERIA; production go/no-go review | AC-019 | M |
| **Gate** | Human production-deployment approval | | |

## M5 — Post-MVP candidates (Phase 5, unscheduled)

Egress-IP rotation (N1/N2 mitigation); additional approved regions; disposable Azure-hosted
browser mode for exceptionally risky research; browser-originated URL telemetry (only via
ADR-0002 revisit with DPO approval).
