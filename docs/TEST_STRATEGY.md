# Test Strategy

Status: Phase 0 — Proposed. Tests are code, live in `tests/`, run in CI; security evidence is
retained per release (AC-019). No test may be satisfied by hard-coded behaviour.

## 1. Layers and tooling

| Layer | Location | Tooling | Scope |
|---|---|---|---|
| Unit | `tests/unit/` | xUnit, .NET | Control-plane domain logic (state machines, authz rules, cert issuance validation), agent logic (session lifecycle, IPC validation) with faked externals |
| Integration | `tests/integration/` | xUnit + Testcontainers (SQL, Envoy), WireMock for Entra | API against real SQL; Envoy config + mTLS acceptance against issued certs; node sidecar sync; telemetry scrubber |
| Security | `tests/security/` | mixed (below) | Leak, authz-boundary, open-proxy, reachability, tamper suites |
| End-to-end | `tests/e2e/` | Windows lab VM + .NET/PowerShell harness driving the real agent + Edge; canary services | Full analyst journeys incl. failure injection |
| Infra | CI stage | `terraform validate/plan`, tfsec/checkov, Trivy on images | IaC hygiene + policy-as-code (e.g. "no NSG allows RFC1918 outbound from egress"); rendered cloud-init for the on-premises hosts parsed as valid cloud-config, with the proxy's nginx asserted to carry no management-port server block (M4-15) |
| Supply chain | CI stage | SBOM (CycloneDX), NuGet/container scanning, lockfile enforcement, signing verification | SR-012, threat N7 |

## 2. Canary infrastructure (built once in Phase 1, reused forever)

- **IP echo service** hosted outside the platform (and one third-party echo as cross-check):
  returns caller's source IP — used to assert AC-002/AC-003 from both research and ordinary
  contexts.
- **DNS canary zone**: authoritative server we control logs resolver source IPs per unique
  test subdomain — proves research resolution occurs from Azure, never corp resolvers (AC-005).
- **WebRTC harness page**: gathers ICE candidates, reports what an adversary site would learn
  (AC-007).
- **External scan host** (outside Azure tenant): open-proxy scans of every ingress IP
  (CONNECT without cert, TLS without client cert, common proxy fingerprints) — AC-016. Since
  ADR-0006 it also scans the **published control-plane endpoint**: only the allowlist and
  telemetry-ingest routes may answer; portal, audit read and admin routes must 404 (M4-16).

## 3. Security test suites → acceptance mapping

| Suite | Key cases | Evidence for |
|---|---|---|
| Leak: fallback | kill tunnel mid-browsing; kill agent; expire session; control plane down — assert zero packets from research browser via corp egress (endpoint capture + echo) | AC-004, FR-007 |
| Leak: DNS | canary resolutions during session; direct-53/DoH attempts from research binary blocked; corp resolver logs show no research names | AC-005 |
| Leak: IPv6 | dual-stack endpoint; AAAA-only target behaviour; direct v6 attempts blocked | AC-006 |
| Leak: WebRTC/QUIC | harness page candidates; UDP capture during session (expect none from research binary except loopback) | AC-007 |
| Leak: startup/prefetch | packet capture from browser spawn to first proxied request; prefetch/preconnect flags honoured | THREAT N11/N12 |
| Separation | ordinary Edge + apps → corp IP while session active; research → Azure IP | AC-002/003 |
| Open proxy | external scans (all regions); unauthenticated CONNECT (covered by `EnvoyClientAuthTests` against a real Envoy, with a meta-test proving the guard detects removal of `require_client_certificate`); expired cert reuse. Since D-19 (M4-11), **revoked-cert reuse is expected to be refused** once the node's session view no longer lists the session — `EnvoySessionAdmissionTests` asserts this against a real Envoy and sidecar, including a meta-test proving the guard detects `failure_mode_allow` being turned on. A cert reused *before* the view catches up is not refused — accepted (THREAT_MODEL §7 item 6). A tunnel already open at revocation is bounded, not refused: `max_stream_duration` (60 min, D-19a) resets its stream regardless of admission state, proved by `An_admitted_tunnel_is_force_closed_once_the_connection_duration_cap_elapses` against a real Envoy with a short-duration override and the session admitted throughout, plus a plain assertion locking the shipped 3600s value. The test earned its keep immediately: the first implementation used `max_connection_duration` instead, which fires its timer on schedule but then waits for the tunnel's own (never-ending) stream to finish before closing anything — the test caught the tunnel still open 20+ seconds past a 2 s cap, before this ever reached a real node | AC-016, AC-020 |
| Corp reachability | probes from egress nodes to RFC1918 + corp public CIDRs + the control plane's DMZ and corporate ranges — all denied, with no exception set: the published endpoint is reached as a public address (ADR-0006, M4-20) | AC-017 |
| Listener separation | management, audit and session endpoints requested on the published port → 404 before authentication; node endpoints on the corporate port likewise; headers and proxy rules cannot move a request between listeners (Kestrel-socket tests, six of which fail without the middleware — M4-16) | ADR-0006 constraint 1 |
| Region authz | select unapproved region via API directly (bypass UI) — refused + audited | AC-008 |
| Sensitive sessions | activation without approval; self-approval; TTL expiry terminates; node ack mismatch raises critical; suppressed sessions produce no hostname records but full mandatory metadata | AC-010/011/012 |
| Roles/privileges | authorisation matrix (Analyst/Approver/Admin × every API operation); node managed-identity scope | SR-004/008 |
| Endpoint tamper | rogue loopback client; IPC malformed/unauthorised messages; WFP rule deletion attempt as user; unmanaged browser launch | SR-006, B1 |
| Tokens/certs | expired/not-yet-valid/replayed tokens; cert renewal after Entra revocation; revocation latency measured against the lease TTL, which is the target while admission is by certificate validity alone (D-14) | B3/B5 |
| Telemetry hygiene | scan Wazuh and SigNoz test exports for URL/hostname patterns (must be zero); audit completeness per event catalogue | AC-013/014 |
| Break glass | drill: emergency sign-in + Azure action in test → high-severity Wazuh events within SLA — the Azure half; the on-premises half has no mechanism to drill yet (M4-21) | AC-015 |
| IaC rebuild | destroy/recreate the test environment from scratch — the Azure stamp and support resources *and* the Proxmox control plane from `dev-onprem`; all suites green | AC-018 |

## 4. E2E environment

A dedicated Intune test tenant/ring with 2+ Windows 11 VMs (one dual-stack), enrolled and
compliant, plus one non-compliant VM for negative tests. E2E runs are semi-automated at MVP
(harness-driven with manual attestation where UI interaction is unavoidable) and fully recorded.

## 5. CI/CD gates

PR: unit + integration + infra static analysis. Main: + security suites that run without the
Windows lab. Release candidate: full matrix incl. lab e2e + external scans; evidence bundle
(reports + captures + scan outputs) archived with the release tag and mapped to
`docs/ACCEPTANCE_CRITERIA.md` checkboxes. Production deploy: human approval, always.
