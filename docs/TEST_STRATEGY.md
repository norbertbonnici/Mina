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
| Infra | CI stage | `terraform validate/plan`, tfsec/checkov, Trivy on images | IaC hygiene + policy-as-code (e.g. "no NSG allows RFC1918 outbound from egress") |
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
  (CONNECT without cert, TLS without client cert, common proxy fingerprints) — AC-016.

## 3. Security test suites → acceptance mapping

| Suite | Key cases | Evidence for |
|---|---|---|
| Leak: fallback | kill tunnel mid-browsing; kill agent; expire session; control plane down — assert zero packets from research browser via corp egress (endpoint capture + echo) | AC-004, FR-007 |
| Leak: DNS | canary resolutions during session; direct-53/DoH attempts from research binary blocked; corp resolver logs show no research names | AC-005 |
| Leak: IPv6 | dual-stack endpoint; AAAA-only target behaviour; direct v6 attempts blocked | AC-006 |
| Leak: WebRTC/QUIC | harness page candidates; UDP capture during session (expect none from research binary except loopback) | AC-007 |
| Leak: startup/prefetch | packet capture from browser spawn to first proxied request; prefetch/preconnect flags honoured | THREAT N11/N12 |
| Separation | ordinary Edge + apps → corp IP while session active; research → Azure IP | AC-002/003 |
| Open proxy | external scans (all regions); unauthenticated CONNECT (covered by `EnvoyClientAuthTests` against a real Envoy, with a meta-test proving the guard detects removal of `require_client_certificate`); expired cert reuse. **Revoked-cert reuse is expected to succeed** until the certificate expires — the node admits on certificate validity alone (D-14) — so the case records the observed window rather than asserting refusal | AC-016 |
| Corp reachability | probes from egress nodes to RFC1918 + corp public CIDRs + control-plane private ranges — all denied except approved dependencies | AC-017 |
| Region authz | select unapproved region via API directly (bypass UI) — refused + audited | AC-008 |
| Sensitive sessions | activation without approval; self-approval; TTL expiry terminates; node ack mismatch raises critical; suppressed sessions produce no hostname records but full mandatory metadata | AC-010/011/012 |
| Roles/privileges | authorisation matrix (Analyst/Approver/Admin × every API operation); node managed-identity scope | SR-004/008 |
| Endpoint tamper | rogue loopback client; IPC malformed/unauthorised messages; WFP rule deletion attempt as user; unmanaged browser launch | SR-006, B1 |
| Tokens/certs | expired/not-yet-valid/replayed tokens; cert renewal after Entra revocation; revocation latency measured against the lease TTL, which is the target while admission is by certificate validity alone (D-14) | B3/B5 |
| Telemetry hygiene | scan Wazuh and SigNoz test exports for URL/hostname patterns (must be zero); audit completeness per event catalogue | AC-013/014 |
| Break glass | drill: emergency sign-in + Azure action in test → high-severity Wazuh events within SLA | AC-015 |
| IaC rebuild | destroy/recreate test environment from scratch; all suites green | AC-018 |

## 4. E2E environment

A dedicated Intune test tenant/ring with 2+ Windows 11 VMs (one dual-stack), enrolled and
compliant, plus one non-compliant VM for negative tests. E2E runs are semi-automated at MVP
(harness-driven with manual attestation where UI interaction is unavoidable) and fully recorded.

## 5. CI/CD gates

PR: unit + integration + infra static analysis. Main: + security suites that run without the
Windows lab. Release candidate: full matrix incl. lab e2e + external scans; evidence bundle
(reports + captures + scan outputs) archived with the release tag and mapped to
`docs/ACCEPTANCE_CRITERIA.md` checkboxes. Production deploy: human approval, always.
