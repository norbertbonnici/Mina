# tests/security

Leak, authz-boundary, open-proxy and reachability suites (docs/TEST_STRATEGY.md §3).
canaries/ holds the observation services deployed outside the platform.
exposure/ holds the scanner: probes run against a deployed stamp from outside it (M1-7), skipped
unless an environment variable names a target, so the solution still tests clean on a laptop.
windows-enforcement/ holds the ADR-0001 register prototypes: admin-only PowerShell that mutates
host state (firewall rules, packet capture) and cleans up after itself, so it runs by hand on a
Windows box rather than in CI.
admin-host/ holds the D-21 enforcement probe: admin-only PowerShell that reads credential-store
ACLs and the CI-agent inventory of the machine it runs on, mutates nothing, and carries its own
negative controls. It runs by hand on an administration host; on any other machine it reports
NOT-AN-ADMINISTRATION-HOST rather than passing, and it must never run on a self-hosted CI runner —
it would then execute under the identity it exists to flag.

Observe leaks off-box. Windows exempts traffic to the host's own address from outbound
filtering, so a canary on the machine under test is reached even by a process that is fully
blocked — an on-box target turns any of these suites into a test that always passes.
