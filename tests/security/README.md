# tests/security

Leak, authz-boundary, open-proxy and reachability suites (docs/TEST_STRATEGY.md §3).
canaries/ holds the observation services deployed outside the platform.
windows-enforcement/ holds the ADR-0001 register prototypes: admin-only PowerShell that mutates
host state (firewall rules, packet capture) and cleans up after itself, so it runs by hand on a
Windows box rather than in CI.

Observe leaks off-box. Windows exempts traffic to the host's own address from outbound
filtering, so a canary on the machine under test is reached even by a process that is fully
blocked — an on-box target turns any of these suites into a test that always passes.
