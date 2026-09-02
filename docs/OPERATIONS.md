# Operations Baseline

## Required runbooks before production
- Egress region unavailable.
- Control plane unavailable.
- Entra authentication unavailable.
- Suspected egress-node compromise.
- Endpoint agent/profile malfunction.
- Wazuh integration failure.
- SigNoz integration failure.
- Published DMZ control-plane endpoint unreachable: nodes cannot pull allowlists or ship
  telemetry, and analyst sessions stop renewing within one lease period (~60 min). Failing
  closed is correct; the runbook is about restoring the endpoint and confirming no audit gap.
- Proxmox host or cluster failure, and on-premises SQL Server failure/restore (ADR-0006).
- Arc agent failure on a control-plane host: breaks Entra authentication to SQL *and* Key Vault
  access, with no stored credential to fall back on by design.
- Key Vault or audit-anchor storage unreachable from the control plane: CA signing stops, so no
  new sessions or renewals; export anchoring stops, the local chain continues and the gap must be
  anchored on recovery and verified.
- Published-endpoint TLS certificate renewal (public CA; nginx on the proxy host, M4-14).
- Egress region activation (standing up a second approved region on demand, D-11).
- Emergency disable of an egress region.
- Break-glass activation and post-use review.
- Certificate/key/secret rotation.
- Database schema migration (apply the idempotent EF script as a deliberate, approved deployment
  step; the application never migrates on startup — see `control-plane/src/Mina.ControlPlane.Persistence/README.md`).
- Rollback to previous release.

## Monitoring
Define SLOs and alerts for:
- session establishment success/failure;
- control-plane availability/latency;
- egress-region health/capacity;
- protected-path failures;
- approval workflow failures;
- audit pipeline health;
- Wazuh/SigNoz integration health (a local hop since ADR-0006; no tunnel involved);
- Arc agent health on every control-plane host; Key Vault and anchor-storage reachability;
- CA key use volume and anchor access (Log Analytics, M4-24) against expected session rates;
- published node-facing endpoint: certificate expiry, error rate, rate-limit hits, source addresses
  outside the stamps' NAT prefixes;
- suspicious/open-proxy indicators;
- break-glass use.
