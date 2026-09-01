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
- suspicious/open-proxy indicators;
- break-glass use.
