# Operations Baseline

## Required runbooks before production
- Egress region unavailable.
- Control plane unavailable.
- Entra authentication unavailable.
- Suspected egress-node compromise.
- Endpoint agent/profile malfunction.
- Wazuh integration failure.
- SigNoz integration failure.
- Telemetry site-to-site tunnel down (ADR-0005 path; relay buffers, verify no audit gap).
- Egress region activation (standing up a second approved region on demand, D-11).
- Emergency disable of an egress region.
- Break-glass activation and post-use review.
- Certificate/key/secret rotation.
- Rollback to previous release.

## Monitoring
Define SLOs and alerts for:
- session establishment success/failure;
- control-plane availability/latency;
- egress-region health/capacity;
- protected-path failures;
- approval workflow failures;
- audit pipeline health;
- Wazuh/SigNoz integration health (including S2S-tunnel delivery lag, ADR-0005);
- suspicious/open-proxy indicators;
- break-glass use.
