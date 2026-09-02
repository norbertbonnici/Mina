# Mina

Organisation-controlled secure internet research egress platform: authorised FIAU analysts use a
locked-down Edge research context whose traffic exits via approved Azure EU egress IPs instead of
the organisation's fixed public IPs. Hybrid since ADR-0006 — the control plane runs on the FIAU
Proxmox cluster, the egress stamps in Azure, with Key Vault and immutable blob storage the only
Azure services the control plane still uses. Governed attribution separation —
not anonymity, not a corporate VPN, never an open proxy. See `CLAUDE.md` for the working rules.

## Status — Phase 0 approved (D-01…D-04), implementation started

The gating decisions were approved on 2026-08-31: hostname-level URL telemetry without TLS
interception (D-01), the agent + loopback-proxy + mTLS architecture (D-02), enforcement via a
distinct research-browser image path with WFP rules (D-03), and the Phase 1 PoC build (D-04).
The steering design stays conditional on the M1-5 verification prototypes. **All Phase 0
decisions (D-01…D-12) are now decided** — see the decision log in `docs/PHASE0_DECISIONS.md`
(D-09 retention values await DPO ratification before production). **ADR-0006 (2026-09-01)**
moved the control plane on premises and superseded ADR-0005, so the Check Point tunnel is no
longer a dependency or an open precondition. Work proceeds per `docs/BACKLOG.md`; milestone M0 is
complete and the on-premises move is tracked as M4-14 to M4-28.

## See it working

```bash
MINA_ENVOY=/path/to/envoy dotnet run --project demo/Mina.Demo -c Release
```

Runs the control plane, a real Envoy egress and the agent in one process, and exposes a proxy port
your browser can use — then press `k` to watch the protected path fail closed. See
[`demo/README.md`](demo/README.md) for what is real in that demo and what is stubbed.

| Read | For |
|---|---|
| `docs/PHASE0_DECISIONS.md` | The decision/assumption list blocking implementation |
| `docs/ARCHITECTURE.md` | Architecture, data flows, resource design (on-premises control plane + Azure stamps) |
| `docs/adr/0001-…` / `0002-…` | Steering/transport comparison; URL-telemetry analysis |
| `docs/adr/0003-…` / `0004-…` | Sensitive-session enforcement; .NET stack |
| `docs/adr/0006-…` (`0005-…` superseded) | On-premises control plane, published DMZ endpoint, Arc/Key Vault/immutable storage |
| `docs/THREAT_MODEL.md` | Expanded threat model + residual risks |
| `docs/EVENT_SCHEMAS.md` | Wazuh/SigNoz event contracts |
| `docs/COST_MODEL.md` | Indicative footprint/cost (Azure priced; on-premises FIAU-side) |
| `docs/TEST_STRATEGY.md` / `docs/BACKLOG.md` | How it will be proven; milestone plan |

Implementation starts at backlog milestone M0/M1 (`docs/BACKLOG.md`) once D-01…D-04 are
decided; ADR-0001 is finalised against the M1-5 prototype evidence before anything is built on
top of it.
