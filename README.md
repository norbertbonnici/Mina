# Mina

Organisation-controlled secure internet research egress platform on Microsoft Azure: authorised
FIAU analysts use a locked-down Edge research context whose traffic exits via approved Azure EU
egress IPs instead of the organisation's fixed public IPs. Governed attribution separation —
not anonymity, not a corporate VPN, never an open proxy. See `CLAUDE.md` for the working rules.

## Status — Phase 0 approved (D-01…D-04), implementation started

The gating decisions were approved on 2026-08-31: hostname-level URL telemetry without TLS
interception (D-01), the agent + loopback-proxy + mTLS architecture (D-02), enforcement via a
distinct research-browser image path with WFP rules (D-03), and the Phase 1 PoC build (D-04).
The steering design stays conditional on the M1-5 verification prototypes. **All Phase 0
decisions (D-01…D-12) are now decided** — see the decision log in `docs/PHASE0_DECISIONS.md`
(one precondition open: network-team confirmation of the ADR-0005 Check Point rule scoping;
D-09 retention values await DPO ratification before production). Work proceeds per
`docs/BACKLOG.md`; milestone M0 is complete.

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
| `docs/ARCHITECTURE.md` | Recommended architecture, data flows, Azure resource design |
| `docs/adr/0001-…` / `0002-…` | Steering/transport comparison; URL-telemetry analysis |
| `docs/adr/0003-…` / `0004-…` | Sensitive-session enforcement; .NET stack |
| `docs/THREAT_MODEL.md` | Expanded threat model + residual risks |
| `docs/EVENT_SCHEMAS.md` | Wazuh/SigNoz event contracts |
| `docs/COST_MODEL.md` | Indicative Azure footprint/cost |
| `docs/TEST_STRATEGY.md` / `docs/BACKLOG.md` | How it will be proven; milestone plan |

Implementation starts at backlog milestone M0/M1 (`docs/BACKLOG.md`) once D-01…D-04 are
decided; ADR-0001 is finalised against the M1-5 prototype evidence before anything is built on
top of it.
