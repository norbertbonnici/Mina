# egress-node

The Azure egress data plane node (ARCHITECTURE §3.3): **Envoy** as an authenticated forward
`CONNECT` proxy. This is the one non-.NET component (ADR-0004) — terminating mTLS at an internet
boundary is Envoy's well-exercised path, so we don't put novel security-critical code there.

> Repository-layout note: `egress-node/` is a component directory added during M1 alongside the
> layout in `CLAUDE.md`. It holds node configuration and (from M3) the telemetry sidecar; the
> node itself is stood up by the Terraform egress stamp (`infra/terraform/modules/egress-stamp`).

## Contents

- `envoy/envoy-bootstrap.yaml` — the Envoy config. Enforces:
  - **mTLS ingress** — a client certificate chaining to Mina's internal CA is required; there is
    no unauthenticated listener (AC-016). The client cert is the short-lived, session-bound
    credential from the control plane.
  - **CONNECT termination + dynamic forward proxy** — resolves and dials the requested authority;
    DNS happens here, never on the endpoint.
  - **Hostname telemetry** (`mina.hostname.v1`) via access log — the plaintext CONNECT authority,
    logged with no TLS interception (ADR-0002 Option 1).
- `cloud-init.yaml` — node bootstrap: runs Envoy as a hardened systemd unit, fetches TLS material
  from Key Vault via managed identity (M2), fails closed if certs are absent.

## Verify the config locally

```bash
ENVOY=/path/to/envoy ./scripts/validate-envoy-config.sh
```

## Prove interop with the agent

The `tests/integration/Mina.Transport.Tests` interop test drives the real .NET agent through a
real Envoy running this config (and asserts the hostname telemetry is emitted):

```bash
MINA_ENVOY=/path/to/envoy dotnet test tests/integration/Mina.Transport.Tests
```

Without `MINA_ENVOY` the interop test skips; the in-process transport tests always run.

## Not yet done (later milestones)

Hardened/pinned Envoy image build (M1-2); Key Vault cert fetch via managed identity and the
sidecar for session-allowlist sync + suppression + log shipping (M2-3/M3-4); HTTP/2 CONNECT
multiplexing on the agent↔Envoy leg (ADR-0001 verification register). Envoy additionally
validating the client cert's session-SAN against the live allowlist is part of M2-3.
