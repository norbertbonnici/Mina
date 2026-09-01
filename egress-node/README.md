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
- `cloud-init.yaml.tftpl` — node bootstrap, rendered by Terraform so the committed Envoy config in
  `envoy/` is what the node actually runs: installs a pinned, checksum-verified Envoy, runs it as a
  hardened systemd unit under a fixed `mina-envoy` account, fetches TLS material
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

## The sidecar

`src/Mina.EgressNode.Sidecar` runs beside Envoy and does two things:

- **Keeps the suppression view current** by polling the control plane's node allowlist, and
- **ships Envoy's hostname telemetry upstream**, dropping the destination for any session marked
  suppressed before it is even queued.

This is the *first* line of suppression enforcement, not the guarantee. A node's view can be stale
and a compromised node could ignore it entirely, so the control plane re-checks every item it
receives: destinations for a suppressed session are discarded there and reduced to counts, and the
discrepancy raises a critical `sensitive_suppression_mismatch` event (threat N5). The sidecar fails
safe in the same direction — a session it has never heard of, or any session before the first
successful refresh, has its destinations withheld rather than logged.

Telemetry that cannot be shipped is dropped rather than buffered without bound: it is operational
data, and an egress node accumulating browsing destinations it cannot deliver is its own risk. The
gap shows up as delivery lag upstream.

Not done yet: the node's **managed-identity** token (a configured token stands in, and the sidecar
warns about it), and push-based revocation — today the poll interval bounds how long a revoked or
newly suppressed session can be acted on stale.
