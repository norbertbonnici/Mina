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
  - **Session admission** (D-19, M4-11) — a valid certificate is no longer enough on its own. Every
    CONNECT is checked against the sidecar over `ext_authz` (gRPC, a Unix socket), which admits only
    a session the control plane currently lists for this region. `failure_mode_allow: false`: a
    sidecar that is down, slow or unreachable refuses every tunnel.
  - **CONNECT termination + dynamic forward proxy** — resolves and dials the requested authority;
    DNS happens here, never on the endpoint.
  - **Hostname telemetry** (`mina.hostname.v1`) via access log — the plaintext CONNECT authority,
    logged with no TLS interception (ADR-0002 Option 1). Only a successful (2xx) CONNECT is shipped
    as telemetry; a refused tunnel is not recorded as a visited destination. For a session the
    sidecar flagged suppressed at admission, Envoy writes a redacted line — counts, no authority —
    so the destination never reaches the node's disk.
  - **A health listener** (`:8081/healthz`, plaintext, unauthenticated by design) — what the load
    balancer probes since M4-11, because a node whose sidecar is down still accepts TCP on the
    tunnel port while refusing every session; this answers 200 only while the admission path is
    healthy.
- `cloud-init.yaml.tftpl` — node bootstrap, rendered by Terraform so the committed Envoy config in
  `envoy/` is what the node actually runs: installs a pinned, checksum-verified Envoy, runs it as a
  hardened systemd unit under a fixed `mina-envoy` account, fetches TLS material
  from Key Vault via managed identity (M2), fails closed if certs are absent. Also declares the
  `mina-sidecar` unit and account — see "The sidecar" below for why that unit's binary is the
  outstanding piece of this node (BACKLOG M4-29).

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

Hardened/pinned Envoy image build (M1-2); Key Vault cert fetch via managed identity; HTTP/2 CONNECT
multiplexing on the agent↔Envoy leg (ADR-0001 verification register). Session admission itself is
done (D-19, M4-11) — what remains is deploying it: a real sidecar build and a real managed-identity
token (BACKLOG M4-29), without which the node admits nothing at all.

## The sidecar

`src/Mina.EgressNode.Sidecar` runs beside Envoy and does three things:

- **Keeps the session view current** by polling the control plane's node endpoint (`~15 s`) —
  which sessions this region serves, and which of them are suppressed.
- **Answers Envoy's admission check** (D-19, M4-11) over a Unix socket for every CONNECT: OK for a
  session the view currently lists with a current lease, refused otherwise. A session issued since
  the last poll triggers one bounded, coalesced refresh-on-miss rather than waiting for the next
  interval, so a brand-new session's first tunnel is not routinely refused. **This is now the whole
  of admission control at the node** — a client certificate chaining to the internal CA is necessary
  but no longer sufficient — so the sidecar being unreachable, or its view older than
  `AdmissionMaxViewAge` (5 min default), means the node refuses every tunnel. That is fail-closed by
  design, not a bug: see D-19 (`docs/PHASE0_DECISIONS.md`) for the exact bounds this gives, including
  the accepted limitation that an *already-open* tunnel is not re-admitted on revocation — bounded,
  not eliminated, by the 60-minute `max_stream_duration` cap on the tunnel listener (D-19a).
- **Tells Envoy which tunnels to log redacted**: every admitting `ext_authz` answer carries
  `suppressed: true|false` as dynamic metadata, and Envoy's two access loggers each match one value.
- **Ships Envoy's hostname telemetry upstream**, dropping the destination for any session marked
  suppressed before it is even queued (covering the window before Envoy's next admission check sees
  the flag), and dropping the record entirely for any CONNECT admission refused (a refusal is not a
  visit).

Suppression enforcement at the node is the *first* line, not the guarantee. A node's view can be stale and
a compromised node could ignore it entirely, so the control plane re-checks every item it receives:
destinations for a suppressed session are discarded there and reduced to counts, and the discrepancy
raises a critical `sensitive_suppression_mismatch` event (threat N5). The sidecar fails safe in the
same direction — a session it has never heard of, or any session before the first successful
refresh, has its destinations withheld rather than logged (and, since M4-11, its tunnel refused).

Telemetry that cannot be shipped is dropped rather than buffered without bound: it is operational
data, and an egress node accumulating browsing destinations it cannot deliver is its own risk. The
gap shows up as delivery lag upstream.

**Verifying admission needs a real Envoy** — `ext_authz`/gRPC semantics for a CONNECT are not
something the in-process transport tests can stand in for; a first attempt at this using Envoy's
HTTP authorization service looked plausible in isolation and refused every tunnel in practice,
because a CONNECT's own check request has no path for `path_prefix` to match. Run the suite against
the pinned release in Docker:

```bash
scripts/test-with-envoy-docker.sh tests/integration/Mina.Transport.Tests
```

Not done yet: the node's **managed-identity** token (a configured token, or a systemd
`LoadCredential`, stands in — see BACKLOG M4-29) and push-based revocation. Push is no longer needed
for *admission* latency, since the poll interval alone now bounds that at ~15 s; it would still
shorten how quickly a *suppression* flag reaches a node between polls.
