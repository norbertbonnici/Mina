# Mina node Docker stack

**Development/testing only. Not a deployable artefact, not part of any shipped package.**

Three containers, wired the way the real egress node is:

```text
your curl (mTLS)  →  envoy (pinned, real config)  →  sidecar (real, built from source)  →  node-api (stub)
                          ↑ ext_authz over the real Unix socket, gRPC (M4-11) ↑
```

- **`envoy`** — the official `envoyproxy/envoy:v1.39.1` image, running the real
  `egress-node/envoy/envoy-bootstrap.yaml`, with **exactly one line rewritten** by `envoy-init`:
  `use_resolvers_as_fallback` is flipped from `false` to `true`. The shipped config pins c-ares to
  Azure's link-local resolver `168.63.129.16` and makes it the only resolver Envoy will ever ask —
  right on a real node, whose own system resolver is the `127.0.0.53` stub that M4-10's nftables
  rule rejects, and unusable here, where that address does not exist and every hostname `CONNECT`
  would fail DNS with a 503. Flipping the flag makes c-ares prefer the nameserver Docker already
  gives the container. Nothing else diverges: the listeners, TLS, RBAC destination policy, ext_authz
  wiring and timeouts are all exactly what a real node runs.

  That 503 is worth knowing about because of step 4 below: an unresolvable DNS pin fails *the same
  way* a missing sidecar does, so a stack broken this way still looks like it is demonstrating
  fail-closed. If every request 503s including step 3's, suspect DNS, not admission.
- **`sidecar`** — `egress-node/src/Mina.EgressNode.Sidecar` built from source in a Dockerfile. The
  real binary, the real admission logic — nothing here is a stand-in.
- **`node-api`** — `demo/Mina.Demo.NodeApiStub`, a small **stub**, not the control plane. The real
  control-plane API validates genuine Entra bearer tokens and has no bypass in it (by design), so
  it cannot be reached over a network without a tenant. This stub serves only the two endpoints the
  sidecar calls (`GET /api/nodes/{region}/sessions`, `POST /api/nodes/telemetry`), plus an `/admin`
  surface to admit and revoke sessions interactively. It does not exercise the real control plane's
  authorization, session-service, or audit logic — only the wire shape the sidecar depends on.

This exists to test **node-side session admission (D-19, M4-11)** — that a certificate is
necessary but no longer sufficient to open a tunnel — end to end, over real Docker networking,
against the pinned Envoy release, without needing Azure or Entra.

## Run it

```bash
demo/docker-stack/up.sh
```

Generates throwaway certs, builds the sidecar and stub images, and brings the stack up in the
foreground (`Ctrl+C` to stop; `docker compose down -v` from this directory to remove volumes too).
Run detached with `demo/docker-stack/up.sh -d`.

## Try it

```bash
demo/docker-stack/new-session.sh
```

Issues a session certificate and prints the exact commands to admit it, tunnel through it, and
revoke it. The short version:

1. **Before admitting**, the tunnel is refused (`curl: (56) CONNECT tunnel failed, response 403`) —
   a valid certificate chaining to the CA is not enough on its own.
2. **Admit it** (`POST /admin/sessions`) and curl again — `200`.
3. **Revoke it** (`DELETE /admin/sessions/{id}`) with the *same, still-valid* certificate — curl
   still succeeds immediately (an already-open admission decision isn't torn down), then starts
   returning `403` once the sidecar's next refresh picks up the change
   (`Mina__Sidecar__AllowlistRefreshInterval`, 5s in this stack — the production default is 15s).
4. **Fail closed**: `docker compose stop sidecar` and curl a still-admitted session — refused
   immediately (`503`), because Envoy is configured with `failure_mode_allow: false`. Also watch
   `curl http://127.0.0.1:8081/healthz` flip to `503` within a few seconds (this is what the real
   load balancer probes instead of the tunnel port, precisely because a node in this state still
   accepts TCP on 8443). `docker compose start sidecar` to recover.

## Ports

| Port | What |
|---|---|
| `8443` | Envoy's tunnel ingress (mTLS + CONNECT) |
| `8081` | Envoy's health listener — `200` only while the sidecar/admission path is healthy |
| `8090` | The node-api stub — `GET /admin/sessions`, `POST /admin/sessions`, `DELETE /admin/sessions/{id}` |

## What this stack is not

Not a rehearsal of node hardening (fixed accounts, dedicated groups, systemd units — see
`egress-node/cloud-init.yaml.tftpl` and BACKLOG M4-29 for the real thing); the sidecar container
runs with a permissive `umask 000` purely so the admission socket is reachable across two
unrelated container images with no coordinated UID/GID. Not the control plane, and not a
replacement for `demo/Mina.Demo`, which exercises the control-plane API, the management UI, and the
analyst/approver governance loop end to end (in-process, real business logic, only sign-in
substituted) — this stack is scoped to the node side only.
