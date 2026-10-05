# tests/security/exposure

What a scanner finds (M1-7). These probe a **deployed** stamp from outside it, which is the half the
in-process and Docker suites cannot reach: `EnvoyClientAuthTests` and `EnvoySessionAdmissionTests`
prove the egress *configuration* refuses the wrong callers, and `ListenerSeparationTests` proves the
listener middleware does. Neither can show that the configuration arrived on the machine, that the
load balancer forwards to the port carrying it, that the DMZ proxy publishes the listener everyone
believes it does, or that nothing else on the host answers.

Nothing here runs in CI. Every project in the solution builds, but each test skips unless its
environment variable names a target, so `dotnet test Mina.slnx` on a laptop is a no-op.

## Running it

Values come from `terraform output` in the environment under test:

```powershell
$env:MINA_STAMP_INGRESS   = terraform output -raw ingress_public_ip
$env:MINA_CONTROL_PLANE_URL = "https://mina-cp.example"          # the DMZ-published endpoint
$env:MINA_CA_VAULT_URI    = terraform output -raw key_vault_uri  # for the chained-certificate probe
dotnet test tests/security/exposure/Mina.Exposure.Tests
```

```powershell
.\tests\security\exposure\Invoke-NodeReachabilityProbe.ps1 `
    -ResourceGroup rg-mina-dev-egress-spc -ScaleSet vmss-mina-dev-egress-spc
```

**Run the .NET half from outside the platform.** Run it from a control-plane host and the
reachability assertions describe that host's network position rather than the internet's.

`MINA_CA_VAULT_URI` needs Key Vault Crypto User on the CA key, because one probe issues a
certificate the live CA genuinely signed. That is one `sign` operation and nothing is written to the
vault; the certificate names a session id that has never existed.

## What each half covers

| | Evidence for |
|---|---|
| `OpenProxyTests` — no client certificate, a foreign CA, a **chained certificate for an unlisted session**, cleartext proxy verbs, and a port sweep of the ingress address | AC-016 |
| `PublishedEndpointTests` — only the node-facing routes answer on the published endpoint; audit, sessions, approvals and region administration must 404 | ADR-0006 constraint 3, M4-16 |
| `Invoke-NodeReachabilityProbe.ps1` — connections from the node to RFC1918, CGNAT, link-local and loopback, run as the `mina-envoy` service account | AC-017, M4-10 |

## Why the controls matter

Every assertion in this directory is a negative — "not reachable", "not proxied", "not answered" —
and a dead node, a wrong address or a firewall in front of the tester satisfies all of them at once.
So each half opens with something that must **succeed**:

- the tunnel port answers TLS and demands a client certificate issued by the internal CA;
- the published endpoint returns 200 on `/healthz`, and its node routes answer 401 rather than 404
  (a 404 everywhere would mean the host is simply down);
- the node reaches the public internet, and root reaches IMDS.

That last pair is also what makes the link-local result meaningful: blocked for `mina-envoy`,
reachable for root, which is M4-10's uid-scoped rule rather than a host-wide block that would break
certificate and sidecar provisioning at the next boot.

## The refusal that is easy to get wrong

`A_certificate_that_chains_to_the_real_ca_is_still_not_enough` asserts the connection is refused
*after* TLS, with `HTTP/1.1 403 Forbidden`. A TLS-layer refusal would also look like "refused" while
proving nothing about admission — the certificate would simply have been rejected on its own merits,
and the probe would never have reached the check it exists to exercise. This is D-19's claim that a
chained certificate is necessary but not sufficient, and it is only worth anything if the refusal
comes from the sidecar.
