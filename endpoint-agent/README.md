# endpoint-agent

The Mina agent that runs on the managed Windows 11 endpoint. It holds the research session and
serves the research browser through a loopback CONNECT proxy whose only route out is the
authenticated mTLS tunnel to an Azure egress node (ADR-0001 Option C).

## How a session works

1. The agent acquires an Entra access token (production: MSAL + WAM broker, reusing the user's
   existing Windows sign-in — FR-002).
2. It generates an EC key pair **on the endpoint** and sends only a CSR to the control plane. The
   private key never leaves the device.
3. The control plane authorises role, device compliance and region (AC-008) and returns a
   short-lived certificate bound to the session, plus the egress endpoint for the chosen region.
4. The agent opens the loopback proxy. Browser CONNECTs are forwarded over mTLS to the egress,
   which resolves the hostname and dials out — so DNS never happens on the endpoint.
5. Before the lease lapses the agent renews with a **fresh token and a fresh key pair**, so
   revocation and Conditional Access re-evaluation take effect within one lease period.

## Fail-closed

The protected path is open only while a session is live. `SessionTunnelConnectionFactory` is the
single choke point: with no session it throws, the proxy answers the browser with an HTTP error,
and `ProtectedPathWorker` tears the listener down entirely. There is no code path from the research
browser to the internet that does not go through the tunnel — no DIRECT fallback exists to take.

A dropped session results from any of: the analyst ending it, the control plane refusing renewal,
the session being ended or revoked elsewhere, the lease lapsing, or the control plane being
unreachable. All of them close the path rather than continue.

## What is deliberately not here yet (M2-4, Windows-only)

- **WAM-broker sign-in.** Until then a token must be supplied via `Mina:Agent:AccessToken`; the
  agent logs a warning saying so and cannot observe revocation.
- **WFP enforcement** pinning the research browser so it cannot reach anything but the loopback
  proxy (ADR-0001 variant C2).
- **Peer verification** — `LoopbackPeerAuthorizer` currently admits any loopback process; the real
  check resolves the peer PID to the managed research browser (THREAT_MODEL B1).
- **Launching the research browser** with the proxy port and hardening flags, and the tray UI.

These need the Windows 11 lab, which is also what ADR-0001's acceptance register is waiting on.

## Tests

`tests/e2e/Mina.Agent.E2E.Tests` runs the agent against the real control-plane API and an egress
stand-in, in process: full browse path, renewal rotating the credential, and every way a session can
be lost resulting in a closed path. `tests/integration/Mina.Transport.Tests` additionally drives the
same agent code through a real Envoy.
