# endpoint-agent

The Mina agent that runs on the managed Windows 11 endpoint. It holds the research session and
serves the research browser through a loopback CONNECT proxy whose only route out is the
authenticated mTLS tunnel to an Azure egress node (ADR-0001 Option C).

## How a session works

1. The agent acquires an Entra access token (production: MSAL + WAM broker, reusing the user's
   existing Windows sign-in — FR-002).
2. It generates an EC key pair **on the endpoint** and sends only a CSR to the control plane. The
   private key never leaves the device.
3. The control plane authorises role, that the token is device-bound, the Conditional Access
   authentication context when one is configured, and region (AC-008), and returns a
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

## The tray UI

`Mina.EndpointAgent.Tray` is the per-user WPF app that shows the analyst whether they are protected,
which region they are exiting from, and whether the session is being logged normally (FR-005,
FR-006). It talks to the agent over a named pipe and holds no authority of its own.

| Project | Target | What it is |
|---|---|---|
| `Mina.EndpointAgent.Ipc` | `net10.0` | The wire contract and the client. No Windows API, so both ends and the tests build anywhere. |
| `Mina.EndpointAgent.Tray.Core` | `net10.0` | Everything the panel decides — what it says, which buttons exist — as a pure projection of the agent's status. |
| `Mina.EndpointAgent.Tray` | `net10.0-windows` | The WPF shell and notification-area icon. Binds to the projection and nothing else. |

### The pipe is a privilege boundary

The agent runs as SYSTEM and the tray as the interactive user, so everything arriving on the pipe is
untrusted input from a process the analyst controls.

- **DACL**: SYSTEM full control, INTERACTIVE read and write — and deliberately *not*
  `CreateNewInstance`, so a process running as the analyst cannot join the listener set and answer
  the tray in the agent's place. No entry for Administrators (who can take ownership regardless, so
  it would not be a boundary) and none for NETWORK, so the pipe is unreachable over SMB.
- **`FirstPipeInstance`**: the agent refuses to start if the name is already taken. On a healthy
  endpoint it starts before any user code, so a name in use means a second agent or a squatter — it
  logs that as a tamper indicator rather than sharing (THREAT_MODEL B1).
- **Bounded**: 64 KiB frames, a 2-minute idle timeout, and four instances. A peer cannot hold the
  agent open by withholding a newline.
- **Server-side validation**: `TrayControlService` re-checks every operation. The two that matter —
  the tray cannot widen the region list (a region is accepted only if the control plane offered it,
  and the control plane checks again at issuance, AC-008), and it cannot put a session into
  sensitive mode (it can only ask; an approver who is not the requester decides, AC-010).
- **No secrets cross it**: the status carries state, region, mode, session id, lease and countdowns.
  Session key material, the client certificate and the Entra token stay on the agent's side (SR-006).

### What the panel refuses to offer

When the protected path is down, the panel has exactly two buttons: retry and end. There is no
control that continues browsing over ordinary corporate egress, and the alert says so in as many
words — an analyst who is not told will assume the page failed to load and try again in ordinary
Edge. That absence is asserted directly in `TrayPanelTests`.

Killing the tray removes the indicator and nothing else. Enforcement is the agent's: the WFP rules
bound to the research browser, and the loopback proxy not listening without a session.

## What is deliberately not here yet (M2-4, Windows-only)

- **WAM-broker sign-in.** Until then a token must be supplied via `Mina:Agent:AccessToken`; the
  agent logs a warning saying so and cannot observe revocation.
- **WFP enforcement** pinning the research browser so it cannot reach anything but the loopback
  proxy (ADR-0001 variant C2).
- **Peer verification** — `LoopbackPeerAuthorizer` currently admits any loopback process; the real
  check resolves the peer PID to the managed research browser (THREAT_MODEL B1).
- **Launching the research browser.** ARCHITECTURE §3.1 has the agent spawning it, which a SYSTEM
  service cannot do into the interactive desktop without duplicating the user's token
  (`WTSQueryUserToken` → `CreateProcessAsUser`). That is a security-relevant design point, so the
  tray does not launch it either and the panel offers no launch button until it is settled — see the
  open question in ARCHITECTURE §3.1.

These need the Windows 11 lab, which is also what ADR-0001's acceptance register is waiting on.

## Tests

`tests/e2e/Mina.Agent.E2E.Tests` runs the agent against the real control-plane API and an egress
stand-in, in process: full browse path, renewal rotating the credential, and every way a session can
be lost resulting in a closed path. `tests/integration/Mina.Transport.Tests` additionally drives the
same agent code through a real Envoy.

`tests/unit/Mina.EndpointAgent.Tests` covers the tray: the server-side rules, the panel projection,
and the transport over a real named pipe including malformed, oversized and faulting exchanges. Two
controls have no Unix equivalent — the pipe DACL and `FirstPipeInstance` — so those tests are marked
`[WindowsOnlyFact]`, skip visibly on Linux, and run in CI's `endpoint-windows` job.
