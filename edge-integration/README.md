# edge-integration

The research browser's launch profile and hardening set for ADR-0001 variant C2 (M2-5).

`research-browser-flags.json` is the operational artefact: the flags the agent passes when it
launches the research browser. This file explains why each one is there, what it was measured
doing, and what is deliberately absent.

Nothing enters the flag set on the strength of a documentation page. A switch or policy name the
browser does not recognise is accepted silently and changes nothing, which looks exactly like it
working — so every entry below was verified by observing behaviour change, and the scripts that
did it are in `tests/security/windows-enforcement/` and re-runnable.

## What the research browser is

A **second Edge installation at its own image path** — Edge Beta on the verification machine.
Not a second profile of the analyst's ordinary Edge.

That is the whole of variant C2, and it exists because of one measured fact: Windows per-app
network controls identify an application by its **image path only**. A rule bound to Edge
Stable's path catches a second `--user-data-dir` profile of that same binary just as readily as
the first, while leaving a different installation untouched (ADR-0001 register item 1,
`Invoke-C2Verification.ps1`). So two profiles of one Edge cannot be told apart at the network
layer — C1 was unenforceable — and two installations can.

A dedicated `--user-data-dir` is still used, but understand what it does and does not do: it
separates **state** (cookies, history, sessions), not **network identity**. The enforcement
boundary is the image path.

## The flag set

| Flag | What it does | Evidence |
|---|---|---|
| `--user-data-dir={ResearchProfileDir}` | Keeps research browsing state out of the analyst's ordinary profile. | Register item 1 — state separation only; the network boundary is the image path. |
| `--proxy-server=http://127.0.0.1:{AgentProxyPort}` | The browser's only route out. A fixed proxy has no `DIRECT` alternative, so when the agent is not serving, browsing fails rather than falling back to corporate egress. | Register items 2 and 3, `Invoke-PolicyScopeVerification.ps1`: the flag binds a spawned instance, and with nothing listening on the proxy, direct egress measured **zero** packets at the NIC against a live baseline and a recovering control. |
| `--proxy-bypass-list=<-loopback>` | Removes Chromium's built-in exemption for loopback destinations, so a research page cannot reach services on the analyst's own machine. | `Invoke-LoopbackBypassVerification.ps1`: with a **dead** proxy — so any success proves the proxy was bypassed — the browser reached a local service by default, **and still did so under the C2 image-path block**, because Windows does not filter loopback. With this flag it did not. Confirmed against a live proxy not to break the route to the agent, which also lives on loopback. |
| `--webrtc-ip-handling-policy=disable_non_proxied_udp` | Stops WebRTC putting UDP on the wire outside the proxy. | Register item 5, `Invoke-WebRtcLeakVerification.ps1`: **a fixed proxy does not stop WebRTC UDP at all** — this flag took it to zero transmitted and zero ICE candidates gathered, i.e. suppressed at source. |
| `--no-first-run`, `--no-default-browser-check` | Operational hygiene, not security. Keeps an unattended launch from stalling on first-run UI. | — |

The proxy port is **discovered, never assumed**. `Mina:Agent:LoopbackPort` defaults to `0`, so the
agent binds an ephemeral port and passes the real one here. Anything that hard-codes a port
reintroduces a predictable local target.

## Why no machine-wide policies

`research-browser-flags.json` ships an empty `machineWidePolicies`, and that is a decision.

Edge reads policy from a **single machine-wide location that every channel and every profile
shares**. Measured directly (register item 2): one fixed-proxy policy took Edge Stable from 24
packets to 0, Edge Beta from 24 to 0, and a second profile to 0 — one location, every browser on
the machine. So there is no such thing as a policy scoped to the research context. Anything set
for it also lands on the analyst's ordinary Edge.

These names **are** pinned, and are listed here so a future decision does not have to re-derive
them:

| Policy | Value | Verified |
|---|---|---|
| `QuicAllowed` (DWORD) | `0` | Suppressed QUIC even against an explicit `--origin-to-force-quic-on`: UDP 12 → **0** → 12. |
| `DnsOverHttpsMode` (REG_SZ) | `off` | With `DnsOverHttpsTemplates` pointed at a watched resolver: 364 packets on `secure`, **0** on `off`. |
| `DnsOverHttpsTemplates` (REG_SZ) | resolver URI | As above. |
| `WebRtcLocalhostIpHandling` (REG_SZ) | `disable_non_proxied_udp` | Same effect as the flag; the flag is preferred because it is per-instance. |
| `ProxySettings` (REG_SZ, JSON) | `{"ProxyMode":"fixed_servers","ProxyServer":"…"}` | Works, and is the current form — `ProxyMode`/`ProxyServer` are deprecated though still honoured. The flag is preferred because this is global. |

**`BuiltInDnsClientEnabled = 0` does NOT suppress DoH** — 367 packets, indistinguishable from
baseline. Recorded because it is a documented candidate a reader would reasonably reach for; do
not use it, use `DnsOverHttpsMode`.

The reason none of them are applied: under C2 the research browser is already confined to the
agent's proxy by WFP rules bound to its image path. QUIC to the internet and DoH to an arbitrary
resolver are both blocked there — measured, not assumed (register items 4 and 5: with enforcement
in force the browser reached **nothing**, and WebRTC UDP was generated and then dropped). Setting
these policies machine-wide would degrade ordinary Edge — no QUIC, no DoH for the analyst's
normal browsing — to duplicate a control already in force for the browser that matters. If the
owner decides that trade is worth making for defence in depth, the names above are ready.

## Not here yet

- **Intune packaging** — the signed agent Win32 app, the browser install, and the shortcut. Needs
  an Intune-managed Windows 11 client, which the verification machine is not. This is the rest of
  M2-5.
- **The WFP rules themselves.** They are the agent's job (M2-4), installed at SYSTEM and
  persistent whenever the agent is installed — not raised per session, because a rule applied even
  **two seconds** after the browser starts already let 12 endpoints escape (register item 4). One
  caution for whoever writes them: Windows does not filter loopback, so the firewall-rule form of
  "block all outbound for this image" leaves the loopback-to-proxy path open implicitly. Filters
  added through the WFP API are not so forgiving — an ALE filter can block loopback — so the
  agent's rule set must permit that path **explicitly** rather than assume it inherits this.
- **`NetworkPredictionOptions`** (prefetch/preconnect, THREAT_MODEL N12). Deliberately unpinned:
  it belongs with the ADR-0007 decision on which background services the research profile
  disables, and pinning it alone would pre-empt that.
*(`--proxy-bypass-list=<-loopback>` was on this list until 2026-09-04; it is measured and shipped
now — see the flag table. The gap it closes was real: **the image-path block did not stop a
research page reaching the analyst's own loopback services**, so the browser flag is the only
control available for that path, not a second layer over one.)*

## How the pieces fit

```text
Intune ─ deploys ─→ agent (SYSTEM) ─ installs ─→ WFP rules bound to the research browser's image path
                          │                          └─ allow loopback→agent proxy, block everything else
                          ├─ binds an ephemeral loopback proxy, and only while a session is live
                          └─ launches the research browser with the flags in research-browser-flags.json
```

The flags are the first line and the WFP rules are the backstop, and the split matters: a browser
launched **without** the flags — by an analyst, or by malware acting as one — still reaches
nothing but the proxy. That is the property C2 was chosen for, and it is why the flag set is
defence in depth rather than the control itself.
