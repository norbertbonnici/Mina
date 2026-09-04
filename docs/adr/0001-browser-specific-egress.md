# ADR-0001: Browser-specific protected egress — steering and transport

- Status: **Accepted 2026-08-31** — Option C, variant C2, mTLS HTTP/2 transport (D-02/D-03),
  conditional on the Phase 1 verification register (M1-5): a failed verification returns this
  ADR to Proposed
- Date: 2026-08-31
- Decision owners: FIAU platform owner, security architecture
- Related: `docs/ARCHITECTURE.md` §4–§6, ADR-0002, ADR-0004

## Context

Only the dedicated Edge research context may use Azure research egress; all other endpoint
traffic must keep ordinary corporate routing. The mechanism must be fail-closed, resist
DNS/IPv6/WebRTC/fallback leaks, bind to Entra identity, never become an open proxy, and be
deployable/enforceable via Intune on managed Windows 11.

## Constraint analysis (facts that drive this decision)

These Windows/Chromium behaviours were established during Phase 0 analysis and constrain all
options. Items marked **[V]** are on the Phase 1 verification register (§ Verification) and must
be re-confirmed by prototype before the decision is finalised.

1. **Per-app network controls key on the executable image path.** Windows Filtering Platform
   (WFP) application conditions and the Windows per-app VPN traffic filters identify an
   application by its image path only — not by command line, profile, or window. A research
   *profile* and ordinary Edge are the same `msedge.exe`, so no network-layer mechanism can
   distinguish two profiles of the same Edge installation. **[V — confirmed 2026-09-04, see
   register item 1]**
2. **Chromium enterprise policies are instance-global.** Edge reads policy from a single
   machine/user registry location; a second `--user-data-dir` instance receives the same
   policies. Proxy/WebRTC/QUIC policies set for the research context would also apply to the
   analyst's ordinary Edge (e.g. breaking Teams calls if WebRTC UDP is disabled). Edge channels
   (Stable/Beta/Dev) are believed to share the same policy location. **[V]**
3. **A fixed proxy configuration does not fall back to DIRECT.** With a fixed proxy (no PAC,
   no `DIRECT` alternative), an unreachable proxy yields a browser error, not direct
   connectivity. This gives inherent fail-closed behaviour. **[V]**
4. **Proxied requests delegate DNS to the proxy.** Chromium sends the hostname in `CONNECT`
   (HTTPS) or the absolute URI (HTTP); name resolution happens at the egress, not on the
   endpoint. This removes the endpoint DNS-leak path for proxied traffic by construction.
5. **WebRTC and QUIC bypass proxies by default** and need explicit browser-level controls
   (IP-handling policy / QUIC disablement) or network-level blocking.

## Options considered

### Option A — Local privileged agent + WireGuard tunnel + per-app steering

Agent establishes a WireGuard tunnel to an Azure egress node and steers only research-browser
traffic into it (WFP callout redirect, a filter driver such as WinDivert, or route manipulation).

- **Pros:** IP-level transport (all protocols), low overhead, natural fit for future egress-IP
  rotation, mature cryptography, official signed Windows driver (wireguard-nt).
- **Cons:** Per-app steering hits constraint 1 — it cannot distinguish Edge profiles, so it
  needs a distinct research binary anyway; flow *redirection* (as opposed to block/allow)
  requires a kernel callout driver (heavy: driver signing, servicing) or a third-party driver
  (WinDivert — supply-chain and support concerns for an FIU); DNS split-handling must be built
  and tested separately; fail-closed must be constructed from route/firewall state rather than
  falling out of the design.
- **Verdict:** viable but the highest-complexity path; rejected for MVP. WireGuard remains a
  candidate *transport* under Option C and for post-MVP IP rotation.

### Option B — Windows VPN platform (VPNv2 CSP per-app traffic filters) + encrypted tunnel

Intune-deployed VPN profile with app-based traffic filters so only listed apps use the tunnel
(Azure VPN Gateway P2S or a custom VPN plugin).

- **Pros:** first-party, Intune-native deployment; no custom kernel code.
- **Cons:** app rules are image-path-based (constraint 1) so the profile problem persists;
  fail-closed and leak behaviour of the built-in client stack is hard to control precisely
  (fallback behaviours, IPv6 handling, DNS registration); Entra-authenticated P2S requires the
  Azure VPN Client, whose interaction with per-app traffic filters is poorly specified;
  per-user session governance (short leases, server-side revocation, region selection) does not
  map cleanly onto VPN profiles.
- **Verdict:** rejected. Weakest control fidelity for the properties that matter most here.

### Option C — Local agent with loopback proxy + authenticated tunnel to Azure egress proxy (**recommended**)

The research browser is locked to a fixed proxy at `127.0.0.1:<port>` served by the Mina
endpoint agent. The agent authenticates to the control plane with the user's existing Entra
session (WAM broker), receives a short-lived session credential, and forwards proxied traffic
through an encrypted, mutually authenticated channel to the egress node in the selected region,
where an authenticated proxy (Envoy) performs the actual internet connections behind Azure NAT
egress IPs.

Why this fits the required properties:

| Required property | How Option C satisfies it |
|---|---|
| Browser-only routing | Proxy configuration is applied only to the research browser context; nothing else on the endpoint references it. |
| Fail closed | Fixed proxy with no DIRECT fallback (constraint 3); agent refuses/blocks the loopback listener whenever no authenticated session exists. |
| DNS leak resistance | Hostnames resolve at the Azure egress (constraint 4); no research DNS touches corporate resolvers. |
| IPv6 leak resistance | No local resolution → no local AAAA path; endpoint-side direct IPv6 blocked under variant C2; egress is IPv4-only at MVP (see ARCHITECTURE §8). |
| WebRTC | Browser IP-handling policy forces WebRTC through the proxy or disables non-proxied UDP; under C2, direct UDP from the research browser is blocked at WFP regardless. |
| Entra-bound | Session credential issued only after Entra auth + role + device checks; egress proxy accepts only mTLS with a valid session-bound certificate. |
| No open proxy | Egress ingress requires mTLS with platform-issued short-lived client certificates; no unauthenticated listener; external open-proxy scans in CI. |
| No corporate routing | Egress subnets deny RFC1918/corp prefixes at NSG/route level; automated reachability tests. |
| Hostname telemetry | Falls out at the egress proxy from `CONNECT` targets without TLS interception (ADR-0002 Option 1). |

#### Enforcement variants (sub-decision C-enf)

Constraints 1–2 mean "how do we stop the research context escaping the proxy" has three variants:

- **C1 — Stable Edge, separate `--user-data-dir`, agent-mediated launch.** The Mina shortcut
  runs the agent, which spawns Edge with a dedicated user-data-dir and locked flags
  (`--proxy-server`, WebRTC/QUIC/DoH hardening flags). No second binary needed.
  *Residual risk:* an analyst (or malware as the analyst) can launch Edge against the research
  user-data-dir manually without the flags, sending research-profile state (cookies, sessions)
  over ordinary corporate egress. Mitigations are detective, not preventive (agent watches for
  unmanaged instances; profile data minimisation).
- **C2 — Distinct research browser binary + SYSTEM-level WFP rules (recommended).** The research
  browser is an Edge installation with its own image path (secondary Edge channel, e.g. Edge
  Beta, or another owner-approved distinct-path option). The agent (SYSTEM) installs persistent
  WFP rules for that image path: allow loopback to the agent proxy only; block all other
  outbound IPv4/IPv6, including DNS. Even a manually launched instance with no flags can reach
  nothing but the authenticated proxy — hard fail-closed at the network layer, tamper-resistant
  against non-admin users.
  *Trade-off:* a pre-release update channel carries different servicing risk than Stable, and
  channel-shared policy registry (constraint 2) still limits per-instance *policy* separation —
  C2 therefore relies on launch flags for browser-level hardening plus WFP for enforcement. **[V]**
- **C3 — Dedicated WebView2 research shell (a signed FIAU .NET application embedding the Edge
  WebView2 engine).** Strongest control: our own image path, our own proxy/flags per WebView2
  environment, no policy bleed, trivially WFP-targetable, familiar .NET delivery.
  *Trade-off:* it is not full Edge (extensions, profiles, collections, DevTools parity), which
  conflicts with the confirmed "Microsoft Edge is the protected research browser" constraint —
  only selectable if the owner relaxes that constraint.

#### Transport sub-options (sub-decision C-tx)

- **mTLS HTTP/2 CONNECT to Envoy (recommended):** outbound TCP 443 (firewall-friendly);
  per-session short-lived client certificates align with Entra session lifetimes and give the
  egress an authenticated per-session identity for telemetry/suppression; no kernel components;
  the terminating proxy is the same component that produces hostname telemetry.
- **WireGuard (alternative, kept open):** better for non-TCP futures and IP rotation; UDP/51820
  needs corporate firewall allowance; session binding requires per-session key provisioning and
  an inner authentication story for telemetry attribution.

## Recommendation

**Option C with enforcement variant C2 and mTLS HTTP/2 transport.** Phase 1 must prototype C2
and C1 side by side and re-verify every **[V]** item before this ADR is marked Accepted. If the
secondary-channel trade-off is rejected by the owner, fall back to C1 plus compensating
detective controls, or escalate C3 as a requirements change.

## Security/privacy consequences

- New trust in the endpoint agent (SYSTEM service): it becomes a security boundary and must be
  signed, Intune-managed, and its IPC hardened (SR-006). See THREAT_MODEL.
- The loopback proxy must not become a local open proxy for other endpoint processes: the agent
  verifies the connecting process (peer PID → image path/user-data-dir) before serving. 
- Hostname telemetry arises server-side (privacy-preferable to client instrumentation; see
  ADR-0002).
- No TLS interception anywhere in this design.

## Operational consequences

- Endpoint: one signed agent package + one browser installation/config, both via Intune.
- Azure: per-region egress stamp (LB → Envoy VMSS → NAT Gateway static IPs), internal CA for
  session certificates (Key Vault-backed), config push/pull between control plane and nodes.
- Rollback: agent uninstall restores a stock endpoint; egress stamps are disposable IaC.

## Verification register (Phase 1 gate)

Status keys: ⬜ not started · 🟡 partially evidenced · ✅ evidenced. Transport items are proven
on the dev machine. Windows items were blocked on a Windows 11 lab machine until 2026-09-04,
when items 1, 2, 4 and 5 — and the Edge half of item 3 — were evidenced on the admin workstation
(Windows Server 2025, build 26100 — the same kernel and WFP stack as Windows 11 24H2, with Edge
Stable 152 and Edge Beta 153 installed at distinct image paths). That substitution is sound for
identification and policy-scope behaviour but not for the Intune/managed-client half: anything
about enrolment, compliance or policy delivery still needs a real managed Windows 11 client.

1. ✅ WFP/per-app identification is image-path-only. **Evidenced 2026-09-04** by
   `tests/security/windows-enforcement/Invoke-C2Verification.ps1`, run against Edge Stable
   152.0.4191.62 and Edge Beta 153.0.4234.19 installed at distinct image paths. With an
   outbound block rule scoped to Stable's image path, egress measured at the NIC (pktmon
   counters, off-box target) was: baseline Stable 24 packets; Stable same profile 0; Stable
   **a different `--user-data-dir` profile** 0; **Edge Beta** 30. So a second profile of the
   same binary is caught by a rule aimed at that binary — profiles are not separable, and C1
   cannot be enforced at the network layer — while a different image path is untouched, so C2
   can be. Reproducible: the script prints a verdict and refuses to pass on an inconclusive
   baseline.
   *Remaining:* this used Windows Firewall rules, a WFP consumer that keys on the same image
   path, rather than the `FwpmFilterAdd` filters the shipping agent installs; the agent's own
   filters and their tamper resistance against a local administrator are M2-4, and "C2 rules
   behave as designed" end-to-end still wants a managed Windows 11 client.
   *Method note that cost a false pass first time:* Windows treats traffic to the host's own
   address as loopback and exempts it from outbound filtering, so a canary listening on the
   test machine is reached even by a comprehensively blocked process. On-box canaries make
   every case pass. This applies to the M1-6 leak suites too — point them off-box.
2. 🟡 Edge channels share the policy registry location; flag-based hardening holds for a spawned
   instance. **Constraint confirmed 2026-09-04** by
   `tests/security/windows-enforcement/Invoke-PolicyScopeVerification.ps1`. A single
   `HKLM\SOFTWARE\Policies\Microsoft\Edge` fixed-proxy policy pointed at a dead local port took
   Stable from 24 packets to 0, Beta from 24 to 0, and a second `--user-data-dir` profile to 0 —
   so one machine-wide location governs **both channels and every profile**, exactly as
   constraint 2 assumes. Removing the policy returned Stable to 23 packets, which is what makes
   those zeros attributable to the policy rather than to a broken path. `--proxy-server` passed
   as a launch flag produced 0 as well, so per-launch hardening does bind a spawned instance.
   Proven behaviourally rather than by reading `edge://policy`, because an unrecognised policy
   name sits in the registry looking correct and changes nothing.
   *Pinned:* `--proxy-server=<host:port>`; policy
   `ProxySettings={"ProxyMode":"fixed_servers","ProxyServer":"<host:port>"}` (REG_SZ). The older
   `ProxyMode` + `ProxyServer` pair is documented as **deprecated** but was verified still
   honoured by Edge 152/153 — the current form was tested precisely so shipping configuration
   need not rest on a deprecated name.
   *Remaining:* the QUIC, DoH and WebRTC names are **not pinned**. Documented candidates are
   `QuicAllowed` (DWORD), `DnsOverHttpsMode` (REG_SZ: off/automatic/secure) with
   `BuiltInDnsClientEnabled` (DWORD), `WebRtcLocalhostIpHandling` (REG_SZ, values including
   `disable_non_proxied_udp`) and `NetworkPredictionOptions` (DWORD, 0 to disable prefetch, for
   THREAT_MODEL N12) — but each needs its own observation to confirm the name is real and takes
   effect (an HTTP/3 origin, DNS capture, an ICE harness), which lands with items 4 and 5. Do
   not write these into `edge-integration/` as settled until then.
3. 🟡 Fixed-proxy fail-closed behaviour (no DIRECT fallback). *Agent-side* fail-closed is proven
   in `tests/integration` (tunnel loss ⇒ HTTP 502, never a direct path). **The Edge side is now
   evidenced too, 2026-09-04** by the item 2 run above: with a fixed proxy that nothing was
   listening on — set as policy, as a second profile, and as a launch flag — direct egress to
   the target measured 0 packets in every case, against a 23–24 packet baseline and control. An
   unreachable fixed proxy yields no connection rather than a direct one, which is the property
   the whole fail-closed design leans on.
   *Remaining:* this is one machine and one Edge build. Behaviour across the ring (multiple
   builds, managed clients, the update channel moving underneath) still needs the Intune test
   ring, and the browser is only half the path — the agent-side half is separately proven.
4. ✅ No pre-proxy traffic at browser startup under C2 (enforcement up before spawn).
   **Evidenced 2026-09-04** by
   `tests/security/windows-enforcement/Invoke-StartupLeakVerification.ps1`, against Edge Beta
   153.0.4234.19 as the research browser. Three cases, observed both as packet counters toward
   the nominated startup URL and as non-loopback TCP connections owned by that image path:
   - **no rule:** 30 packets to the startup URL and **9 distinct third-party endpoints**
     contacted that nothing asked for — Microsoft (`150.171.*`, `4.209.*`), Google
     (`142.250.181.193`, `172.217.116.4`) and Akamai (`2.23.231.*`, `95.101.234.*`), all on 443.
     N11/N12 is a live leak, not a theoretical one.
   - **rule in force before spawn:** 0 packets and **0 endpoints**. Nothing escaped.
   - **rule applied 2 s after spawn:** 6 packets and **12 endpoints** already gone. The ordering
     requirement is real, which is what makes the middle case worth anything — a rule only ever
     installed first proves nothing about whether installing it first matters.
   The endpoint counts vary run to run with whatever the browser decides to contact — a later
   run saw 7 and 6 rather than 9 and 12. The zero is the stable, load-bearing result; the
   non-zero figures are illustrative of scale, not fixed measurements.
   This is why ARCHITECTURE §3.1 has the rules persist whenever the agent is installed rather
   than being raised per session: the safe window is "always", and a two-second gap is enough to
   disclose the organisation's ordinary egress IP to a dozen endpoints.
   *Remaining:* headless was used to keep this scriptable, and headless Chromium suppresses some
   background services, so the 9 endpoints are a floor rather than the full picture of what a
   headed research browser emits. Prefetch/preconnect flag behaviour specifically
   (`NetworkPredictionOptions`) is not separately pinned — see item 2's remaining.
   **The endpoint observation is TCP-only** (`Get-NetTCPConnection`), so this run says nothing
   about UDP: no DNS query was measured in any case, including the unfiltered one, even though
   the browser must have resolved those nine hosts somehow. The blanket outbound block covers
   UDP too, but that is inference from the rule's scope, not measurement — DNS belongs to N12
   and the M1-6 DNS leak suite, and needs its own observation.
   *Note for M2-4:* Windows does not filter loopback, so "block all outbound for this image"
   already leaves the loopback-to-proxy path open and C2's allow rule is implicit for a firewall
   rule. Filters added directly through the WFP API are not automatically so forgiving — an ALE
   filter can block loopback — so the agent's own rule set must permit that path explicitly
   rather than inheriting this behaviour. This test cannot surface that.
5. ✅ WebRTC leak harness passes with the chosen flag/policy set. **Evidenced 2026-09-04** by
   `tests/security/windows-enforcement/Invoke-WebRtcLeakVerification.ps1` driving
   `tests/security/canaries/webrtc-harness.html` (TEST_STRATEGY §2's harness page, built here).
   ICE is offered a STUN server on an off-box address nothing listens on; the measurement is the
   UDP that leaves, since against a real STUN server those same packets would return the public
   egress address. Edge Beta 153, counts as transmitted/dropped:
   - **no proxy, no hardening:** 6 transmitted — ICE does emit UDP.
   - **fixed proxy, no hardening:** 6 transmitted. **WebRTC bypasses the proxy**, confirming
     constraint 5. This is the finding that matters: the fixed proxy is the control the
     fail-closed design leans on, and it does nothing whatsoever about WebRTC.
   - **proxy + `--webrtc-ip-handling-policy=disable_non_proxied_udp`:** 0 transmitted, 0 dropped,
     **0 candidates** — suppressed at source, no socket ever created.
   - **proxy + policy `WebRtcLocalhostIpHandling=disable_non_proxied_udp` (REG_SZ):** identical.
     This **pins the policy name behaviourally**, which item 2 could only list as a documented
     candidate.
   - **C2 image-path block, no browser flags:** 0 transmitted but **6 dropped**, and a candidate
     still gathered — the browser tried and the network layer caught it.
   The last two rows are the defence-in-depth story stated precisely: the flag or policy stops
   the attempt being made, and the image-path rule stops it landing if the flag is absent,
   stripped or ignored (THREAT_MODEL B1, an analyst stripping launch flags).
   *What an adversary site learns (AC-007):* on this build the single host candidate is
   mDNS-obfuscated (`<uuid>.local`) with **no literal address**, so candidate content is not
   where the leak shows up — the UDP egress is. Do not read "mDNS obfuscation is on by default"
   as WebRTC being safe by default; the packets still leave.
   *Measurement note, because it produced a false result first:* pktmon's counter rows carry a
   Counter column (`Upper`/`Lower`/`Drops`), and reading Tx without it reports **dropped packets
   as sent** — which turned the image-path case into an apparent "enforcement gap" until the
   per-component output was inspected. Invisible for TCP, where a blocked `connect()` yields no
   packet at all; decisive for UDP, where `sendto()` produces one that is then dropped. The
   module now separates the two, and reports drops as evidence in their own right: silence alone
   cannot distinguish "blocked" from "never ran".
   *Remaining:* headless, as with item 4. QUIC is untouched — constraint 5 names it alongside
   WebRTC and `QuicAllowed` is still an unpinned documented candidate. No real STUN server was
   used, so the public-address disclosure is inferred from the egress rather than observed
   returning. AC-007 as a whole still wants the M1-6 suite against a live stamp.
6. 🟡 Envoy CONNECT termination + mTLS client-cert authorisation. **Functionally evidenced**
   2026-08-31: the real .NET agent tunnels through a real Envoy 1.39.1 running the committed
   config, mTLS client-cert enforced, hostname telemetry emitted (interop test + config
   validation). Remaining: behaviour at ~50 concurrent (load test, M4) and HTTP/2-CONNECT
   multiplexing (currently HTTP/1.1 for the PoC).
7. ⬜ Corporate firewall permits outbound 443 to egress ingress IPs (assumption A5).

## Approval

Approved by the project owner on 2026-08-31: Option C (D-02), enforcement variant C2 with the
channel trade-off accepted (D-03), mTLS HTTP/2 transport (C-tx). Acceptance is conditional on
the verification register above being satisfied by the M1-5 prototypes; the C1 fallback and C3
escalation paths remain documented if verification fails. See `docs/PHASE0_DECISIONS.md`.
