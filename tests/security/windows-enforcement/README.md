# tests/security/windows-enforcement

The ADR-0001 M1-5 verification register. Admin-only PowerShell that measures what Windows and Edge
**actually do** under the chosen enforcement variant, rather than what their documentation says they
do. Each script mutates host state (firewall rules, packet capture, browser policy), cleans up after
itself, and prints a verdict.

These run **by hand on a Windows box**, not in CI: they need an administrative session, `pktmon`,
a real Edge installation, and an off-box target. CI has none of those.

## Run the readiness check first

`Initialize-LabHost.ps1` establishes that results from this host will mean anything. It is not one
of the register items; it is the thing that stops the register producing confident nonsense.

```powershell
.\Initialize-LabHost.ps1                    # add -InstallMissing to install Edge Beta via winget
```

It records host identity (the SKU is the variable under test — earlier results were taken on Server
2025 and accepted for a client SKU by argument rather than measurement), asserts the preconditions
that would otherwise make a result vacuous, measures the target channel idle, and self-tests
`pktmon` so that a "0 packets" verdict is falsifiable rather than indistinguishable from a probe
that never worked here.

## Then the register

Not every script takes a target — passing one that a script does not declare is a binding error, so
the readiness banner prints the correct invocation per script:

| File | Register item | Target parameters |
|---|---|---|
| `Initialize-LabHost.ps1` | *(not an item — host readiness and provenance)* | `-TargetIp -TargetPort` |
| `Invoke-C2Verification.ps1` | 1 — per-app controls key on the image path | `-TargetIp -TargetPort` |
| `Invoke-PolicyScopeVerification.ps1` | 2 — policy scope across channels and profiles | `-TargetIp -TargetPort` |
| `Invoke-StartupLeakVerification.ps1` | 4 — no pre-proxy traffic at browser startup | `-TargetIp -TargetPort` |
| `Invoke-WebRtcLeakVerification.ps1` | 5 — WebRTC leak harness against the chosen flag | *none* |
| `Invoke-DnsLeakVerification.ps1` | DNS — does the browser resolve names itself while proxied? | *none* |
| `Invoke-Ipv6LeakVerification.ps1` | IPv6 — does it ever reach an IPv6-only destination directly? | *none* |
| `Invoke-LoopbackBypassVerification.ps1` | Loopback — can a research page reach the analyst's own machine? | *none* |
| `Invoke-QuicDohVerification.ps1` | Pins the QUIC and DoH policy names behaviourally | `-TargetIp` only |
| `MinaEnforcementProbe.psm1` | The shared predicates every script above calls | — |

## The target must be off-box, and nothing may listen on it

Windows exempts traffic to the host's own address from outbound filtering, so a canary on the
machine under test is reached even by a process that is fully blocked — an on-box target turns every
one of these into a test that always passes. Nothing may listen on the port either, or the counter
moves for reasons that have nothing to do with the process under test.

Every script defaults to the lab address `10.20.40.21`. **Do not point these at a public resolver to
work around a routing problem.** `1.1.1.1` and its kind answer on 443, which breaks the
"nothing listens" precondition, turns `Invoke-QuicDohVerification`'s forced-QUIC cases into a real
handshake with a stranger, and sends unsolicited probe traffic from a regulated organisation's lab
to a third party.

## Why the register exists at all

Every control ADR-0001 variant C2 rests on was measured here rather than assumed, and several
measurements contradicted the documentation. The loopback gap (THREAT_MODEL B1, info-disclosure) was
found this way: Chromium exempts loopback from proxying by default *and* Windows never filters
loopback through WFP, so the image-path block is no backstop — two documented behaviours that are
only a hole when they meet. `BuiltInDnsClientEnabled=0` turning out not to suppress DoH is another.
A register that only confirmed expectations would not have been worth writing.
