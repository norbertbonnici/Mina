# Mina demo harness

**Development only. Not a deployable artefact, and not part of any shipped package.**

Runs the whole platform in one process so the protected path can be driven from a real browser:

```text
your browser → agent loopback proxy → mTLS tunnel → egress → the internet
                                   ↑
                    session certificate issued by the real control-plane API
```

## Run it

```bash
dotnet run --project demo/Mina.Demo -c Release
```

To run the **real Envoy** as the egress (recommended — it is the actual production component, and
the hostname telemetry you see is Envoy's own access log), point `MINA_ENVOY` at an Envoy binary:

```bash
MINA_ENVOY=/path/to/envoy dotnet run --project demo/Mina.Demo -c Release
```

Without it the demo uses an in-process stand-in that enforces the same mTLS + CONNECT contract, and
says so on screen. Use `--proxy-port <n>` to change the default port (18080).

## Point a browser at it

- **Firefox** — Settings → Network Settings → Manual proxy: HTTP proxy `127.0.0.1`, port `18080`,
  tick "Also use this proxy for HTTPS".
- **Chrome / Edge** — launch with `--proxy-server="http://127.0.0.1:18080"`. This is exactly what
  the agent will pass the research browser on a managed endpoint.
- **curl** — `curl -x http://127.0.0.1:18080 https://example.com`

Every site you visit is printed as the egress saw it: `example.com:443`. Hostname and port only —
never the URL path, because nothing decrypts TLS anywhere in this design (ADR-0002 Option 1).

## What to try

| Key | What it demonstrates |
|---|---|
| `k` | **Fail closed.** Ends the session and tears down the proxy. The browser immediately has no route out — it does not fall back to ordinary corporate egress (FR-007, AC-004). |
| `r` | Re-establish. Browsing resumes on the same port. |
| `n` | Renewal rotates the session certificate — same session id, new credential (the lease model in ARCHITECTURE §4). |
| `a` | Analyst asks for URL-telemetry suppression on the live session. Approve it in the management UI, then press `v`. |
| `v` | Activate the approval. Refused unless somebody else approved it (AC-010). |
| `s` | Current session, region, logging mode and whether the path is open. |
| `q` | Quit; the session is ended with the control plane. |

The `info:` lines interleaved in the output are the control plane's real audit events
(`session_started`, `session_ended`, `session_renewed`) as they are written.

## The management UI

The demo also serves the management console at `http://127.0.0.1:18091` (`--ui-port` to change it),
signed in as an approver, reading the very same sessions and approvals the API is writing. The full
governance loop is therefore visible end to end: press `a` to raise a suppression request as the
analyst, approve it in the browser, press `v` to activate, and watch the session turn Sensitive on
the Sessions screen.

## What is real here, and what is not

**Real:** the control-plane API and its authorisation (analyst role, device compliance, region
selectability), CSR-based issuance with the private key never leaving the agent, the short-lived
session certificate, the mTLS tunnel, the loopback CONNECT proxy and its fail-closed behaviour, and
— with `MINA_ENVOY` set — the egress running the committed production config.

**Not real:**

- **Sign-in.** This process substitutes a demo authentication handler for Entra. That substitution
  lives in the demo, not in the API: the shipping control-plane API contains no bypass.
- **The egress is local**, so traffic exits from this machine's IP, not an Azure egress IP. Proving
  the observed public IP changes (AC-003) needs the Azure PoC stamp.
- **Storage and CA are in-memory** — sessions and the CA are lost on restart, as the startup
  warnings say.
- **Sign-in to the UI is substituted too** — every visitor is the approver. The shipping UI refuses
  its development sign-in outside a Development host.
- **No Windows enforcement.** WFP rules, browser pinning and the peer check that verifies the
  connecting process is the managed research browser are M2-4 and need the Windows lab. In this
  demo any local process can use the proxy port.
