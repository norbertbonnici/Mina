# Acceptance Criteria

## MVP
- [ ] AC-001 Managed Windows 11 endpoint launches the dedicated research browser using a valid existing Entra session without a separate password prompt.
- [ ] AC-002 Only protected research-browser traffic uses Azure egress; normal applications retain normal routing.
- [ ] AC-003 External validation sees the selected Azure egress IP rather than the organisation's normal fixed public IP.
- [ ] AC-004 Loss of protected connectivity does not silently fall back to ordinary egress.
- [ ] AC-005 DNS leak testing passes.
- [ ] AC-006 IPv4/IPv6 leak/fallback testing passes.
- [ ] AC-007 WebRTC/common browser leakage testing passes according to the approved design.
- [ ] AC-008 Analyst can select an approved EU region and cannot select an unapproved region.
- [ ] AC-009 Default telemetry correlates the approved URL/hostname data with user, device and session. *(Ingest attributes every record to a session — and through it to user and device — or discards it; tested. Full evidence needs the live stamp.)*
- [ ] AC-010 Sensitive URL suppression cannot activate without manager approval.
- [ ] AC-011 Sensitive-session approval automatically expires.
- [ ] AC-012 Sensitive sessions retain mandatory non-URL audit events. *(Suppression is enforced authoritatively at ingest: a suppressed session's destinations are discarded and reduced to counts even if a node sends them, and the discrepancy raises a critical event; tested at service and HTTP level.)*
- [ ] AC-013 Wazuh receives the documented security/audit event set. *(The event set is emitted to a durable, hash-chained audit store and tested; delivery to Wazuh is M3-5. Since ADR-0006 the relay sits on the FIAU network beside Wazuh, so this is a local hop with no tunnel precondition.)*
- [ ] AC-014 SigNoz receives documented operational telemetry without accidental sensitive URL leakage. *(Scrub processors sit on the trace and log pipelines ahead of any exporter, with no way to disable them; content-scan tests assert a destination emitted as a span attribute or interpolated into a log message never reaches the exporter. Delivery to the real SigNoz is M3-6 — a local hop since ADR-0006.)*
- [ ] AC-015 Break-glass is unavailable to ordinary analysts and use generates a high-severity event.
- [ ] AC-016 Egress endpoints are not externally usable as unauthenticated/open proxies. *(mTLS against the internal CA plus node-side session admission since D-19/M4-11 — a chained, unexpired certificate is necessary but no longer sufficient; verified against a real Envoy and the sidecar in Docker: `EnvoyClientAuthTests`, `EnvoySessionAdmissionTests`.)*
- [ ] AC-020 A revoked or unknown session cannot open a new tunnel at an egress node beyond one session-view refresh interval, and a node that cannot reach the control plane refuses new tunnels rather than admitting on certificate validity alone. *(D-19/M4-11, `EnvoySessionAdmissionTests` against a real Envoy: revoked-session refusal, unknown-session refusal, and the fail-closed case with no sidecar answering, each with a passing control leg and a meta-test proving the fail-closed assertion would notice `failure_mode_allow` being turned on. Explicitly does **not** cover a tunnel already open at the moment of revocation — accepted limitation, THREAT_MODEL §7 item 6.)*
- [ ] AC-017 Egress nodes cannot reach internal corporate/RFC1918 destinations except explicitly approved platform dependencies. *(Since ADR-0006 the approved set is empty: the control plane is reached at a public endpoint, so the deny is blanket and stays an assertion rather than an allowlist — M4-20 re-checks it.)*
- [ ] AC-018 A clean test environment can be recreated from source-controlled IaC. *(Both halves: the Azure stamp and support resources, and the on-premises control plane from `environments/dev-onprem` — a hand-built Proxmox plane does not satisfy this.)*
- [ ] AC-019 Security tests are automated where practical and evidence is retained with the release.
