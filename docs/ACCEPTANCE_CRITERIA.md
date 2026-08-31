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
- [ ] AC-013 Wazuh receives the documented security/audit event set. *(The event set is emitted to a durable, hash-chained audit store and tested; delivery to Wazuh over the ADR-0005 tunnel is M3-5 and needs the network team's rule confirmation.)*
- [ ] AC-014 SigNoz receives documented operational telemetry without accidental sensitive URL leakage.
- [ ] AC-015 Break-glass is unavailable to ordinary analysts and use generates a high-severity event.
- [ ] AC-016 Egress endpoints are not externally usable as unauthenticated/open proxies.
- [ ] AC-017 Egress nodes cannot reach internal corporate/RFC1918 destinations except explicitly approved platform dependencies.
- [ ] AC-018 A clean test environment can be recreated from source-controlled IaC.
- [ ] AC-019 Security tests are automated where practical and evidence is retained with the release.
