# Mina

## Mission
Build an organisation-controlled secure internet research egress platform in Microsoft Azure. Authorised analysts use a dedicated locked-down Microsoft Edge research profile whose internet traffic exits through approved Azure public egress addresses instead of the organisation's normal fixed public IPs.

This is **not** a remote-access VPN into the corporate network and must never become an open proxy.

## Authoritative documents
Read these before making architectural or implementation changes:
- `docs/REQUIREMENTS.md`
- `docs/ARCHITECTURE.md`
- `docs/THREAT_MODEL.md`
- `docs/ACCEPTANCE_CRITERIA.md`
- `docs/IMPLEMENTATION_PLAN.md`
- `docs/LOGGING_AND_PRIVACY.md`
- `docs/adr/`

If code and documentation conflict, stop and surface the conflict. Do not silently reinterpret a security requirement.

## Confirmed environment
- Microsoft Azure only; no multi-cloud requirement.
- Corporate-managed Windows 11 endpoints enrolled in Intune.
- Microsoft Entra ID is the identity plane.
- Dedicated Entra enterprise application.
- Reuse the user's existing signed-in Entra session; no separate password store.
- Microsoft Edge is the protected research browser.
- Approximately 50 concurrent users initially.
- EU egress regions at launch; analysts may select only administrator-approved regions.
- IP rotation is post-MVP / nice-to-have.
- Wazuh receives security and audit events.
- SigNoz receives service observability/operational telemetry.

## Non-negotiable security properties
1. Only the protected research-browser traffic uses research egress. Normal endpoint traffic retains normal corporate routing.
2. Protected browsing fails closed. Loss of the protected path must not silently expose browsing through normal organisational egress.
3. No unauthenticated forwarding, open proxy, or general-purpose public VPN service.
4. No route from research egress nodes into internal corporate networks unless a future, separately approved ADR explicitly changes this.
5. Explicitly address DNS, IPv6, WebRTC, proxy and fallback leakage.
6. Bind access to Entra identity and appropriate managed/compliant device posture.
7. Use least privilege, managed identities and Key Vault where appropriate.
8. Deploy and manage endpoint configuration/components through Intune; sign endpoint code/scripts where applicable.
9. Infrastructure must be reproducible as code. Prefer Terraform unless an approved ADR says otherwise.
10. Do not claim anonymity. The goal is controlled separation of research egress from ordinary organisational egress with governance and auditability.

## Logging and sensitive sessions
Default sessions record session/audit metadata and the approved level of URL/hostname telemetry.

Do **not** introduce TLS interception merely to obtain full HTTPS URLs. First establish what can be observed without decryption. If full paths require interception, stop and request a human architecture/privacy decision.

Analysts may request a time-bound sensitive session in which URL telemetry is suppressed. This requires manager approval through the management interface. Suppression must be enforced authoritatively by the control/logging plane, not by an analyst-controlled client toggle.

Even during suppression, retain:
- user identity;
- managed device identity;
- session ID and start/end;
- selected egress region;
- request and justification reference;
- approver and decision;
- approval/expiry timestamps;
- administrative and break-glass events.

No permanent logging exemptions.

## Break glass
Break-glass capability is management-only. It must be strongly protected, separate from ordinary analyst access, fully audited, and generate high-severity Wazuh events. Never expose break-glass credentials or mechanisms in source code, endpoint packages, or user-accessible configuration.

## Decisions you MUST NOT make silently
Stop and obtain explicit human approval before:
- introducing TLS interception / HTTPS decryption;
- choosing final production telemetry retention periods;
- adding any route to internal corporate networks;
- weakening Conditional Access or device-compliance requirements;
- creating permanent logging exemptions;
- adding third-party SaaS dependencies;
- materially increasing data collection;
- changing the approved production region/public-IP strategy;
- deploying to production;
- making destructive Azure or production identity changes.

Record approved architectural decisions as ADRs.

## Engineering workflow
### Phase 0 first
Before production implementation:
1. Inspect the repository and all authoritative docs.
2. Validate the objective, non-goals and assumptions.
3. Produce/update logical architecture, Azure resource design, trust boundaries and data flows.
4. Produce/update the threat model.
5. Identify architecture alternatives and ADRs.
6. Identify unresolved human decisions.
7. Produce the implementation backlog and test strategy.
8. Estimate Azure resource footprint and major cost drivers.
9. Stop for approval of unresolved architectural decisions.

### Implementation
After Phase 0 approval:
- Work milestone by milestone.
- Keep changes reviewable and testable.
- Update architecture/threat model/ADRs when design changes.
- Write unit, integration, security and end-to-end tests.
- Do not hard-code behaviour merely to satisfy tests.
- Before declaring a milestone complete, run tests and map evidence to `docs/ACCEPTANCE_CRITERIA.md`.
- Never perform production deployment or destructive cloud operations without explicit human approval.

## Repository layout
```text
/
  CLAUDE.md
  docs/
    REQUIREMENTS.md
    ARCHITECTURE.md
    THREAT_MODEL.md
    LOGGING_AND_PRIVACY.md
    ACCEPTANCE_CRITERIA.md
    IMPLEMENTATION_PLAN.md
    OPERATIONS.md
    adr/
  infra/
    terraform/
      modules/
      environments/dev/
      environments/test/
      environments/prod/
  control-plane/
  management-ui/
  endpoint-agent/
  edge-integration/
  integrations/
    wazuh/
    signoz/
  tests/
    unit/
    integration/
    security/
    e2e/
  scripts/
```

## Initial task
Start with **Phase 0 only**. Do not implement production code yet. Challenge unsafe or ambiguous assumptions. Return the Phase 0 design package and only the questions that genuinely require a human decision.
