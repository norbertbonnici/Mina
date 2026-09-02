# Requirements

## 1. Purpose
Provide authorised analysts with an organisation-controlled, governed research-browsing path whose public internet egress is separated from the organisation's ordinary fixed public IP addresses.

## 2. Scope
### In scope
- Azure-hosted internet egress for a dedicated Edge research context.
- Control plane on the FIAU Proxmox cluster, with Azure Key Vault and immutable blob storage as its
  only Azure dependencies (ADR-0006).
- Entra SSO and authorisation.
- Windows 11 / Intune-managed endpoint integration.
- Analyst selection of approved EU egress regions.
- Session governance and audit.
- Manager-approved, time-bound URL-telemetry suppression.
- Wazuh security/audit integration.
- SigNoz observability integration.
- Management-only break glass.
- Infrastructure as code and automated testing.

### Out of scope for MVP
- Remote access into corporate networks.
- Multi-cloud.
- General-purpose device-wide consumer VPN replacement.
- Open/public proxy service.
- Guaranteed anonymity.
- Egress-IP rotation (design should permit later addition).
- TLS interception unless separately approved.

## 3. Functional requirements
| ID | Requirement |
|---|---|
| FR-001 | Provide a dedicated `Mina` Edge launch experience on managed Windows 11 endpoints. |
| FR-002 | Reuse the user's current Entra sign-in under normal operation. |
| FR-003 | Permit only authorised users on appropriate managed/compliant devices. |
| FR-004 | Route only the protected research-browser traffic through research egress. |
| FR-005 | Allow analysts to select an egress region from an administrator-approved EU list. |
| FR-006 | Expose protected/unprotected state, selected region and session mode to the analyst. |
| FR-007 | Fail closed if protected egress cannot be established or maintained. |
| FR-008 | Record session/audit metadata and the approved level of URL/hostname telemetry by default. |
| FR-009 | Allow an analyst to request a time-bound sensitive session with URL telemetry suppressed. |
| FR-010 | Require manager approval before suppression becomes active. |
| FR-011 | Automatically expire suppression and restore normal policy or terminate the sensitive session. |
| FR-012 | Preserve non-URL audit metadata during sensitive sessions. |
| FR-013 | Provide a management interface for approvals, health, policy and audit visibility. |
| FR-014 | Forward security/audit events to Wazuh. |
| FR-015 | Export operational telemetry to SigNoz. |
| FR-016 | Provide management-only break-glass access with high-severity auditing/alerting. |
| FR-017 | Support approximately 50 concurrent users with headroom. |

## 4. Security requirements
| ID | Requirement |
|---|---|
| SR-001 | Research egress nodes must not provide a route into internal corporate networks. Unchanged by ADR-0006: the on-premises control plane is reached at a published DMZ endpoint over the public internet, exactly as the Azure endpoint was, so nodes gain no corporate route. |
| SR-002 | No unauthenticated forwarding or open-proxy behaviour. |
| SR-003 | Explicitly mitigate/test DNS, IPv6, WebRTC and fallback leaks. |
| SR-004 | Use least privilege for Azure RBAC, applications, managed identities and administrators — **and, since ADR-0006, for the on-premises plane: Proxmox administrative access, the SQL Server host and its sysadmin roles, and local OS accounts on the control-plane VMs.** |
| SR-005 | Prefer managed identities and Key Vault over static credentials. On premises this means Azure Arc managed identities for SQL Server, Key Vault and storage (D-17/D-18); no stored credential anywhere in the product. |
| SR-006 | Protect endpoint local IPC and configuration from ordinary-user tampering. |
| SR-007 | Apply Entra Conditional Access/device compliance where feasible. |
| SR-008 | Separate platform administration and approval authority where practical. |
| SR-009 | Break-glass use must generate a high-severity security event. |
| SR-010 | Infrastructure and policy changes must be auditable. |
| SR-011 | Infrastructure must be reproducible from source-controlled IaC. |
| SR-012 | Maintain dependency/SBOM, vulnerability-management, patching and rollback processes. |

## 5. Privacy/audit requirements
- URL logging must be treated as a separate telemetry concern from core audit logging.
- Do not silently deploy TLS interception to obtain HTTPS URL paths.
- Retention periods are configurable and require legal/data-protection approval before production.
- Sensitive-session suppression cannot remove approval/session/admin audit events.
- Permanent logging exemptions are prohibited.

## 6. Operational requirements
- **Hybrid (ADR-0006): control plane on the FIAU Proxmox cluster, research egress in Azure.** The
  on-premises plane must be reproducible from source-controlled configuration to the same standard
  AC-018 demands of the Azure side; a hand-built control plane would not satisfy it.
- EU egress at launch.
- At least two production egress regions are desirable for hardened production, subject to Phase 0 design/cost review.
- Health monitoring, capacity monitoring and alerting must be defined before production.
- Control-plane availability — Proxmox HA, SQL Server backup/restore, uptime of the published
  node-facing endpoint — is FIAU-provided since ADR-0006 and must be defined before production (M4-22).
- Production deployment requires explicit human approval.
