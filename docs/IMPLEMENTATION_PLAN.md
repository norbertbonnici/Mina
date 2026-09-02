# Implementation Plan

## Phase 0 - Architecture and security design
Deliverables:
- Architecture and data-flow diagrams.
- Transport comparison and ADR.
- Threat-model expansion.
- URL telemetry feasibility analysis and ADR proposal.
- Entra/Conditional Access integration design.
- Endpoint enforcement design.
- Resource model (Azure; hybrid since ADR-0006) and approximate cost drivers.
- Event schemas for Wazuh and SigNoz.
- Test strategy and implementation backlog.
- List of decisions requiring human approval.

**Gate:** Human architecture approval before production implementation.

## Phase 1 - Egress proof of concept
- Single non-production EU Azure region.
- IaC baseline.
- Encrypted endpoint-to-egress transport.
- Browser-only routing proof.
- DNS/IPv6/WebRTC/fallback tests.
- External open-proxy and internal-reachability tests.

## Phase 2 - Identity and endpoint integration
- Entra enterprise app/roles.
- Existing-session SSO.
- Device/compliance integration where feasible.
- Intune deployment.
- Dedicated Edge profile/shortcut.
- Protected state and approved-region selection.

## Phase 3 - Governance and telemetry
- Management UI/API.
- Manager approval workflow.
- Time-bound URL suppression.
- Core audit pipeline.
- Wazuh integration.
- SigNoz integration.

## Phase 4 - Production hardening
- **On-premises control plane (ADR-0006, backlog M4-14 to M4-28).** Proxmox provisioning as code:
  DMZ VLAN, publishing proxy, application and SQL hosts. Node-facing listener published from the
  FIAU DMZ, with split listeners in the API. Azure Arc onboarding for SQL Server Entra
  authentication and Key Vault/storage access. Immutable-blob audit export sink, and diagnostics
  and alerting on CA key use and audit-anchor access. On-premises break glass. ADR-0005 (telemetry
  over the Check Point tunnel) is retired: Wazuh/SigNoz delivery is a local hop.
- HA/capacity design: second region if approved; Proxmox HA pair with a background-service lease (M4-23).
- Key/secret rotation.
- Backup/restore (including on-premises SQL Server) and rebuild procedures.
- Patch/vulnerability management.
- Security review and penetration testing.
- Break-glass implementation and exercise.
- Runbooks, SLOs, alerts and rollback.

## Phase 5 - Optional enhancements
- Egress-IP rotation.
- Additional approved regions.
- Disposable/remote Azure-hosted browser mode for exceptionally risky research.
