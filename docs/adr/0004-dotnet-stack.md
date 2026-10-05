# ADR-0004: .NET implementation stack

- Status: **Accepted in full** (direction 2026-08-31; component details confirmed by owner
  2026-08-31, D-12)
- Date: 2026-08-31
- Decision owners: platform owner

## Context

The deploying organisation's engineering standardises on .NET. The project owner has directed that Mina's application
components be another .NET project. Infrastructure-as-code remains Terraform per the
non-negotiable project requirements (this ADR does not touch that). The Azure egress data plane
is a network component, not an application, and is considered separately below.

## Decision

- **Runtime:** .NET 10 (current LTS), C#, unless organisational standards pin a different LTS.
- **control-plane/** — ASP.NET Core Web API; Microsoft.Identity.Web for Entra token validation;
  EF Core on Azure SQL Database; managed identity to Key Vault; OpenTelemetry .NET SDK.
- **management-ui/** — Blazor Server with Entra sign-in and app-role authorisation
  (Analyst / Approver / Platform Admin).
- **endpoint-agent/** — .NET Worker Service running as a Windows service (SYSTEM) for WFP and
  session management, plus a per-user WPF/WinUI tray app for status and region selection
  (FR-006), communicating over an ACL'd named pipe. MSAL.NET with the WAM broker
  (`Microsoft.Identity.Client.Broker`) for silent SSO from the existing Entra session.
  Authenticode-signed; packaged and deployed via Intune (Win32 app).
- **edge-integration/** — launch profile, flags and (if ever adopted per ADR-0002 Option 2)
  extension artefacts; no standalone runtime.
- **Egress data plane:** Envoy on hardened Linux VMSS (not .NET). Rationale: terminating
  mTLS + HTTP/2 CONNECT at an internet boundary is exactly Envoy's well-exercised path;
  writing a custom .NET forward proxy would concentrate novel security-critical code on the
  most exposed component. The node's small config/telemetry sidecar may be .NET if convenient.

## Alternatives considered

1. Custom .NET (Kestrel/YARP-based) egress proxy — rejected for MVP (novel attack surface on
   the trust boundary); may be revisited post-MVP if Envoy operational fit is poor.
2. Blazor WebAssembly or separate SPA framework for the UI — rejected; Server keeps the token
   surface server-side and matches an internal-admin-tool profile.
3. Non-LTS .NET — rejected; LTS servicing matters more than feature velocity here.

## Security/privacy consequences

NuGet supply chain enters the threat model (SBOM, lockfiles, scanning — SR-012). Agent code
signing and Intune delivery satisfy the endpoint-signing requirement. No new data collection.

## Operational consequences

Single-stack maintainability for the operating organisation; Envoy is the one non-.NET operational skill required,
confined to an IaC-managed, rebuildable stamp.

## Approval

Stack direction: approved by owner. Component details: review with the Phase 0 package.
