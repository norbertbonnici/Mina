# Security policy

Mina is a controlled-egress platform whose value rests on a small set of security properties
(fail-closed browsing, no open proxy, no path into internal networks, authoritative telemetry
suppression). A weakness in any of them matters more than an ordinary bug.

## Reporting a vulnerability

Please do **not** open a public GitHub issue for a suspected vulnerability.

Use GitHub's private vulnerability reporting on this repository ("Report a vulnerability" under the
Security tab), or email the maintainer at the address in the repository profile with the subject
line `Mina security`. Include:

- the component (control plane, management UI, endpoint agent, egress node, infrastructure, docs);
- the property you believe is affected, ideally by reference to `docs/THREAT_MODEL.md` or a
  requirement in `docs/REQUIREMENTS.md`;
- reproduction steps or a proof of concept;
- whether you believe a deployed instance is at risk.

You will receive an acknowledgement within five working days. We aim to triage within two weeks
and will keep you informed. Please allow a reasonable disclosure window before publishing.

## Scope

In scope: anything in this repository, including Terraform, PowerShell packaging scripts, the
Envoy configuration, and documentation that would lead an operator into an insecure deployment.

Out of scope: Microsoft Azure, Entra ID, Intune, Edge, Envoy, Wazuh and SigNoz themselves (report
those to their vendors), and deployments operated by third parties.

## What counts as a vulnerability here

Beyond the usual (authentication bypass, injection, privilege escalation), the following are
treated as security findings for Mina specifically:

- research-browser traffic that can leave by any route other than the protected tunnel,
  including DNS, IPv6, WebRTC or proxy-fallback paths;
- the protected path failing **open** rather than closed;
- any way for an unauthenticated or non-approved client to forward traffic through an egress node;
- any reachable path from an egress node into a private network;
- URL or hostname telemetry recorded during an approved sensitive session, or a client-side
  control that suppresses telemetry without approval;
- gaps in audit-chain integrity, or events that should raise a Wazuh alert and do not;
- break-glass mechanisms exposed in source, packages or user-accessible configuration.

## Supported versions

Mina has no released versions yet. Fixes land on `main`. Deployers should track `main` and the
security review history in `docs/SECURITY_REVIEW_2026-09-01.md`.
