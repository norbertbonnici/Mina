# Contributing to Mina

Thank you for your interest. Mina is a security product: a change that is correct in isolation can
still weaken a property the whole system depends on. Please read this page before opening a pull
request.

## Before you start

1. Read the authoritative documents, in this order: `docs/REQUIREMENTS.md`, `docs/ARCHITECTURE.md`,
   `docs/THREAT_MODEL.md`, `docs/LOGGING_AND_PRIVACY.md`, `docs/ACCEPTANCE_CRITERIA.md`, and the
   ADRs in `docs/adr/`. `CLAUDE.md` is the project's working rules and applies to human and
   AI-assisted contributions alike.
2. Open an issue first for anything beyond a small fix, so the design can be discussed before code
   is written. Architectural changes need an ADR (`docs/adr/0000-adr-template.md`).
3. If code and documentation disagree, raise the conflict in the issue. Do not silently
   reinterpret a security requirement to make a test pass.

## Changes that need explicit maintainer agreement

These are listed in `CLAUDE.md` under "Decisions you MUST NOT make silently". Pull requests that
make any of them without a linked, accepted ADR will not be merged:

- introducing TLS interception or HTTPS decryption;
- adding any route from egress nodes into internal networks;
- weakening Conditional Access or device-compliance requirements;
- creating permanent logging exemptions, or materially increasing data collection;
- adding third-party SaaS dependencies;
- changing the approved region or public-IP strategy.

## Development setup

- .NET SDK pinned in `global.json`. `dotnet restore Mina.slnx --locked-mode` must succeed; lock
  files are tracked and CI fails on drift.
- Terraform for `infra/terraform`. Provider lock files are tracked.
- Envoy is needed for the transport interop tests and the demo (`demo/README.md`).
- Windows 11 is needed for the endpoint-agent tests marked as Windows-only; CI runs them on a
  Windows runner.

```bash
dotnet build Mina.slnx -c Release
dotnet test Mina.slnx -c Release
```

## Pull request expectations

- One concern per pull request, with a description that states which requirement, acceptance
  criterion or threat it serves (for example `FR-006`, `AC-014`, threat `B4`).
- Tests for behaviour you add or change: unit, integration, security or end-to-end as
  appropriate. Security-relevant fixes should include a test that fails without the fix.
- Update `docs/` and the relevant ADR when the design changes. `docs/BACKLOG.md` tracks milestone
  status.
- Never commit credentials, tenant identifiers, real hostnames, certificates or private keys.
  Use the `*.example` files and environment variables the repository already provides.
  `.gitignore` lists the files that must stay local.
- Commit messages follow the existing style: `type(scope): summary`, for example
  `feat(m2-6): ...` or `docs(adr): ...`.

## Reporting security issues

Do not open a public issue for a vulnerability. See `SECURITY.md`.

## Licence

By contributing you agree that your contributions are licensed under the Apache License 2.0, as
stated in `LICENSE` section 5. No contributor licence agreement is required.
