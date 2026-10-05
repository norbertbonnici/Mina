# management-ui

The management console for managers and platform administrators (FR-013): the approvals queue,
sessions, and a platform overview.

## Screens

- **Overview** — active sessions, how many are in sensitive mode, the approval backlog, and which
  approved regions are actually selectable (an approved region with no active stamp is deliberately
  not offered to analysts, AC-008).
- **Approvals** — the queue of suppression requests, with approve (granting a bounded window) and
  deny. Approver role only; the page is refused outright to anyone else, so a pending request and
  who raised it never reach them.
- **Sessions** — recent sessions with analyst, device, region, state and logging mode. The metadata
  shown here is the mandatory set that is retained even while URL telemetry is suppressed.

## Design notes

- **Static server rendering throughout.** An admin console gains nothing from a persistent Blazor
  circuit, and plain request/response keeps every screen simple to reason about and to test. Actions
  are ordinary form posts with antiforgery.
- **The UI calls the application services directly**, against the same database as the API, rather
  than over HTTP. Both are trusted server-side halves of the control plane, and the authorisation
  rules live in the application services — so the same rules bind whichever front door a request
  arrives through. A decision refused there (self-approval, for instance) is refused here too, and
  is reported back on the screen rather than swallowed.
- **Roles come from Entra**, via the same claims mapping the API uses.

## Running it locally

```bash
ASPNETCORE_ENVIRONMENT=Development dotnet run --project management-ui/src/Mina.ManagementUi
```

In Development the configured **development sign-in** signs every visitor in as an approver so the
screens can be reviewed without an Entra tenant. That is an authentication bypass, so it is refused
unless the host is in Development *and* `Mina:Ui:DevSignIn:Enabled` is explicitly true — asking for
it in any other environment is a startup failure, not a warning.

Standalone it uses an in-memory store private to the process, so it starts empty. To see it with
real data, run the demo harness instead: it hosts this UI against the same stores the control-plane
API is writing to, so you can raise a request as the analyst and approve it here.

```bash
MINA_ENVOY=/path/to/envoy dotnet run --project demo/Mina.Demo -c Release
```

## Not built yet

Audit views (the durable audit store is M3-3), region policy administration (regions are
configuration today), and the platform-admin screens. The `Mina.Admin` policy exists and is wired,
but nothing uses it yet.
