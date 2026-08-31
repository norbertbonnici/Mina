# Mina.ControlPlane.Persistence

EF Core persistence for the control-plane governance store (ARCHITECTURE §3.2: Azure SQL, private
endpoint, TDE at rest). Currently holds research sessions; approvals and the audit tables land with
M3.

Hostname telemetry is **not** stored here. It is a separate data class with its own access controls
(LOGGING_AND_PRIVACY §3, class C3) and gets its own schema, so a reader of governance data does not
implicitly get browsing destinations.

## Design notes

- **The domain has no EF dependency.** `ResearchSession` is mapped from this project via
  `IEntityTypeConfiguration`; EF materialises it through its private constructor and backing
  fields, so the aggregate keeps its invariants and exposes no setters for persistence to abuse.
- **Enums are stored as strings** (`Active`, `Revoked`, …) so audit rows are legible and adding an
  enum member cannot silently re-map existing rows the way ordinal storage can.
- **Optimistic concurrency** via a shadow `Version` column. It is a shadow property so the token
  does not leak into the domain, and an `int` rather than SQL Server `rowversion` so behaviour is
  identical on every provider (including the SQLite used in tests). A stale write raises
  `DbUpdateConcurrencyException` instead of overwriting — this is what stops a concurrent renewal
  from resurrecting a session an administrator just revoked.
- **`UpdateAsync` refuses detached instances.** A detached aggregate has lost the concurrency token
  it was loaded with (the token lives in the change tracker), so saving it would quietly turn a
  conflicting write into a lost update. Load via `FindAsync`, mutate, then update.

## Migrations

Generated with the EF tools; they are source-controlled and applied by the **deployment pipeline**,
never automatically at application startup — schema change stays a deliberate, reviewable step
(and production changes need explicit human approval per `CLAUDE.md`).

Add a migration after changing the model:

```bash
dotnet ef migrations add <Name> --project control-plane/src/Mina.ControlPlane.Persistence --context MinaDbContext
```

Produce the idempotent SQL script the pipeline applies:

```bash
dotnet ef migrations script --idempotent --project control-plane/src/Mina.ControlPlane.Persistence --context MinaDbContext --output migrate.sql
```

`MinaDbContextFactory` supplies a design-time context, so neither command needs a live database.

## Connection and authentication

The API uses this store when `ConnectionStrings:MinaDb` is set; otherwise it falls back to an
in-memory store and says so loudly at startup. Production connection strings use a managed identity
(`Authentication=Active Directory Default`) — no passwords in configuration (SR-005).

## Tests

`tests/integration/Mina.ControlPlane.Persistence.Tests` runs against SQLite in-memory: mapping
round-trip, lifecycle persistence, enum storage, the concurrency contract, and `SessionService`
driven end to end over the real repository. Provider-specific behaviour against Azure SQL is
verified once the dev environment exists.
