using Microsoft.EntityFrameworkCore;
using Mina.ControlPlane.Domain.Sessions;

namespace Mina.ControlPlane.Persistence;

/// <summary>
/// The control-plane database (ARCHITECTURE §3.2: Azure SQL, private endpoint, TDE at rest).
/// Holds the governance state — sessions now, approvals and audit as those milestones land.
/// Hostname telemetry lives in a separate schema and is deliberately not modelled here
/// (LOGGING_AND_PRIVACY §3: C3 is a distinct data class with its own access controls).
/// </summary>
public sealed class MinaDbContext(DbContextOptions<MinaDbContext> options) : DbContext(options)
{
    /// <summary>
    /// Shadow concurrency token. It is a shadow property so optimistic concurrency does not leak
    /// into the domain aggregate, and an <c>int</c> rather than SQL Server <c>rowversion</c> so the
    /// same behaviour holds on every provider (including the SQLite used by tests).
    /// </summary>
    internal const string VersionProperty = "Version";

    public DbSet<ResearchSession> Sessions => Set<ResearchSession>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        ArgumentNullException.ThrowIfNull(modelBuilder);
        modelBuilder.ApplyConfigurationsFromAssembly(typeof(MinaDbContext).Assembly);
    }

    public override Task<int> SaveChangesAsync(CancellationToken cancellationToken = default)
    {
        BumpConcurrencyTokens();
        return base.SaveChangesAsync(cancellationToken);
    }

    public override int SaveChanges()
    {
        BumpConcurrencyTokens();
        return base.SaveChanges();
    }

    /// <summary>
    /// Advances the concurrency token on every modified entity, so a stale writer's UPDATE matches
    /// no rows and surfaces as a concurrency conflict. This is what stops a lost update from
    /// silently resurrecting a revoked session (THREAT_MODEL: session revocation must stick).
    /// </summary>
    private void BumpConcurrencyTokens()
    {
        foreach (var entry in ChangeTracker.Entries<ResearchSession>())
        {
            if (entry.State == EntityState.Modified)
            {
                var version = entry.Property<int>(VersionProperty);
                version.CurrentValue = version.OriginalValue + 1;
            }
        }
    }
}
