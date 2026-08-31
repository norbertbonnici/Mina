using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Storage.ValueConversion;
using Mina.ControlPlane.Domain.Audit;
using Mina.ControlPlane.Domain.SensitiveSessions;
using Mina.ControlPlane.Domain.Sessions;
using Mina.ControlPlane.Domain.Telemetry;

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

    public DbSet<SensitiveSessionRequest> SensitiveSessionRequests => Set<SensitiveSessionRequest>();

    public DbSet<AuditEvent> AuditEvents => Set<AuditEvent>();

    public DbSet<HostnameObservation> Hostnames => Set<HostnameObservation>();

    public DbSet<SuppressedTrafficSummary> SuppressedTraffic => Set<SuppressedTrafficSummary>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        ArgumentNullException.ThrowIfNull(modelBuilder);
        modelBuilder.ApplyConfigurationsFromAssembly(typeof(MinaDbContext).Assembly);
    }

    protected override void ConfigureConventions(ModelConfigurationBuilder configurationBuilder)
    {
        ArgumentNullException.ThrowIfNull(configurationBuilder);

        // Every timestamp in this model is UTC by construction (the control plane reads its clock
        // via TimeProvider.GetUtcNow), so storing the instant rather than an offset loses nothing.
        // It also keeps ordering and range predicates translatable on every provider — SQLite,
        // which the tests run against, cannot compare or ORDER BY datetimeoffset, so without this
        // the expiry and queue queries could not be exercised before production.
        configurationBuilder.Properties<DateTimeOffset>().HaveConversion<UtcDateTimeOffsetConverter>();
    }

    /// <summary>Stores a <see cref="DateTimeOffset"/> as its UTC instant and reads it back as UTC.</summary>
    internal sealed class UtcDateTimeOffsetConverter()
        : ValueConverter<DateTimeOffset, DateTime>(
            offset => offset.UtcDateTime,
            utc => new DateTimeOffset(DateTime.SpecifyKind(utc, DateTimeKind.Utc), TimeSpan.Zero));

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
    /// Advances the concurrency token on every modified entity that carries one, so a stale
    /// writer's UPDATE matches no rows and surfaces as a concurrency conflict. This is what stops a
    /// lost update from silently resurrecting a revoked session, or from overwriting an approval
    /// decision that was made concurrently.
    /// </summary>
    private void BumpConcurrencyTokens()
    {
        foreach (var entry in ChangeTracker.Entries())
        {
            if (entry.State != EntityState.Modified || entry.Metadata.FindProperty(VersionProperty) is null)
            {
                continue;
            }

            // Non-generic entry: the token comes back boxed.
            var version = entry.Property(VersionProperty);
            version.CurrentValue = (int)version.OriginalValue! + 1;
        }
    }
}
