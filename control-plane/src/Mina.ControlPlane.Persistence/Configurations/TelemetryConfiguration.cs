using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using Mina.ControlPlane.Domain.Telemetry;

namespace Mina.ControlPlane.Persistence.Configurations;

/// <summary>
/// Hostname telemetry (data class C3). Deliberately in its own <c>telemetry</c> schema, separate
/// from the governance tables: reading session and approval audit must not implicitly grant reading
/// analysts' browsing destinations, and the two have different retention (LOGGING_AND_PRIVACY §3,
/// §7). The grants that enforce that separation are an operational step on the database itself.
/// </summary>
internal sealed class HostnameObservationConfiguration : IEntityTypeConfiguration<HostnameObservation>
{
    public void Configure(EntityTypeBuilder<HostnameObservation> builder)
    {
        builder.ToTable("Hostnames", TelemetrySchema.Name);
        builder.HasKey(o => o.Id);
        builder.Property(o => o.Id).ValueGeneratedNever();

        builder.Property(o => o.SessionId).IsRequired();
        builder.Property(o => o.Region).IsRequired().HasMaxLength(64);
        builder.Property(o => o.OccurredAt).IsRequired();
        builder.Property(o => o.Hostname).IsRequired().HasMaxLength(HostnameObservation.MaxHostnameLength);
        builder.Property(o => o.Port).IsRequired();
        builder.Property(o => o.BytesUp).IsRequired();
        builder.Property(o => o.BytesDown).IsRequired();
        builder.Property(o => o.DurationMs).IsRequired();

        // Retention sweeps and "what did this session reach" both key on these.
        builder.HasIndex(o => new { o.SessionId, o.OccurredAt });
        builder.HasIndex(o => o.OccurredAt);
    }
}

internal sealed class SuppressedTrafficSummaryConfiguration : IEntityTypeConfiguration<SuppressedTrafficSummary>
{
    public void Configure(EntityTypeBuilder<SuppressedTrafficSummary> builder)
    {
        builder.ToTable("SuppressedTraffic", TelemetrySchema.Name);
        builder.HasKey(s => s.Id);
        builder.Property(s => s.Id).ValueGeneratedNever();

        builder.Property(s => s.SessionId).IsRequired();
        builder.Property(s => s.Region).IsRequired().HasMaxLength(64);
        builder.Property(s => s.IntervalStart).IsRequired();
        builder.Property(s => s.ConnectionCount).IsRequired();
        builder.Property(s => s.BytesTotal).IsRequired();

        builder.HasIndex(s => new { s.SessionId, s.IntervalStart });
    }
}

/// <summary>The schema telemetry tables live in.</summary>
internal static class TelemetrySchema
{
    public const string Name = "telemetry";
}
