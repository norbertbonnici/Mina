using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using Mina.ControlPlane.Domain.Audit;

namespace Mina.ControlPlane.Persistence.Configurations;

/// <summary>
/// The governance audit trail (data class C1). It sits in its own <c>audit</c> schema so the
/// database can grant the control plane INSERT and SELECT and nothing else: rewriting history then
/// requires going around the application, and the hash chain makes that detectable.
/// </summary>
internal sealed class AuditEventConfiguration : IEntityTypeConfiguration<AuditEvent>
{
    public void Configure(EntityTypeBuilder<AuditEvent> builder)
    {
        builder.ToTable("Events", AuditSchema.Name);
        builder.HasKey(e => e.Id);
        builder.Property(e => e.Id).ValueGeneratedNever();

        // Unique so two writers racing for the same position cannot both succeed — one fails and
        // retries against the new tip rather than forking the chain.
        builder.HasIndex(e => e.Sequence).IsUnique();

        builder.Property(e => e.Sequence).IsRequired();
        builder.Property(e => e.EventType).IsRequired().HasMaxLength(64);
        builder.Property(e => e.Severity).IsRequired().HasConversion<string>().HasMaxLength(16);
        builder.Property(e => e.Component).IsRequired().HasConversion<string>().HasMaxLength(24);
        builder.Property(e => e.OccurredAt).IsRequired();
        builder.Property(e => e.Environment).IsRequired().HasMaxLength(16);
        builder.Property(e => e.Region).HasMaxLength(64);
        builder.Property(e => e.UserObjectId).HasMaxLength(64);
        builder.Property(e => e.UserPrincipalName).HasMaxLength(256);
        builder.Property(e => e.DeviceId).HasMaxLength(64);
        builder.Property(e => e.Data).IsRequired().HasMaxLength(4000);
        builder.Property(e => e.PreviousHash).IsRequired().HasMaxLength(64);
        builder.Property(e => e.Hash).IsRequired().HasMaxLength(64);

        builder.HasIndex(e => e.OccurredAt);
        builder.HasIndex(e => e.SessionId);
        builder.HasIndex(e => e.EventType);
    }
}

/// <summary>The schema audit tables live in.</summary>
internal static class AuditSchema
{
    public const string Name = "audit";
}
