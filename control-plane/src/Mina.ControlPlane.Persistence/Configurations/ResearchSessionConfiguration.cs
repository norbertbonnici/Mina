using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using Mina.ControlPlane.Domain.Sessions;

namespace Mina.ControlPlane.Persistence.Configurations;

/// <summary>
/// Maps <see cref="ResearchSession"/> without the domain knowing about EF Core. EF materialises the
/// aggregate through its private constructor (parameter names match property names) and writes the
/// remaining state through backing fields, so the aggregate keeps its invariants — there are no
/// public setters for persistence to abuse.
/// </summary>
internal sealed class ResearchSessionConfiguration : IEntityTypeConfiguration<ResearchSession>
{
    public void Configure(EntityTypeBuilder<ResearchSession> builder)
    {
        builder.ToTable("Sessions");
        builder.HasKey(s => s.Id);
        builder.Property(s => s.Id).ValueGeneratedNever(); // ids come from the domain, not the database

        builder.Property(s => s.UserObjectId).IsRequired().HasMaxLength(64);
        builder.Property(s => s.UserPrincipalName).IsRequired().HasMaxLength(256);
        builder.Property(s => s.DeviceId).HasMaxLength(64);
        builder.Property(s => s.Region).IsRequired().HasMaxLength(64);
        builder.Property(s => s.CertificateSerialNumber).IsRequired().HasMaxLength(64);
        builder.Property(s => s.RevokedBy).HasMaxLength(256);

        // Enums as strings: audit records stay legible in the database, and adding a member cannot
        // silently re-map existing rows the way ordinal storage can.
        builder.Property(s => s.State).IsRequired().HasConversion<string>().HasMaxLength(16);
        builder.Property(s => s.Mode).IsRequired().HasConversion<string>().HasMaxLength(16);
        builder.Property(s => s.EndReason).HasConversion<string>().HasMaxLength(16);

        builder.Property(s => s.CreatedAt).IsRequired();
        builder.Property(s => s.LeaseExpiresAt).IsRequired();

        builder.Property<int>(MinaDbContext.VersionProperty).IsConcurrencyToken().HasDefaultValue(0);

        // Supports "this analyst's sessions" in the management UI (M3-2).
        builder.HasIndex(s => s.UserObjectId);

        // Supports the expiry sweeper: active sessions whose lease has lapsed (FR-011/AC-011).
        builder.HasIndex(s => new { s.State, s.LeaseExpiresAt });
    }
}
