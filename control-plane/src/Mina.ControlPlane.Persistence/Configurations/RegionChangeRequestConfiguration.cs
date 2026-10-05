using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using Mina.ControlPlane.Domain.Regions;

namespace Mina.ControlPlane.Persistence.Configurations;

/// <summary>Maps region change requests (ADR-0008 Option C) — the audited record of who asked for
/// what region change and why, and who later confirmed it was actually applied.</summary>
internal sealed class RegionChangeRequestConfiguration : IEntityTypeConfiguration<RegionChangeRequest>
{
    public void Configure(EntityTypeBuilder<RegionChangeRequest> builder)
    {
        builder.ToTable("RegionChangeRequests");
        builder.HasKey(r => r.Id);
        builder.Property(r => r.Id).ValueGeneratedNever();

        builder.Property(r => r.RequestedByObjectId).IsRequired().HasMaxLength(64);
        builder.Property(r => r.RequestedByUpn).IsRequired().HasMaxLength(256);
        builder.Property(r => r.Kind).IsRequired().HasConversion<string>().HasMaxLength(24);
        builder.Property(r => r.RegionName).IsRequired().HasMaxLength(RegionChangeRequest.MaxRegionNameLength);
        builder.Property(r => r.Justification).IsRequired().HasMaxLength(RegionChangeRequest.MaxJustificationLength);
        builder.Property(r => r.RequestedAt).IsRequired();

        builder.Property(r => r.Status).IsRequired().HasConversion<string>().HasMaxLength(16);
        builder.Property(r => r.ResolvedByObjectId).HasMaxLength(64);
        builder.Property(r => r.ResolvedByUpn).HasMaxLength(256);
        builder.Property(r => r.ResolutionNote).HasMaxLength(1024);

        builder.Property<int>(MinaDbContext.VersionProperty).IsConcurrencyToken().HasDefaultValue(0);

        // The pending queue: oldest first.
        builder.HasIndex(r => new { r.Status, r.RequestedAt });

        // Recently-resolved history.
        builder.HasIndex(r => new { r.Status, r.ResolvedAt });
    }
}
