using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using Mina.ControlPlane.Domain.Coordination;

namespace Mina.ControlPlane.Persistence.Configurations;

/// <summary>
/// Maps the background-work lease. One row per named piece of work; the primary key is what makes
/// two instances contend rather than both proceed.
/// </summary>
internal sealed class BackgroundLeaseConfiguration : IEntityTypeConfiguration<BackgroundLease>
{
    public void Configure(EntityTypeBuilder<BackgroundLease> builder)
    {
        builder.ToTable("BackgroundLeases");
        builder.HasKey(l => l.Name);

        builder.Property(l => l.Name).HasMaxLength(64);
        builder.Property(l => l.Owner).IsRequired().HasMaxLength(128);
        builder.Property(l => l.ExpiresAt).IsRequired();

        // The concurrency token is the whole mechanism: two instances that read the same lapsed
        // lease and both try to take it produce one winner and one DbUpdateConcurrencyException,
        // rather than two holders who each believe they are the only one.
        builder.Property<int>(MinaDbContext.VersionProperty).IsConcurrencyToken().HasDefaultValue(0);
    }
}
