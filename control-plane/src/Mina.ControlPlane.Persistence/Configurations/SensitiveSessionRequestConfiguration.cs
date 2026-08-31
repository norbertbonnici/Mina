using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using Mina.ControlPlane.Domain.SensitiveSessions;

namespace Mina.ControlPlane.Persistence.Configurations;

/// <summary>
/// Maps the sensitive-session approval record. These rows are the audit trail for suppression:
/// who asked, under what reference, who decided, when, and until when. They are mandatory even
/// when URL telemetry is suppressed (ADR-0003), so nothing here is optional on a whim.
/// </summary>
internal sealed class SensitiveSessionRequestConfiguration : IEntityTypeConfiguration<SensitiveSessionRequest>
{
    public void Configure(EntityTypeBuilder<SensitiveSessionRequest> builder)
    {
        builder.ToTable("SensitiveSessionRequests");
        builder.HasKey(r => r.Id);
        builder.Property(r => r.Id).ValueGeneratedNever();

        builder.Property(r => r.SessionId).IsRequired();
        builder.Property(r => r.RequesterObjectId).IsRequired().HasMaxLength(64);
        builder.Property(r => r.RequesterUpn).IsRequired().HasMaxLength(256);
        builder.Property(r => r.JustificationReference).IsRequired().HasMaxLength(128);
        builder.Property(r => r.ApproverObjectId).HasMaxLength(64);
        builder.Property(r => r.ApproverUpn).HasMaxLength(256);

        builder.Property(r => r.State).IsRequired().HasConversion<string>().HasMaxLength(24);
        builder.Property(r => r.EndReason).HasConversion<string>().HasMaxLength(24);

        builder.Property(r => r.RequestedDuration).IsRequired();
        builder.Property(r => r.RequestedAt).IsRequired();

        builder.Property<int>(MinaDbContext.VersionProperty).IsConcurrencyToken().HasDefaultValue(0);

        // The approver queue: pending requests, oldest first.
        builder.HasIndex(r => new { r.State, r.RequestedAt });

        // The expiry sweeper: anything still open past its window (AC-011).
        builder.HasIndex(r => new { r.State, r.ExpiresAt });

        builder.HasIndex(r => r.SessionId);
    }
}
