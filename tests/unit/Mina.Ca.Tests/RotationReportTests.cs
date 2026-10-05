using System.Text.Json;
using Mina.ControlPlane.Domain.Audit;
using Mina.ControlPlane.Pki;

namespace Mina.Ca.Tests;

/// <summary>
/// Covers only the pure half of <see cref="RotationReport"/> -- <see cref="RotationReport.ToSeverity"/>
/// and <see cref="RotationReport.ToAuditDraft"/> -- the same split this project already draws
/// between <see cref="CaRotationStatus.Classify"/> (unit-tested, I/O-free) and the orchestration
/// methods in <c>Program.cs</c> that call Key Vault (not unit-tested here, same as `bootstrap`/
/// `show`/the rest of `rotation-check` never have been). <see cref="RotationReport.ReportAsync"/>
/// needs a real or fake SQL Server and is exercised, if at all, at the integration level.
/// </summary>
public class RotationReportTests
{
    [Theory]
    [InlineData(RotationUrgency.Healthy, AuditSeverity.Info)]
    [InlineData(RotationUrgency.Warning, AuditSeverity.Warning)]
    [InlineData(RotationUrgency.Critical, AuditSeverity.Critical)]
    public void ToSeverity_maps_each_urgency_to_the_documented_severity(
        RotationUrgency urgency, AuditSeverity expected)
    {
        Assert.Equal(expected, RotationReport.ToSeverity(urgency));
    }

    [Fact]
    public void ToSeverity_rejects_an_undefined_urgency_rather_than_silently_defaulting()
    {
        // A severity mapping that silently fell through to a default for an unrecognised value
        // would misreport rather than fail loudly if RotationUrgency ever gains a fourth case.
        Assert.Throws<ArgumentOutOfRangeException>(() => RotationReport.ToSeverity((RotationUrgency)99));
    }

    [Fact]
    public void ToAuditDraft_sets_the_catalogued_event_type_and_component()
    {
        var status = new CaRotationStatus(RotationUrgency.Warning, DaysRemaining: 42);
        var draft = RotationReport.ToAuditDraft(status, new Uri("https://kv-mina-test.vault.azure.net/"));

        Assert.Equal("ca_rotation_status", draft.EventType);
        Assert.Equal(AuditComponent.ControlPlane, draft.Component);
        Assert.Equal(AuditSeverity.Warning, draft.Severity);
    }

    [Fact]
    public void ToAuditDraft_carries_urgency_days_remaining_and_vault_in_the_data_payload()
    {
        var status = new CaRotationStatus(RotationUrgency.Critical, DaysRemaining: 7);
        var draft = RotationReport.ToAuditDraft(status, new Uri("https://kv-mina-test.vault.azure.net/"));

        // Serialised the same way AuditWriter.WriteAsync itself serialises Data, so this proves
        // what actually reaches the audit chain, not just what the anonymous type happens to expose.
        using var document = JsonDocument.Parse(JsonSerializer.Serialize(draft.Data));
        var root = document.RootElement;

        Assert.Equal("Critical", root.GetProperty("urgency").GetString());
        Assert.Equal(7, root.GetProperty("daysRemaining").GetInt32());
        Assert.Equal("https://kv-mina-test.vault.azure.net/", root.GetProperty("vault").GetString());
    }

    [Fact]
    public void ToAuditDraft_leaves_user_device_and_session_unset()
    {
        // This is a system-originated periodic check, not attributable to a signed-in analyst --
        // the same shape as telemetry_retention_applied and role_assignment_observed
        // (EVENT_SCHEMAS.md), neither of which carries a user/device/session either.
        var status = new CaRotationStatus(RotationUrgency.Healthy, DaysRemaining: 400);
        var draft = RotationReport.ToAuditDraft(status, new Uri("https://kv-mina-test.vault.azure.net/"));

        Assert.Null(draft.UserObjectId);
        Assert.Null(draft.UserPrincipalName);
        Assert.Null(draft.DeviceId);
        Assert.Null(draft.SessionId);
        Assert.Null(draft.Region);
    }
}
