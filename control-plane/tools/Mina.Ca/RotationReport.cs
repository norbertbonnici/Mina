using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Mina.ControlPlane.Application.Audit;
using Mina.ControlPlane.Domain.Audit;
using Mina.ControlPlane.Persistence;
using Mina.ControlPlane.Pki;

namespace Mina.Ca;

/// <summary>
/// Reports a <see cref="CaRotationStatus"/> as a <c>ca_rotation_status</c> audit event (M4-2,
/// EVENT_SCHEMAS.md), so the existing Wazuh delivery pipeline -- already running inside the
/// deployed control-plane API, already tailed by a configured Wazuh agent -- carries this result
/// with no new delivery mechanism of its own.
/// </summary>
/// <remarks>
/// Deliberately goes through <see cref="AuditWriter"/> and the real hash-chained audit store
/// rather than appending a line to the Wazuh delivery file directly: the chain's tamper-evidence
/// property (EVENT_SCHEMAS §2, `IAuditEventStore`'s own doc comment) exists precisely so a written
/// event cannot be quietly altered or removed, and a rotation-check result reaching Wazuh but not
/// the audit trail would be the one path around that guarantee.
/// </remarks>
public static class RotationReport
{
    /// <summary>
    /// EVENT_SCHEMAS §3's own suggested severity mapping (high/critical page-worthy) applied to
    /// M4-2's three-way urgency: <see cref="RotationUrgency.Critical"/> maps to
    /// <see cref="AuditSeverity.Critical"/>, not merely High -- an unrotated CA past this threshold
    /// is a looming loss of the platform's whole session-issuance capability (M2-2c), the same
    /// order of consequence as the other events already at this severity (break-glass use,
    /// <c>sensitive_suppression_mismatch</c>).
    /// </summary>
    public static AuditSeverity ToSeverity(RotationUrgency urgency) => urgency switch
    {
        RotationUrgency.Healthy => AuditSeverity.Info,
        RotationUrgency.Warning => AuditSeverity.Warning,
        RotationUrgency.Critical => AuditSeverity.Critical,
        _ => throw new ArgumentOutOfRangeException(nameof(urgency), urgency, "Unknown rotation urgency."),
    };

    /// <summary>
    /// Builds the event to write. Pure and I/O-free so it is unit-testable without a database --
    /// the same split <see cref="CaRotationStatus.Classify"/> itself already uses.
    /// </summary>
    public static AuditEventDraft ToAuditDraft(CaRotationStatus status, Uri vaultUri) => new(
        EventType: "ca_rotation_status",
        Severity: ToSeverity(status.Urgency),
        Component: AuditComponent.ControlPlane,
        Data: new
        {
            urgency = status.Urgency.ToString(),
            daysRemaining = status.DaysRemaining,
            vault = vaultUri.ToString(),
        });

    /// <summary>
    /// Writes <paramref name="draft"/> to the real audit chain over <paramref name="connectionString"/>.
    /// Builds a minimal, short-lived service provider mirroring exactly how the control-plane API
    /// itself wires <see cref="AuditWriter"/> (`Program.cs`: <c>TimeProvider.System</c> singleton,
    /// <c>AuditWriter</c> scoped, <see cref="AuditOptions"/> bound to configuration) rather than a
    /// second, divergent construction path for the same write.
    /// </summary>
    public static async Task ReportAsync(
        AuditEventDraft draft, string connectionString, string environment, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(connectionString);
        ArgumentException.ThrowIfNullOrWhiteSpace(environment);

        var services = new ServiceCollection();
        services.AddMinaSqlPersistence(connectionString);
        services.AddSingleton(TimeProvider.System);
        services.Configure<AuditOptions>(o => o.Environment = environment);
        services.AddScoped<AuditWriter>();

        await using var provider = services.BuildServiceProvider();
        await using var scope = provider.CreateAsyncScope();
        var writer = scope.ServiceProvider.GetRequiredService<AuditWriter>();

        try
        {
            await writer.WriteAsync(draft, cancellationToken).ConfigureAwait(false);
        }
        catch (AuditWriteException ex)
        {
            // Rethrown as a type Program.cs's top-level catch already handles, so a reporting
            // failure surfaces the same way any other bad-input/operational failure here does
            // (a clear message and a non-zero exit) rather than an unhandled-exception crash.
            throw new InvalidOperationException($"Could not report the rotation-check result: {ex.Message}", ex);
        }
    }
}
