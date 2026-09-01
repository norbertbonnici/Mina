using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Mina.ControlPlane.Application.Audit;
using Mina.ControlPlane.Application.SensitiveSessions;
using Mina.ControlPlane.Application.Sessions;

namespace Mina.ControlPlane.Application.Configuration;

/// <summary>
/// Startup validation for the options that govern security behaviour.
/// </summary>
/// <remarks>
/// These values were bound with a bare <c>Configure&lt;T&gt;</c>, so a bad one was discovered at the
/// point of use: a suppression window of a day or more reached the database and failed there, and a
/// window of zero silently refused every request — disabling an approved governance workflow with no
/// error anywhere. A misconfigured host that starts is worse than one that does not, because the
/// failure then looks like a bug in the workflow rather than a typo in configuration.
///
/// Validators live in this project rather than in either host so the API and the management UI
/// cannot drift in what they consider a valid policy: both reference it, and both call
/// <see cref="ServiceCollectionExtensions.AddValidatedMinaOptions"/>.
/// </remarks>
public sealed class SensitiveSessionOptionsValidator : IValidateOptions<SensitiveSessionOptions>
{
    /// <summary>
    /// Ceiling on the suppression window. Not a number chosen here: <c>RequestedDuration</c> is a
    /// SQL Server <c>time</c> column, which cannot hold 24 hours, so this limit is already in force
    /// — it was simply enforced by the database instead of at startup. Raising it means changing
    /// the column type, which is a migration and an ADR, not a configuration change.
    /// </summary>
    public static readonly TimeSpan MaxSupportedDuration = TimeSpan.FromHours(24);

    public ValidateOptionsResult Validate(string? name, SensitiveSessionOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        var failures = new List<string>();

        if (options.MaxDuration <= TimeSpan.Zero)
        {
            failures.Add(
                $"Mina:SensitiveSession:MaxDuration is {options.MaxDuration}; it must be positive. "
                + "A non-positive maximum refuses every suppression request, disabling the approval "
                + "workflow silently.");
        }
        else if (options.MaxDuration >= MaxSupportedDuration)
        {
            failures.Add(
                $"Mina:SensitiveSession:MaxDuration is {options.MaxDuration}; it must be under "
                + $"{MaxSupportedDuration}. Requested durations are stored in a SQL Server 'time' "
                + "column, which cannot represent 24 hours, so a larger window would fail at the "
                + "database when an analyst used it.");
        }

        // The batch sizes are the reason this validator exists at all: both are passed straight to
        // a repository that refuses a limit below 1, so a zero — a very plausible reading of
        // "0 means unlimited" — throws on every sweep. The sweeper catches and retries, so the host
        // stays up and healthy while approvals silently stop expiring: exactly the shape of
        // misconfiguration this class was added to stop (AC-011).
        if (options.ExpirySweepBatchSize < 1)
        {
            failures.Add(
                $"Mina:SensitiveSession:ExpirySweepBatchSize is {options.ExpirySweepBatchSize}; it must "
                + "be at least 1. There is no 'unlimited' value: a non-positive batch stops the expiry "
                + "sweep entirely, and approvals would outlive their window with the host reporting healthy.");
        }

        if (options.ApproverQueuePageSize < 1)
        {
            failures.Add(
                $"Mina:SensitiveSession:ApproverQueuePageSize is {options.ApproverQueuePageSize}; it must "
                + "be at least 1, or the approver queue cannot be read at all.");
        }

        RequireRole(failures, options.ApproverRole, "Mina:SensitiveSession:ApproverRole");
        RequireRole(failures, options.AnalystRole, "Mina:SensitiveSession:AnalystRole");

        if (failures.Count == 0
            && string.Equals(options.ApproverRole, options.AnalystRole, StringComparison.Ordinal))
        {
            // FR-010: approval requires someone other than the requester. One role for both would
            // not defeat that on its own — the aggregate still refuses self-approval — but it makes
            // every analyst an approver of their colleagues' requests, which is not the control the
            // separation of roles was built to give.
            failures.Add(
                "Mina:SensitiveSession:ApproverRole and AnalystRole are the same role "
                + $"('{options.ApproverRole}'). Suppression approval must be a distinct role.");
        }

        return failures.Count == 0
            ? ValidateOptionsResult.Success
            : ValidateOptionsResult.Fail(failures);
    }

    private static void RequireRole(List<string> failures, string value, string key)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            failures.Add($"{key} must name an app role; an empty role name authorises no one.");
        }
    }
}

/// <summary>Validates the session lease policy.</summary>
public sealed class SessionServiceOptionsValidator : IValidateOptions<SessionServiceOptions>
{
    /// <summary>
    /// Ceiling on a session lease. ARCHITECTURE §4 puts the lease at roughly 60 minutes, and the
    /// value is also the lifetime of the session client certificate, so a mistyped configuration
    /// does not merely keep a row alive — it mints a long-lived credential for the egress tunnel.
    /// The ceiling exists to make that typo a startup failure rather than a year-long certificate.
    /// </summary>
    public static readonly TimeSpan MaxLeaseTtl = TimeSpan.FromHours(24);

    public ValidateOptionsResult Validate(string? name, SessionServiceOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        var failures = new List<string>();

        if (options.LeaseTtl <= TimeSpan.Zero)
        {
            failures.Add(
                $"Mina:Session:LeaseTtl is {options.LeaseTtl}; it must be positive. A non-positive "
                + "lease issues certificates that have already expired.");
        }
        else if (options.LeaseTtl > MaxLeaseTtl)
        {
            failures.Add(
                $"Mina:Session:LeaseTtl is {options.LeaseTtl}, over the {MaxLeaseTtl} ceiling. The "
                + "lease is also the session certificate's lifetime (ARCHITECTURE §4 sets it at "
                + "about 60 minutes); a longer one weakens revocation, which works by declining to "
                + "renew.");
        }

        if (string.IsNullOrWhiteSpace(options.AnalystRole))
        {
            failures.Add("Mina:Session:AnalystRole must name an app role; an empty role authorises no one.");
        }

        // Whitespace here is worse than either extreme. The gate is switched on by "is this
        // non-blank", but matched by an exact ordinal comparison — so " " disables the compliance
        // check silently, and " c1" arms a gate no token can ever satisfy while the challenge names
        // an id that does not exist in the tenant. Neither is distinguishable from working.
        if (options.RequiredAuthContextId.Length != options.RequiredAuthContextId.Trim().Length)
        {
            failures.Add(
                $"Mina:Session:RequiredAuthContextId ('{options.RequiredAuthContextId}') has leading or "
                + "trailing whitespace. Leave it empty to disable the Conditional Access "
                + "authentication-context check, or give the exact context id; a padded value arms a "
                + "gate no token can satisfy.");
        }

        return failures.Count == 0
            ? ValidateOptionsResult.Success
            : ValidateOptionsResult.Fail(failures);
    }
}

/// <summary>Validates the audit chain's own configuration.</summary>
public sealed class AuditOptionsValidator : IValidateOptions<AuditOptions>
{
    public ValidateOptionsResult Validate(string? name, AuditOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        var failures = new List<string>();

        if (string.IsNullOrWhiteSpace(options.Environment))
        {
            // Stamped on every event and used to scope export anchors; blank would merge one
            // environment's anchors into another's high-water mark.
            failures.Add($"{AuditOptions.Section}:Environment must be set (for example 'dev' or 'prod').");
        }

        if (options.MaxAppendAttempts < 1)
        {
            failures.Add(
                $"{AuditOptions.Section}:MaxAppendAttempts is {options.MaxAppendAttempts}; it must be "
                + "at least 1, or no audit event can ever be written and every governance action fails.");
        }

        return failures.Count == 0
            ? ValidateOptionsResult.Success
            : ValidateOptionsResult.Fail(failures);
    }
}

/// <summary>Binds and validates the shared control-plane options for any host.</summary>
public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Binds the options both hosts share, validating them at startup. <c>ValidateOnStart</c> is the
    /// point: without it a validator only runs when something first resolves the options, which for
    /// a rarely used path can be long after deployment.
    /// </summary>
    public static IServiceCollection AddValidatedMinaOptions(
        this IServiceCollection services, IConfiguration configuration)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configuration);

        services.AddOptions<SensitiveSessionOptions>()
            .Bind(configuration.GetSection(SensitiveSessionOptions.Section))
            .ValidateOnStart();
        services.AddSingleton<IValidateOptions<SensitiveSessionOptions>, SensitiveSessionOptionsValidator>();

        services.AddOptions<SessionServiceOptions>()
            .Bind(configuration.GetSection(SessionServiceOptions.Section))
            .ValidateOnStart();
        services.AddSingleton<IValidateOptions<SessionServiceOptions>, SessionServiceOptionsValidator>();

        services.AddOptions<AuditOptions>()
            .Bind(configuration.GetSection(AuditOptions.Section))
            .ValidateOnStart();
        services.AddSingleton<IValidateOptions<AuditOptions>, AuditOptionsValidator>();

        return services;
    }
}
