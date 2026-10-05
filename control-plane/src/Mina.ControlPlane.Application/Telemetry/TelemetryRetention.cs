using Microsoft.Extensions.Options;
using Mina.ControlPlane.Domain.Telemetry;

namespace Mina.ControlPlane.Application.Telemetry;

/// <summary>
/// How long C3 hostname telemetry is kept (LOGGING_AND_PRIVACY §7, D-09).
/// </summary>
/// <remarks>
/// <para>
/// <see cref="HostnameRetentionDays"/> is deliberately nullable with no default. A retention period
/// is a data-protection commitment, and the operating value in LOGGING_AND_PRIVACY is a proposal
/// awaiting DPO ratification; shipping a default would mean this code destroys analyst browsing
/// records on a number nobody has approved, and destroying too early is as much a failure as
/// keeping too long. Unset therefore means "do not delete", the platform logs plainly at startup
/// that retention is not being enforced, and enabling it is a deployment decision with a name
/// against it.
/// </para>
/// <para>
/// Only C3 is enforced here. C1/C2 governance audit is append-only and hash-chained: deleting from
/// it breaks the chain that `/api/audit/verify` checks, so it needs its own ADR and its own
/// mechanism, and neither exists yet. C5 operational telemetry lives in SigNoz and is subject to
/// SigNoz's own retention, not this platform's.
/// </para>
/// </remarks>
public sealed class TelemetryRetentionOptions
{
    public const string SectionName = "Mina:Telemetry:Retention";

    /// <summary>Days to keep hostname telemetry. Null disables deletion entirely.</summary>
    public int? HostnameRetentionDays { get; set; }

    /// <summary>Rows removed per pass, so a first run against a large backlog cannot hold a long transaction.</summary>
    public int BatchSize { get; set; } = 500;

    /// <summary>How often the sweep runs.</summary>
    public TimeSpan Interval { get; set; } = TimeSpan.FromHours(6);

    public IEnumerable<string> Validate()
    {
        if (HostnameRetentionDays is <= 0)
        {
            yield return $"{SectionName}:HostnameRetentionDays must be greater than zero when set.";
        }

        if (BatchSize is <= 0 or > 10_000)
        {
            yield return $"{SectionName}:BatchSize must be between 1 and 10000.";
        }

        if (Interval < TimeSpan.FromMinutes(1))
        {
            yield return $"{SectionName}:Interval must be at least one minute.";
        }
    }
}

/// <summary>What one retention pass removed.</summary>
public readonly record struct RetentionOutcome(bool Enforced, int Hostnames, int SuppressedSummaries)
{
    public int Total => Hostnames + SuppressedSummaries;
}

/// <summary>
/// Applies C3 retention. Kept out of the hosted service so the deletion rules are testable without
/// a timer, and so the "disabled means delete nothing" case is asserted rather than assumed.
/// </summary>
public sealed class TelemetryRetentionService(
    ITelemetryRepository repository,
    ITelemetryAuditSink audit,
    IOptions<TelemetryRetentionOptions> options,
    TimeProvider clock)
{
    private readonly ITelemetryRepository _repository = repository ?? throw new ArgumentNullException(nameof(repository));
    private readonly ITelemetryAuditSink _audit = audit ?? throw new ArgumentNullException(nameof(audit));
    private readonly TelemetryRetentionOptions _options = (options ?? throw new ArgumentNullException(nameof(options))).Value;
    private readonly TimeProvider _clock = clock ?? throw new ArgumentNullException(nameof(clock));

    public async Task<RetentionOutcome> ApplyAsync(CancellationToken cancellationToken)
    {
        if (_options.HostnameRetentionDays is not { } days)
        {
            return new RetentionOutcome(Enforced: false, 0, 0);
        }

        var cutoff = _clock.GetUtcNow().AddDays(-days);

        // Batched, and drained rather than one batch per pass: a first run after this ships faces
        // however much has accumulated since the platform started, and leaving that to trickle out
        // one batch every six hours would mean the retention period is not actually met for weeks.
        var hostnames = await DrainAsync(
            (limit, ct) => _repository.DeleteHostnamesBeforeAsync(cutoff, limit, ct), cancellationToken)
            .ConfigureAwait(false);
        var summaries = await DrainAsync(
            (limit, ct) => _repository.DeleteSuppressedSummariesBeforeAsync(cutoff, limit, ct), cancellationToken)
            .ConfigureAwait(false);

        if (hostnames + summaries > 0)
        {
            // Recorded in the governance trail, not just the service log. Deletion of analyst data
            // is the one thing here that cannot be reconstructed afterwards, so the fact that it
            // happened, and how much went, has to survive in the append-only record.
            await _audit.RetentionAppliedAsync(cutoff, hostnames, summaries, cancellationToken).ConfigureAwait(false);
        }

        return new RetentionOutcome(Enforced: true, hostnames, summaries);
    }

    private async Task<int> DrainAsync(
        Func<int, CancellationToken, Task<int>> deleteBatch, CancellationToken cancellationToken)
    {
        var total = 0;
        while (!cancellationToken.IsCancellationRequested)
        {
            var removed = await deleteBatch(_options.BatchSize, cancellationToken).ConfigureAwait(false);
            total += removed;
            if (removed < _options.BatchSize)
            {
                break;
            }
        }

        return total;
    }
}
