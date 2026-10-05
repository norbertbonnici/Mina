using Microsoft.Extensions.Options;
using Mina.ControlPlane.Application.Sessions;
using Mina.ControlPlane.Domain.Sessions;
using Mina.ControlPlane.Domain.Telemetry;

namespace Mina.ControlPlane.Application.Telemetry;

/// <summary>
/// Defines "outside office hours" for the browsing-data review flag (M3-8). Deliberately unset by
/// default, the same posture as <see cref="TelemetryRetentionOptions.HostnameRetentionDays"/>: an
/// off-hours flag is a judgement about an analyst's activity, and shipping one nobody chose would
/// mean the platform started passing that judgement on a definition no owner had approved. Unset
/// means every connection is unflagged, not that every connection is off-hours.
/// </summary>
public sealed class OfficeHoursOptions
{
    public const string Section = "Mina:ManagementUi:OfficeHours";

    /// <summary>IANA time zone id, e.g. <c>Europe/Malta</c>. A connection's flag depends on the wall
    /// clock this zone reads at the instant it occurred, not on UTC or the viewer's own zone.</summary>
    public string? Timezone { get; set; }

    /// <summary>Days a connection is in-hours on, e.g. Monday-Friday. Empty means unconfigured.</summary>
    public IList<DayOfWeek> Days { get; init; } = [];

    /// <summary>Start of the in-hours window, local to <see cref="Timezone"/>.</summary>
    public TimeOnly? StartLocal { get; set; }

    /// <summary>End of the in-hours window, local to <see cref="Timezone"/>, exclusive.</summary>
    public TimeOnly? EndLocal { get; set; }

    /// <summary>
    /// All four fields are required together: a window with no days, or days with no window, cannot
    /// answer "is this outside office hours" at all, so partial configuration is treated the same as
    /// no configuration rather than guessed at.
    /// </summary>
    public bool IsConfigured =>
        !string.IsNullOrWhiteSpace(Timezone) && Days.Count > 0 && StartLocal is not null && EndLocal is not null;

    public IEnumerable<string> Validate()
    {
        // Partial configuration is the failure mode worth catching loudly: all-unset is the
        // supported "disabled" state, but three of four fields set and one forgotten would silently
        // fall back to disabled too, which reads as "the flag isn't working" rather than as the
        // startup-time typo it actually is.
        var fieldsSet = new[]
        {
            !string.IsNullOrWhiteSpace(Timezone), Days.Count > 0, StartLocal is not null, EndLocal is not null,
        }.Count(set => set);

        if (fieldsSet is > 0 and < 4)
        {
            yield return $"{Section} is partially configured (Timezone, Days, StartLocal, EndLocal must all be " +
                "set together, or all left unset to disable off-hours flagging).";
            yield break;
        }

        if (!IsConfigured)
        {
            yield break;
        }

        if (TimeZoneInfo.TryFindSystemTimeZoneById(Timezone!, out _) == false)
        {
            yield return $"{Section}:Timezone '{Timezone}' is not a recognised IANA/Windows time zone id.";
        }

        if (StartLocal >= EndLocal)
        {
            yield return $"{Section}:StartLocal ({StartLocal}) must be before EndLocal ({EndLocal}). An " +
                "overnight-spanning window (e.g. 22:00-06:00) is not supported in this version.";
        }
    }

    /// <summary>
    /// Whether <paramref name="occurredAt"/> falls outside the configured window. Always false when
    /// unconfigured — flagging stays inert, not fail-open into flagging everything.
    /// </summary>
    public bool IsOutsideOfficeHours(DateTimeOffset occurredAt)
    {
        if (!IsConfigured)
        {
            return false;
        }

        var zone = TimeZoneInfo.FindSystemTimeZoneById(Timezone!);
        var local = TimeZoneInfo.ConvertTime(occurredAt, zone);
        if (!Days.Contains(local.DayOfWeek))
        {
            return true;
        }

        var timeOfDay = TimeOnly.FromDateTime(local.DateTime);
        return timeOfDay < StartLocal!.Value || timeOfDay >= EndLocal!.Value;
    }
}

/// <summary>Raised when a browsing-data query is shaped in a way the platform refuses to run.</summary>
public sealed class BrowsingDataQueryException(string message) : Exception(message);

/// <summary>One hostname connection, with its off-hours flag already resolved.</summary>
public sealed record HostnameConnectionView(
    DateTimeOffset OccurredAt, string Hostname, int Port, long BytesUp, long BytesDown, int DurationMs, bool IsOffHours);

/// <summary>One interval of a suppressed session's traffic — counts only, no destinations.</summary>
public sealed record SuppressedIntervalView(DateTimeOffset IntervalStart, int ConnectionCount, long BytesTotal, bool IsOffHours);

/// <summary>
/// One session's browsing data. <see cref="Hostnames"/> is always empty for a <c>Sensitive</c>
/// session — the view carries <see cref="SuppressedIntervals"/> instead, because the destinations
/// were never recorded to withhold in the first place (LOGGING_AND_PRIVACY §4).
/// </summary>
public sealed record SessionBrowsingView(
    Guid SessionId,
    string UserObjectId,
    string UserPrincipalName,
    string? DeviceId,
    string Region,
    SessionMode Mode,
    DateTimeOffset CreatedAt,
    DateTimeOffset? EndedAt,
    IReadOnlyList<HostnameConnectionView> Hostnames,
    IReadOnlyList<SuppressedIntervalView> SuppressedIntervals)
{
    public bool HasOffHoursActivity => Hostnames.Any(h => h.IsOffHours) || SuppressedIntervals.Any(s => s.IsOffHours);
}

/// <summary>
/// A browsing-data review request. <paramref name="AnalystUserObjectId"/> null means every analyst —
/// see <see cref="BrowsingDataReviewService.MaxUnscopedRangeDays"/> for what that allows.
/// </summary>
public sealed record BrowsingDataQuery(
    string? AnalystUserObjectId, DateTimeOffset From, DateTimeOffset To, bool OffHoursOnly = false);

public sealed record BrowsingDataResult(
    IReadOnlyList<SessionBrowsingView> Sessions, int ConnectionsTotal, int OffHoursFlaggedCount, int SensitiveSessionCount);

/// <summary>
/// The read path behind the browsing-data review view (M3-8, FR-013, threat N10). Resolves sessions
/// for the requested scope, fetches their telemetry in two batched calls rather than one call per
/// session, computes off-hours flags at read time from the current <see cref="OfficeHoursOptions"/>
/// (so a later policy correction applies retroactively rather than needing a backfill), and writes
/// exactly one <c>telemetry_viewed</c> audit event per query — always, including when the result is
/// empty, because an empty result is still a fact about what was looked at.
/// </summary>
public sealed class BrowsingDataReviewService(
    ISessionQueries sessionQueries,
    ITelemetryRepository telemetry,
    ITelemetryAuditSink audit,
    IOptions<OfficeHoursOptions> officeHours)
{
    /// <summary>
    /// A query naming no analyst must stay inside this many days. Without it, one query could pull
    /// every analyst's entire browsing history at once — technically permitted by RBAC alone, but
    /// exactly the unsupervised-bulk-read threat N10 exists to rule out. A single-analyst deep-dive
    /// carries no such limit: naming one analyst is itself the scoping this guards against losing.
    /// </summary>
    public const int MaxUnscopedRangeDays = 90;

    private readonly ISessionQueries _sessionQueries = sessionQueries ?? throw new ArgumentNullException(nameof(sessionQueries));
    private readonly ITelemetryRepository _telemetry = telemetry ?? throw new ArgumentNullException(nameof(telemetry));
    private readonly ITelemetryAuditSink _audit = audit ?? throw new ArgumentNullException(nameof(audit));
    private readonly OfficeHoursOptions _officeHours = (officeHours ?? throw new ArgumentNullException(nameof(officeHours))).Value;

    public async Task<BrowsingDataResult> ReviewAsync(
        SessionPrincipal viewer, BrowsingDataQuery query, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(viewer);
        ArgumentNullException.ThrowIfNull(query);
        Validate(query);

        var sessions = string.IsNullOrWhiteSpace(query.AnalystUserObjectId)
            ? await _sessionQueries.ListInRangeAsync(query.From, query.To, cancellationToken).ConfigureAwait(false)
            : await _sessionQueries.ListForAnalystAsync(
                query.AnalystUserObjectId, query.From, query.To, cancellationToken).ConfigureAwait(false);

        // Partitioned by mode *before* anything is read: a Sensitive session's id is never handed to
        // the hostname query at all, so its destinations cannot leave storage on this path even if
        // a defect upstream had written some (ingest should have reduced them to counts). The
        // suppression is enforced at the repository call, not by discarding rows after the fact --
        // BrowsingDataReviewServiceTests asserts this against the call, not just the view model.
        var normalIds = sessions.Where(s => s.Mode != SessionMode.Sensitive).Select(s => s.Id).ToArray();
        var sensitiveIds = sessions.Where(s => s.Mode == SessionMode.Sensitive).Select(s => s.Id).ToArray();

        // Two batched reads regardless of session count, not one call per session: the point of
        // batching is to keep the round-trip count flat as a reviewer's date range grows.
        var hostnamesBySession = (await _telemetry
                .ListForSessionsAsync(normalIds, cancellationToken).ConfigureAwait(false))
            .GroupBy(o => o.SessionId)
            .ToDictionary(g => g.Key, g => (IReadOnlyList<HostnameObservation>)[.. g]);
        var suppressedBySession = (await _telemetry
                .ListSuppressedForSessionsAsync(sensitiveIds, cancellationToken).ConfigureAwait(false))
            .GroupBy(s => s.SessionId)
            .ToDictionary(g => g.Key, g => (IReadOnlyList<SuppressedTrafficSummary>)[.. g]);

        var views = new List<SessionBrowsingView>();
        var connectionsTotal = 0;
        var offHoursCount = 0;
        var sensitiveCount = 0;

        foreach (var session in sessions)
        {
            SessionBrowsingView view;
            if (session.Mode == SessionMode.Sensitive)
            {
                // hostnamesBySession cannot contain this session: its id was excluded from the
                // hostname query above. This branch only ever renders the aggregate.
                var suppressedViews = suppressedBySession.GetValueOrDefault(session.Id, [])
                    .Select(s => new SuppressedIntervalView(
                        s.IntervalStart, s.ConnectionCount, s.BytesTotal, _officeHours.IsOutsideOfficeHours(s.IntervalStart)))
                    .ToList();

                view = new SessionBrowsingView(
                    session.Id, session.UserObjectId, session.UserPrincipalName, session.DeviceId, session.Region,
                    session.Mode, session.CreatedAt, session.EndedAt, [], suppressedViews);

                sensitiveCount++;
                connectionsTotal += suppressedViews.Sum(s => s.ConnectionCount);
                offHoursCount += suppressedViews.Count(s => s.IsOffHours);
            }
            else
            {
                var hostnameViews = hostnamesBySession.GetValueOrDefault(session.Id, [])
                    .Select(h => new HostnameConnectionView(
                        h.OccurredAt, h.Hostname, h.Port, h.BytesUp, h.BytesDown, h.DurationMs,
                        _officeHours.IsOutsideOfficeHours(h.OccurredAt)))
                    .ToList();

                view = new SessionBrowsingView(
                    session.Id, session.UserObjectId, session.UserPrincipalName, session.DeviceId, session.Region,
                    session.Mode, session.CreatedAt, session.EndedAt, hostnameViews, []);

                connectionsTotal += hostnameViews.Count;
                offHoursCount += hostnameViews.Count(h => h.IsOffHours);
            }

            if (!query.OffHoursOnly || view.HasOffHoursActivity)
            {
                views.Add(view);
            }
        }

        // Written server-side, unconditionally, after the read completes and before returning it —
        // never left to whichever screen or endpoint called this service, so there is exactly one
        // place C3 access can be audited from and no way to reach the data around it (threat N10).
        var targetAnalystUpn = string.IsNullOrWhiteSpace(query.AnalystUserObjectId)
            ? null
            : sessions.Select(s => s.UserPrincipalName).FirstOrDefault() ?? query.AnalystUserObjectId;
        await _audit.TelemetryViewedAsync(
            viewer.UserPrincipalName, viewer.UserObjectId, targetAnalystUpn,
            query.From, query.To, sessions.Count, cancellationToken).ConfigureAwait(false);

        return new BrowsingDataResult(views, connectionsTotal, offHoursCount, sensitiveCount);
    }

    private static void Validate(BrowsingDataQuery query)
    {
        if (query.To <= query.From)
        {
            throw new BrowsingDataQueryException("The date range's end must be after its start.");
        }

        if (string.IsNullOrWhiteSpace(query.AnalystUserObjectId)
            && query.To - query.From > TimeSpan.FromDays(MaxUnscopedRangeDays))
        {
            throw new BrowsingDataQueryException(
                $"A query across every analyst must stay within {MaxUnscopedRangeDays} days. Narrow the date " +
                "range, or name one analyst to see a longer history.");
        }
    }
}
