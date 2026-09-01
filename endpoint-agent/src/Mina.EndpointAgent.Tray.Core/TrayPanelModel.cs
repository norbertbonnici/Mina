using System.Globalization;
using Mina.EndpointAgent.Ipc;

namespace Mina.EndpointAgent.Tray;

/// <summary>How a piece of the panel should read. Semantic, not a colour — the shell picks those.</summary>
public enum TrayTone
{
    /// <summary>Nothing to say.</summary>
    Neutral,

    /// <summary>Working as intended.</summary>
    Good,

    /// <summary>True and deliberate, but the analyst should know: suppression is running.</summary>
    Warning,

    /// <summary>Research browsing is not happening.</summary>
    Bad,
}

/// <summary>Buttons the panel offers. What is absent matters as much as what is present.</summary>
[Flags]
public enum TrayActions
{
    None = 0,
    Reconnect = 1,
    EndSession = 2,
    StartSession = 4,
    RequestSensitive = 8,
    ActivateSensitive = 16,
    CancelSensitive = 32,
}

/// <summary>
/// Everything on the panel at one instant. Produced by <see cref="TrayPanel"/> from the agent's
/// status, so what the analyst sees is a function of what the agent reported and nothing else.
/// </summary>
public sealed record TrayPanelModel
{
    public required string Headline { get; init; }

    public required TrayTone Tone { get; init; }

    public required string Detail { get; init; }

    /// <summary>
    /// The fail-closed reassurance. Present only when browsing has stopped, because that is the
    /// moment an analyst needs telling that nothing leaked out the ordinary way.
    /// </summary>
    public string? Alert { get; init; }

    public IReadOnlyList<RegionChoice> Regions { get; init; } = [];

    public string? SelectedRegion { get; init; }

    public bool CanChooseRegion { get; init; }

    public required string LoggingLabel { get; init; }

    public required TrayTone LoggingTone { get; init; }

    /// <summary>Session id and lease countdown, or null when there is no session.</summary>
    public string? SessionLine { get; init; }

    /// <summary>Where the suppression request has got to, or null when there is none.</summary>
    public string? SensitiveLine { get; init; }

    public required TrayActions Actions { get; init; }

    /// <summary>The last refusal or transport failure, for the panel's error strip.</summary>
    public string? Notice { get; init; }
}

/// <summary>A region as offered to the analyst: the Azure name, and something readable.</summary>
public sealed record RegionChoice(string Name, string DisplayName)
{
    public override string ToString() => DisplayName;
}

/// <summary>
/// Projects the agent's status onto the panel. A pure function on purpose: every rule about what
/// the analyst is told — and which buttons exist — is decided here and can be asserted directly.
/// </summary>
public static class TrayPanel
{
    /// <summary>
    /// Readable names for the approved EU regions. Unknown names fall through unchanged rather
    /// than being hidden: the control plane is the source of the list, and a region the tray has
    /// not heard of must still be selectable.
    /// </summary>
    private static readonly Dictionary<string, string> RegionDisplayNames = new(StringComparer.OrdinalIgnoreCase)
    {
        ["westeurope"] = "West Europe",
        ["northeurope"] = "North Europe",
        ["germanywestcentral"] = "Germany West Central",
        ["francecentral"] = "France Central",
        ["swedencentral"] = "Sweden Central",
        ["norwayeast"] = "Norway East",
        ["switzerlandnorth"] = "Switzerland North",
        ["italynorth"] = "Italy North",
        ["polandcentral"] = "Poland Central",
        ["spaincentral"] = "Spain Central",
    };

    public static string DisplayNameFor(string region) =>
        RegionDisplayNames.TryGetValue(region, out var display) ? display : region;

    /// <summary>The panel when the agent service cannot be reached at all.</summary>
    public static TrayPanelModel Unavailable(string reason) => new()
    {
        Headline = "Agent unavailable",
        Tone = TrayTone.Bad,
        Detail = reason,
        Alert = "Research browsing is not available. Nothing has moved to your normal internet connection.",
        LoggingLabel = "Unknown",
        LoggingTone = TrayTone.Neutral,
        Actions = TrayActions.Reconnect,
    };

    public static TrayPanelModel From(AgentStatusDto status, DateTimeOffset now, string? notice = null)
    {
        ArgumentNullException.ThrowIfNull(status);

        var regions = status.SelectableRegions.Select(r => new RegionChoice(r, DisplayNameFor(r))).ToArray();
        var regionName = DisplayNameFor(status.Region);
        var sensitive = status.Sensitive;

        var model = status.State switch
        {
            ProtectedPathStates.Protected => Protected(status, regionName, now),
            ProtectedPathStates.Connecting => Connecting(regionName),
            ProtectedPathStates.Stopped => Stopped(),
            _ => Failed(status, now),
        };

        return model with
        {
            Regions = regions,
            SelectedRegion = status.Region,

            // Changing region tears down the session, so it is offered whenever the agent is
            // willing to act — including while stopped, where it decides where the next one goes.
            CanChooseRegion = regions.Length > 0,
            SensitiveLine = DescribeSensitive(sensitive, now),
            Actions = model.Actions | SensitiveActions(status),
            Notice = notice,
        };
    }

    private static TrayPanelModel Protected(AgentStatusDto status, string regionName, DateTimeOffset now)
    {
        var suppressed = string.Equals(status.Mode, "Sensitive", StringComparison.OrdinalIgnoreCase);

        return new TrayPanelModel
        {
            Headline = "Protected",
            Tone = TrayTone.Good,
            Detail =
                $"Research browsing exits from {regionName}. Everything else on this PC uses your " +
                "normal corporate connection.",
            LoggingLabel = suppressed ? "Hostnames suppressed" : "Hostnames recorded",
            LoggingTone = suppressed ? TrayTone.Warning : TrayTone.Neutral,
            SessionLine = DescribeSession(status, now),
            Actions = TrayActions.EndSession,
        };
    }

    private static TrayPanelModel Connecting(string regionName) => new()
    {
        Headline = "Connecting",
        Tone = TrayTone.Neutral,
        Detail =
            $"Establishing the protected path to {regionName}. Research browsing will not work until it is up.",
        LoggingLabel = "Hostnames recorded",
        LoggingTone = TrayTone.Neutral,
        Actions = TrayActions.EndSession,
    };

    private static TrayPanelModel Stopped() => new()
    {
        Headline = "Session ended",
        Tone = TrayTone.Neutral,
        Detail =
            "You ended your research session. The research browser has no route out until you start another.",
        LoggingLabel = "No session",
        LoggingTone = TrayTone.Neutral,
        Actions = TrayActions.StartSession,
    };

    private static TrayPanelModel Failed(AgentStatusDto status, DateTimeOffset now)
    {
        var detail = string.IsNullOrWhiteSpace(status.Reason)
            ? "The protected path is down."
            : status.Reason;

        var attempt = (status.ConsecutiveFailures + 1).ToString(CultureInfo.InvariantCulture);
        var retry = status.NextAttemptAt is { } next && next > now
            ? $" Trying again in {Countdown(next - now)} (attempt {attempt})."
            : string.Empty;

        return new TrayPanelModel
        {
            Headline = "Browsing stopped",
            Tone = TrayTone.Bad,
            Detail = detail + retry,

            // The single most important sentence in the product. An analyst who is not told this
            // will assume the page failed to load and try again in ordinary Edge.
            Alert =
                "Your research browsing did not fall back. Nothing was sent through the organisation's " +
                "normal internet connection, and the rest of this PC is unaffected.",
            LoggingLabel = "No session",
            LoggingTone = TrayTone.Neutral,
            Actions = TrayActions.Reconnect | TrayActions.EndSession,
        };
    }

    private static string DescribeSession(AgentStatusDto status, DateTimeOffset now)
    {
        var id = status.SessionId is { } sessionId
            ? sessionId.ToString("N", CultureInfo.InvariantCulture)[..8]
            : "—";

        if (status.LeaseExpiresAt is not { } expires)
        {
            return id;
        }

        return expires > now
            ? $"{id} · lease ends in {Countdown(expires - now)}"
            : $"{id} · lease expired";
    }

    private static string? DescribeSensitive(SensitiveRequestDto? sensitive, DateTimeOffset now)
    {
        if (sensitive is null)
        {
            return null;
        }

        var reference = sensitive.JustificationReference;
        return sensitive.State switch
        {
            "Requested" => $"Waiting for a manager to decide · {reference}",
            "Approved" =>
                $"Approved by {sensitive.ApproverUpn ?? "a manager"} for " +
                $"{sensitive.RequestedMinutes.ToString(CultureInfo.InvariantCulture)} minutes · "
                + "starts when you say so",
            "ActiveSuppressed" => DescribeActive(sensitive, now),
            "Denied" => $"Declined by {sensitive.ApproverUpn ?? "a manager"} · {reference}",
            "Cancelled" => $"Withdrawn · {reference}",
            "Ended" => $"Ended · {reference}",
            _ => null,
        };
    }

    private static string DescribeActive(SensitiveRequestDto sensitive, DateTimeOffset now)
    {
        if (sensitive.ExpiresAt is not { } expires)
        {
            return "Suppressed";
        }

        // "Ends the session", not "reverts to normal logging". Expiry terminates the session rather
        // than resuming telemetry underneath the analyst (ADR-0003), and the panel must not imply
        // otherwise.
        return expires > now
            ? $"Suppressed for another {Countdown(expires - now)}, then the session ends"
            : "The suppression window has elapsed";
    }

    private static TrayActions SensitiveActions(AgentStatusDto status)
    {
        // Suppression can only be asked for against a live session, so the option is absent rather
        // than disabled when there is none.
        if (!string.Equals(status.State, ProtectedPathStates.Protected, StringComparison.Ordinal))
        {
            return TrayActions.None;
        }

        return status.Sensitive?.State switch
        {
            "Requested" => TrayActions.CancelSensitive,
            "Approved" => TrayActions.ActivateSensitive | TrayActions.CancelSensitive,
            "ActiveSuppressed" => TrayActions.None,
            _ => TrayActions.RequestSensitive,
        };
    }

    private static string Countdown(TimeSpan remaining)
    {
        if (remaining < TimeSpan.Zero)
        {
            remaining = TimeSpan.Zero;
        }

        return remaining.TotalHours >= 1
            ? remaining.ToString(@"h\:mm\:ss", CultureInfo.InvariantCulture)
            : remaining.ToString(@"m\:ss", CultureInfo.InvariantCulture);
    }
}
