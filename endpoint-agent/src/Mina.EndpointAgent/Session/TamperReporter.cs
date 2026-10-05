namespace Mina.EndpointAgent.Session;

/// <summary>
/// The only tamper indicators EVENT_SCHEMAS.md's `client_tamper_suspected` row defines. Kept here
/// as constants, rather than inline strings at each call site, so the control plane's own
/// server-side validation (`TamperEndpoints.KnownIndicators`) has exactly one client-side
/// equivalent to stay in sync with.
/// </summary>
public static class TamperIndicators
{
    public const string WfpRuleMissing = "wfp_rule_missing";
    public const string UnmanagedBrowserInstance = "unmanaged_browser_instance";
    public const string ForeignProxyClient = "foreign_proxy_client";
    public const string FlagMismatch = "flag_mismatch";
}

/// <summary>
/// Reports a tamper indicator without making the caller wait on — or fail over — a network call.
/// Detection lives in security-critical hot paths (a rejected loopback connection, a firewall-rule
/// drift check at startup); none of them should block, or be able to fail, on top of what they are
/// already doing because the control plane happened to be unreachable.
/// </summary>
public interface ITamperReporter
{
    void Report(string indicator, Guid? sessionId = null);
}

/// <summary>Fire-and-forget production reporter, backed by <see cref="ControlPlaneClient"/>.</summary>
public sealed partial class TamperReporter(ControlPlaneClient controlPlane, ILogger<TamperReporter> logger)
    : ITamperReporter
{
    public void Report(string indicator, Guid? sessionId = null)
    {
        _ = ReportAsync(indicator, sessionId);
    }

    private async Task ReportAsync(string indicator, Guid? sessionId)
    {
        try
        {
            await controlPlane.ReportTamperAsync(indicator, sessionId, CancellationToken.None).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is ControlPlaneException or HttpRequestException or NoAccessTokenAvailableException)
        {
            // Best-effort by design (see the interface remarks): logged so an operator watching
            // this machine's own logs can see it, never surfaced to whatever detected the tamper
            // indicator in the first place.
            Log.ReportFailed(logger, indicator, ex.Message);
        }
    }

    private static partial class Log
    {
        [LoggerMessage(Level = LogLevel.Warning,
            Message = "Could not report tamper indicator '{Indicator}' to the control plane: {Reason}")]
        public static partial void ReportFailed(ILogger logger, string indicator, string reason);
    }
}
