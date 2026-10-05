namespace Mina.ManagementUi.Infrastructure;

/// <summary>Approved and active egress regions, bound from configuration (mirrors the API).</summary>
public sealed class MinaUiRegionOptions
{
    public IList<string> Approved { get; init; } = [];

    public IList<string> Active { get; init; } = [];
}

/// <summary>Startup diagnostics for the management UI.</summary>
public static partial class UiStartupLog
{
    [LoggerMessage(Level = LogLevel.Warning,
        Message = "No ConnectionStrings:MinaDb configured — the management UI is reading an in-memory " +
                  "store private to this process, so it will not show sessions created by the API.")]
    public static partial void UsingInMemoryStore(ILogger logger);

    [LoggerMessage(Level = LogLevel.Warning,
        Message = "Development sign-in is enabled: every visitor is signed in as {UserPrincipalName} " +
                  "without authenticating. This is permitted only in Development.")]
    public static partial void UsingDevelopmentSignIn(ILogger logger, string userPrincipalName);

    [LoggerMessage(Level = LogLevel.Warning,
        Message = "Browsing-data off-hours flagging is NOT enforced: {Section} is unset, so no connection " +
                  "is ever flagged. This is a stated condition, not an oversight — set it to enable flagging.")]
    public static partial void OfficeHoursFlaggingDisabled(ILogger logger, string section);
}
