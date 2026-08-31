namespace Mina.EndpointAgent;

/// <summary>Startup-time diagnostics for the endpoint agent.</summary>
internal static partial class AgentStartupLog
{
    [LoggerMessage(Level = LogLevel.Warning,
        Message = "Using a configured access token. This is a development stand-in for Entra sign-in " +
                  "and cannot observe token revocation; production uses the WAM broker (M2-4).")]
    public static partial void UsingConfiguredAccessToken(ILogger logger);
}
