namespace Mina.ControlPlane.Api.Infrastructure;

/// <summary>Startup-time diagnostics for the control-plane host.</summary>
public static partial class StartupLog
{
    [LoggerMessage(Level = LogLevel.Warning,
        Message = "No ConnectionStrings:MinaDb configured — using the in-memory session store. " +
                  "Sessions are lost on restart and are not shared between instances; this is for " +
                  "local development only and must not be used in test or production.")]
    public static partial void UsingInMemorySessionStore(ILogger logger);

    [LoggerMessage(Level = LogLevel.Warning,
        Message = "Using the ephemeral development certificate authority. Certificates it issues stop " +
                  "validating when this process restarts; production must use the Key Vault-backed CA.")]
    public static partial void UsingDevelopmentCertificateAuthority(ILogger logger);

    [LoggerMessage(Level = LogLevel.Information,
        Message = "Background services are disabled on this instance: suppression approvals will not " +
                  "expire and the audit chain will not be anchored from here. Exactly one instance in " +
                  "the deployment must have Mina:Hosting:RunBackgroundServices left enabled.")]
    public static partial void BackgroundServicesDisabled(ILogger logger);
}
