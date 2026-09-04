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
        Message = "Internal CA loaded from Key Vault {VaultUri}: {Subject}, valid until {NotAfter:u}. " +
                  "The signing key stays in the vault; every issuance is a sign operation there.")]
    public static partial void UsingKeyVaultCertificateAuthority(
        ILogger logger, string vaultUri, string subject, DateTimeOffset notAfter);
}
