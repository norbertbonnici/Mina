using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace Mina.ControlPlane.Hosting;

/// <summary>
/// Startup guards for running the control plane outside Azure App Service.
/// </summary>
/// <remarks>
/// The move to the on-premises Proxmox cluster (ADR-0006) replaced the platform that used to supply these
/// things. App Service injected configuration from its own settings store and Key Vault references,
/// terminated TLS and told the app about it, and managed the Data Protection key ring. A VM behind a
/// reverse proxy supplies none of that, so each becomes something this host has to assert for
/// itself — and the failure modes are quiet ones: a missing setting that silently selects an
/// in-memory database, a request that looks like plain HTTP because the proxy terminated TLS, an
/// antiforgery token that stops validating after a restart.
/// </remarks>
public static class HostingGuard
{
    /// <summary>
    /// Opt-in switch for the development stand-ins: the in-memory stores, the ephemeral CA and the
    /// filesystem audit sink. Defaults to enabled only in the Development environment, so a host
    /// that is not Development refuses to start on a stand-in rather than quietly running on one.
    /// </summary>
    public const string AllowDevelopmentFallbacksKey = "Mina:AllowDevelopmentFallbacks";

    /// <summary>Directory the Data Protection key ring is persisted to. Required off App Service.</summary>
    public const string DataProtectionKeyPathKey = "Mina:Hosting:DataProtectionKeyPath";

    /// <summary>
    /// Opt-in switch for running both surfaces on one listener. Separate from
    /// <see cref="AllowDevelopmentFallbacksKey"/> on purpose: while the immutable-blob audit sink
    /// (M4-19) is unbuilt, every non-Development host has to set that flag simply to boot — so
    /// hanging listener separation off it meant the one configuration the separation exists to
    /// protect was also the one that switched it off.
    /// </summary>
    public const string AllowSingleListenerKey = "Mina:Hosting:AllowSingleListener";

    /// <summary>Number of reverse proxies in front of this host, for forwarded-header processing.</summary>
    public const string ForwardedProxyCountKey = "Mina:Hosting:ForwardedProxyCount";

    public static bool DevelopmentFallbacksAllowed(IConfiguration configuration, IHostEnvironment environment)
    {
        ArgumentNullException.ThrowIfNull(configuration);
        ArgumentNullException.ThrowIfNull(environment);

        return configuration.GetValue(AllowDevelopmentFallbacksKey, defaultValue: environment.IsDevelopment());
    }

    public static bool SingleListenerAllowed(IConfiguration configuration, IHostEnvironment environment)
    {
        ArgumentNullException.ThrowIfNull(configuration);
        ArgumentNullException.ThrowIfNull(environment);

        return configuration.GetValue(AllowSingleListenerKey, defaultValue: environment.IsDevelopment());
    }

    /// <summary>
    /// Refuses to start when a development stand-in would be used and has not been explicitly
    /// permitted. Failing here is the point: every one of these substitutions is silent at runtime
    /// and only discovered by its consequences — sessions that vanish on restart, a certificate
    /// authority that no longer recognises the certificates it issued a minute ago, or audit anchors
    /// written to a filesystem that cannot make them immutable.
    /// </summary>
    public static void RequireExplicitFallback(bool allowed, string standIn, string realSetting)
    {
        if (allowed)
        {
            return;
        }

        throw new InvalidOperationException(
            $"Refusing to start: this host would use {standIn}, which is a development stand-in. "
            + $"Configure {realSetting} for a real deployment, or set "
            + $"{AllowDevelopmentFallbacksKey}=true to accept the stand-in deliberately. "
            + "Since ADR-0006 the control plane is configured on a VM rather than by App Service, "
            + "so a missing setting is a likely mistake rather than an impossible one.");
    }

    /// <summary>
    /// Persists the Data Protection key ring outside the host's ephemeral state.
    /// </summary>
    /// <remarks>
    /// This is the quietest of the failures the move introduces. Without a persisted key ring the
    /// keys are regenerated on restart, so antiforgery tokens and authentication cookies issued
    /// before a restart stop validating after it — an approver mid-decision gets a rejected form
    /// post and no useful error. Across two instances behind the proxy it is worse: the failure
    /// becomes intermittent, depending on which instance served the GET. The directory must be
    /// shared storage when more than one instance runs.
    /// </remarks>
    public static IServiceCollection AddMinaDataProtection(
        this IServiceCollection services, IConfiguration configuration, IHostEnvironment environment)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configuration);
        ArgumentNullException.ThrowIfNull(environment);

        var keyPath = configuration[DataProtectionKeyPathKey];
        if (string.IsNullOrWhiteSpace(keyPath))
        {
            RequireExplicitFallback(
                DevelopmentFallbacksAllowed(configuration, environment),
                "an in-memory Data Protection key ring, so sign-ins and antiforgery tokens stop "
                + "working across a restart and across instances",
                DataProtectionKeyPathKey);
            return services;
        }

        var keyRing = Directory.CreateDirectory(keyPath);
        services.AddDataProtection()
            .SetApplicationName("Mina")
            .PersistKeysToFileSystem(keyRing);

        return services;
    }

    /// <summary>
    /// Trusts the reverse proxy's forwarded headers. On premises the proxy terminates TLS, so
    /// without this the host sees plain HTTP: OIDC redirect URIs are built with the wrong scheme and
    /// cookies lose the conditions under which they are marked Secure.
    /// </summary>
    /// <remarks>
    /// <c>KnownNetworks</c> and <c>KnownProxies</c> are cleared deliberately. The defaults trust only
    /// loopback, which is wrong for a proxy on another host in the DMZ; the platform's own network
    /// policy is what restricts who can reach this listener (ADR-0006 constraints 2 and 3), and it
    /// is a stronger control than an address list maintained in two places. The forward limit still
    /// bounds how many hops are honoured.
    /// </remarks>
    public static void ConfigureForwardedHeaders(ForwardedHeadersOptions options, IConfiguration configuration)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(configuration);

        options.ForwardedHeaders = Microsoft.AspNetCore.HttpOverrides.ForwardedHeaders.XForwardedFor
            | Microsoft.AspNetCore.HttpOverrides.ForwardedHeaders.XForwardedProto
            | Microsoft.AspNetCore.HttpOverrides.ForwardedHeaders.XForwardedHost;
        options.ForwardLimit = configuration.GetValue(ForwardedProxyCountKey, defaultValue: 1);

        options.KnownIPNetworks.Clear();
        options.KnownProxies.Clear();
    }
}
