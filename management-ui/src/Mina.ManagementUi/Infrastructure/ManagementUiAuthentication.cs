using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.Identity.Web;

namespace Mina.ManagementUi.Infrastructure;

/// <summary>Chooses how humans sign in to the management UI.</summary>
public static class ManagementUiAuthentication
{
    /// <summary>
    /// Entra OIDC normally; the development sign-in only when the host is in Development *and* it
    /// has been switched on explicitly. Asking for the bypass anywhere else is a startup failure
    /// rather than a warning — an authentication bypass that can be enabled by configuration alone
    /// is the kind of thing that reaches production by accident.
    /// </summary>
    public static IServiceCollection AddManagementUiAuthentication(
        this IServiceCollection services, IConfiguration configuration, IHostEnvironment environment)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configuration);
        ArgumentNullException.ThrowIfNull(environment);

        services.Configure<DevSignInOptions>(configuration.GetSection(DevSignInOptions.Section));
        var devSignInRequested = configuration.GetValue<bool>($"{DevSignInOptions.Section}:Enabled");

        if (devSignInRequested && !environment.IsDevelopment())
        {
            throw new InvalidOperationException(
                $"{DevSignInOptions.Section}:Enabled is set, but the host environment is " +
                $"'{environment.EnvironmentName}'. The development sign-in bypasses authentication " +
                "and is permitted only in Development.");
        }

        if (devSignInRequested)
        {
            services.AddAuthentication(DevSignInAuthHandler.SchemeName)
                .AddScheme<AuthenticationSchemeOptions, DevSignInAuthHandler>(
                    DevSignInAuthHandler.SchemeName, _ => { });
            return services;
        }

        services.AddAuthentication(OpenIdConnectDefaults.AuthenticationScheme)
            .AddMicrosoftIdentityWebApp(configuration.GetSection("AzureAd"));

        return services;
    }
}
