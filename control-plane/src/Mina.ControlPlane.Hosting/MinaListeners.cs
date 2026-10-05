using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;

namespace Mina.ControlPlane.Hosting;

/// <summary>Which of the control plane's two listeners an endpoint belongs to.</summary>
public enum MinaListener
{
    /// <summary>
    /// Published from the on-premises DMZ so the Azure egress nodes can reach it (ADR-0006). Carries the
    /// session allowlist and telemetry ingest, and nothing else.
    /// </summary>
    Node,

    /// <summary>
    /// Reachable from corporate workstations only: the analyst session API, the suppression
    /// workflow, the audit read API and every administrative endpoint.
    /// </summary>
    Management,
}

/// <summary>Ports the two listeners bind. Both are required outside Development.</summary>
public sealed class MinaListenerOptions
{
    public const string Section = "Mina:Hosting:Listeners";

    /// <summary>Port for the internet-published, node-facing listener.</summary>
    public int? NodePort { get; set; }

    /// <summary>Port for the corporate-facing listener.</summary>
    public int? ManagementPort { get; set; }

    /// <summary>
    /// True once both ports are configured and distinct. When false the process serves everything on
    /// whatever it was told to listen on, which is the single-listener shape used by local
    /// development and by the test host — and which must never be what runs in the DMZ.
    /// </summary>
    public bool Separated => NodePort is > 0 && ManagementPort is > 0 && NodePort != ManagementPort;

    public int? PortFor(MinaListener listener) => listener switch
    {
        MinaListener.Node => NodePort,
        MinaListener.Management => ManagementPort,
        _ => null,
    };
}

/// <summary>
/// Marks an endpoint as belonging to one listener, or to both. Read by the separation middleware.
/// </summary>
/// <remarks>
/// An endpoint carrying none of this metadata is refused on a separated host, not served. That
/// default is not tidiness: when a path matches a route but the HTTP method does not, ASP.NET Core
/// substitutes a synthetic method-rejection endpoint whose metadata collection is empty. Serving
/// metadata-less endpoints meant a wrong-method request to any management path answered 405 with an
/// <c>Allow</c> header on the published listener, enumerating the whole management route table and
/// its verbs to an unauthenticated internet caller — while a genuinely absent path answered 404.
/// Defaulting to deny also means an endpoint added without declaring a listener disappears in
/// testing rather than appearing on the internet.
/// </remarks>
public sealed class MinaListenerMetadata
{
    private MinaListenerMetadata(MinaListener? listener) => Listener = listener;

    /// <summary>The listener this endpoint belongs to, or null when it belongs to both.</summary>
    public MinaListener? Listener { get; }

    public static MinaListenerMetadata For(MinaListener listener) => new(listener);

    public static MinaListenerMetadata Any { get; } = new(null);
}

/// <summary>
/// Binds the control plane's endpoints to two separate listeners.
/// </summary>
/// <remarks>
/// ADR-0006 constraint 1: the node-facing endpoint is published to the internet, so the management
/// surface must not be reachable there *even if the DMZ reverse proxy is misconfigured*. That rules
/// out proxy path rules and host-header matching as the mechanism, because both are exactly what a
/// proxy misconfiguration gets wrong, and a host header is client-controlled besides.
///
/// The mechanism used instead is the local port the TCP connection was accepted on
/// (<see cref="ConnectionInfo.LocalPort"/>). It is a property of which socket accepted the
/// connection, so nothing the client sends can change it, and no proxy rule can route a request to
/// a port the process is not listening on for that purpose. Forwarded-header processing does not
/// touch it either: <c>UseForwardedHeaders</c> rewrites the remote address, scheme and host, and
/// deliberately not the local port.
///
/// The check runs after routing and *before* authentication, so an endpoint that does not belong to
/// the listener answers a plain 404 — the same answer a path that does not exist gives. A request
/// for the audit API arriving on the published port learns nothing, not even that it is
/// authenticated elsewhere.
/// </remarks>
public static class MinaListeners
{
    /// <summary>
    /// Binds Kestrel to both ports when they are configured. Returns whether separation is active,
    /// so the caller can refuse to start if it is required and absent.
    /// </summary>
    public static bool ConfigureMinaListeners(this WebApplicationBuilder builder)
    {
        ArgumentNullException.ThrowIfNull(builder);

        builder.Services.Configure<MinaListenerOptions>(builder.Configuration.GetSection(MinaListenerOptions.Section));

        var options = new MinaListenerOptions();
        builder.Configuration.GetSection(MinaListenerOptions.Section).Bind(options);

        if (options.NodePort is > 0 && options.NodePort == options.ManagementPort)
        {
            throw new InvalidOperationException(
                $"{MinaListenerOptions.Section}:NodePort and ManagementPort are both "
                + $"{options.NodePort}. Configuring one port would serve the management surface on "
                + "the listener published to the internet, which is what ADR-0006 constraint 1 "
                + "exists to prevent.");
        }

        if (!options.Separated)
        {
            return false;
        }

        builder.Services.Configure<KestrelServerOptions>(kestrel =>
        {
            kestrel.ListenAnyIP(options.NodePort!.Value);
            kestrel.ListenAnyIP(options.ManagementPort!.Value);
        });

        return true;
    }

    /// <summary>Declares which listener an endpoint or group belongs to.</summary>
    public static TBuilder RequireListener<TBuilder>(this TBuilder builder, MinaListener listener)
        where TBuilder : IEndpointConventionBuilder
    {
        ArgumentNullException.ThrowIfNull(builder);
        builder.Add(endpoint => endpoint.Metadata.Add(MinaListenerMetadata.For(listener)));
        return builder;
    }

    /// <summary>
    /// Declares an endpoint as belonging to both listeners — the health probe, because each
    /// listener is fronted by something that has to check it. Deliberately explicit: the middleware
    /// refuses anything that has not said which listener it belongs to.
    /// </summary>
    public static TBuilder AllowOnAnyListener<TBuilder>(this TBuilder builder)
        where TBuilder : IEndpointConventionBuilder
    {
        ArgumentNullException.ThrowIfNull(builder);
        builder.Add(endpoint => endpoint.Metadata.Add(MinaListenerMetadata.Any));
        return builder;
    }

    /// <summary>
    /// Refuses a request that reached an endpoint belonging to the other listener. Must be
    /// registered after routing and before authentication.
    /// </summary>
    public static IApplicationBuilder UseMinaListenerSeparation(this IApplicationBuilder app)
    {
        ArgumentNullException.ThrowIfNull(app);

        return app.Use(async (context, next) =>
        {
            var options = context.RequestServices.GetRequiredService<IOptions<MinaListenerOptions>>().Value;
            var endpoint = context.GetEndpoint();

            // Unseparated hosts (local development, the test host) serve everything, which is why
            // the startup guard refuses that shape outside Development. A request that matched no
            // endpoint at all is left to the framework's own 404.
            if (!options.Separated || endpoint is null)
            {
                await next(context).ConfigureAwait(false);
                return;
            }

            var declared = endpoint.Metadata.GetMetadata<MinaListenerMetadata>();

            // Default deny, but only on the published listener. The property being defended is
            // one-directional: the node listener faces the internet and must expose exactly what it
            // declares, so anything undeclared — including the synthetic method-rejection endpoint,
            // which carries no metadata — is refused there. The corporate listener is not that
            // exposure, so an undeclared endpoint keeps normal framework behaviour and a wrong
            // method still answers 405 for whoever is debugging it. The cost of the asymmetry is
            // that a wrong method on a node route also answers 404 rather than 405, which discloses
            // less and is the right trade on an internet-facing port.
            var onPublishedListener = context.Connection.LocalPort == options.NodePort;

            if ((declared is null && onPublishedListener)
                || (declared?.Listener is { } listener && context.Connection.LocalPort != options.PortFor(listener)))
            {
                // 404, not 403 or 405: on this listener the endpoint does not exist. Anything else
                // confirms the management API is present on the published port, which is the whole
                // property this middleware is here to provide.
                context.Response.StatusCode = StatusCodes.Status404NotFound;
                return;
            }

            await next(context).ConfigureAwait(false);
        });
    }
}
