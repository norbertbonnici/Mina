using System.Collections.Concurrent;
using Google.Protobuf.WellKnownTypes;
using Grpc.Core;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Mina.EgressNode.Sidecar.Envoy;
using EnvoyStatus = Mina.EgressNode.Sidecar.Envoy.Status;
using EnvoyStatusCode = Mina.EgressNode.Sidecar.Envoy.StatusCode;

namespace Mina.EgressNode.Sidecar;

/// <summary>
/// Answers Envoy's <c>ext_authz</c> check for every tunnel the node is asked to open (M4-11).
/// </summary>
/// <remarks>
/// <para>
/// Envoy has already verified the client certificate against the internal CA before this is
/// consulted; this decides whether the <em>session</em> that certificate names is one the control
/// plane currently lists for this region. A gRPC status of OK opens the tunnel. Anything else — a
/// refusal from here, an RPC error, a deadline, a socket that is not there — closes it, because the
/// Envoy side is configured with <c>failure_mode_allow: false</c>. There is therefore no code path
/// here whose failure admits anyone, and the handler is written to keep it that way: it returns OK
/// from exactly one place.
/// </para>
/// <para>
/// gRPC rather than Envoy's HTTP authorization service, and not for taste: for a CONNECT, Envoy's
/// HTTP check request is itself a CONNECT — authority-form, no path, the analyst's destination as
/// its host — and Kestrel closes that connection before answering, so every session on the node
/// would have been refused. The gRPC request is an ordinary RPC and carries the verified
/// certificate's principal as a field. Established against the pinned Envoy in Docker, not
/// reasoned about.
/// </para>
/// </remarks>
public static class SessionAdmissionHost
{
    /// <summary>
    /// Adds the admission listener: Kestrel on the given Unix socket, HTTP/2 only (gRPC needs it,
    /// and Envoy's cluster speaks nothing else to it). The host refuses to start serving if any
    /// other endpoint is bound — a TCP listener here, however it got configured, would be an
    /// admission oracle reachable from the network.
    /// </summary>
    public static WebApplicationBuilder AddSessionAdmissionListener(this WebApplicationBuilder builder, string socketPath)
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentException.ThrowIfNullOrWhiteSpace(socketPath);

        builder.Services.AddGrpc();
        builder.Services.AddSingleton<AdmissionMissLimiter>();
        builder.WebHost.ConfigureKestrel(kestrel =>
        {
            kestrel.AddServerHeader = false;
            kestrel.ListenUnixSocket(socketPath, listen => listen.Protocols = HttpProtocols.Http2);
        });

        return builder;
    }

    public static WebApplication UseSessionAdmission(this WebApplication app)
    {
        ArgumentNullException.ThrowIfNull(app);

        app.Lifetime.ApplicationStarted.Register(() =>
        {
            var addresses = app.Services.GetRequiredService<IServer>().Features.Get<IServerAddressesFeature>()?.Addresses ?? [];
            var stray = addresses.Where(a => !a.StartsWith("http://unix:", StringComparison.OrdinalIgnoreCase)).ToList();
            if (stray.Count > 0)
            {
                // Stop rather than log: a warning in a journal nobody reads is not a control.
                var bound = string.Join(", ", stray);
                AdmissionLog.BoundToNetwork(app.Logger, bound);
                app.Lifetime.StopApplication();
            }
        });

        app.MapGrpcService<SessionAdmissionService>();

        // Envoy's active health check, and through it the load balancer's: healthy only while the
        // view is loaded and fresh, so a node that would refuse every session says so rather than
        // taking traffic it will answer with 503.
        app.MapGet("/healthz", (NodeSessionView view, IOptions<SidecarOptions> options, TimeProvider clock) =>
            view.IsFresh(clock, options.Value.AdmissionMaxViewAge)
                ? Results.Text("ok")
                : Results.Text(
                    view.Age(clock) is { } age ? $"session view is {age.TotalSeconds:F0}s old" : "session view not loaded",
                    statusCode: StatusCodes.Status503ServiceUnavailable));

        return app;
    }
}

/// <summary>The Envoy external-authorization service the sidecar exposes on its socket.</summary>
public sealed class SessionAdmissionService(
    NodeSessionView view,
    ISessionViewRefresher refresher,
    AdmissionMissLimiter misses,
    IOptions<SidecarOptions> options,
    TimeProvider clock,
    ILogger<SessionAdmissionService> logger) : Authorization.AuthorizationBase
{
    /// <summary>
    /// The dynamic-metadata key Envoy's access log reads to decide whether to log a tunnel's
    /// destination. Set on every admitted session: <c>true</c> under an approved suppression,
    /// <c>false</c> otherwise. Stated both ways rather than present-or-absent because Envoy's
    /// access-log metadata filter cannot invert a match (established against the pinned release),
    /// so each of the two loggers in envoy-bootstrap.yaml matches one explicit value. A refusal
    /// carries no metadata and falls to the full logger by its key-not-found default.
    /// </summary>
    public const string SuppressedMetadataKey = "suppressed";

    private readonly SidecarOptions _options = options.Value;

    public override async Task<CheckResponse> Check(CheckRequest request, ServerCallContext context)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(context);

        // Only the peer principal is read. The request attributes also carry the analyst's CONNECT
        // authority as request.http.host; it is not this service's business and is not touched.
        var sessionId = SessionPrincipal.TryParse(request.Attributes?.Source?.Principal);
        if (sessionId is not { } id)
        {
            AdmissionLog.RefusedUnreadable(logger);
            return Refuse();
        }

        var decision = view.Admit(id, clock, _options.AdmissionMaxViewAge);

        if (decision == Admission.UnknownSession && misses.ShouldRefreshFor(id, clock, _options.AllowlistRefreshInterval))
        {
            // A session issued since the last refresh is unknown here for up to one interval, and
            // the analyst's browser is already trying. One bounded refresh closes that gap; if it
            // does not return in time the answer is still the answer the view gives.
            using var timeout = new CancellationTokenSource(_options.AdmissionRefreshOnMissTimeout);
            using var linked = CancellationTokenSource.CreateLinkedTokenSource(timeout.Token, context.CancellationToken);
            try
            {
                await refresher.RefreshAsync(linked.Token).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                AdmissionLog.MissRefreshTimedOut(logger, id);
            }

            decision = view.Admit(id, clock, _options.AdmissionMaxViewAge);
        }

        if (decision != Admission.Admitted)
        {
            AdmissionLog.Refused(logger, id, decision);
            return Refuse();
        }

        var response = new CheckResponse
        {
            Status = new EnvoyStatus { Code = (int)Grpc.Core.StatusCode.OK },
            OkResponse = new OkHttpResponse(),
        };

        // Suppression at Envoy itself: this flag selects which access-log entry writes the tunnel's
        // line. True selects the one that omits the CONNECT authority, so a suppressed session's
        // destination is never written to the node's disk at all — not logged and then dropped by
        // the shipper. The sidecar's own withholding (TelemetryBatcher) and the control plane's
        // ingest check (threat N5) remain as the second and third lines; this is the first.
        response.DynamicMetadata = new Struct
        {
            Fields = { [SuppressedMetadataKey] = Value.ForBool(view.MustWithholdDestination(id)) },
        };

        return response;
    }

    // gRPC PERMISSION_DENIED (7) is what Envoy reads as "refused"; the HTTP status is what the
    // analyst's agent sees on the CONNECT.
    private static CheckResponse Refuse() => new()
    {
        Status = new EnvoyStatus { Code = (int)Grpc.Core.StatusCode.PermissionDenied },
        DeniedResponse = new DeniedHttpResponse { Status = new HttpStatus { Code = EnvoyStatusCode.Forbidden } },
    };
}

/// <summary>
/// Bounds refresh-on-miss to one control-plane request per unknown session per refresh interval,
/// so a certificate for a session that will never be listed cannot turn every tunnel attempt into
/// a control-plane call.
/// </summary>
public sealed class AdmissionMissLimiter
{
    private const int PruneAbove = 4096;

    private readonly ConcurrentDictionary<Guid, long> _lastMiss = new();

    public bool ShouldRefreshFor(Guid sessionId, TimeProvider clock, TimeSpan minInterval)
    {
        ArgumentNullException.ThrowIfNull(clock);

        var now = clock.GetTimestamp();
        if (_lastMiss.TryGetValue(sessionId, out var last) && clock.GetElapsedTime(last, now) < minInterval)
        {
            return false;
        }

        _lastMiss[sessionId] = now;

        if (_lastMiss.Count > PruneAbove)
        {
            foreach (var (key, stamp) in _lastMiss)
            {
                if (clock.GetElapsedTime(stamp, now) >= minInterval)
                {
                    _lastMiss.TryRemove(key, out _);
                }
            }
        }

        return true;
    }
}

internal static partial class AdmissionLog
{
    [LoggerMessage(EventId = 7100, Level = LogLevel.Warning,
        Message = "Tunnel refused: the client certificate's principal is not a session URI.")]
    public static partial void RefusedUnreadable(ILogger logger);

    [LoggerMessage(EventId = 7101, Level = LogLevel.Information,
        Message = "Tunnel refused for session {SessionId}: {Reason}.")]
    public static partial void Refused(ILogger logger, Guid sessionId, Admission reason);

    [LoggerMessage(EventId = 7102, Level = LogLevel.Critical,
        Message = "The admission listener is bound to a network address ({Addresses}); it must only ever answer on its Unix socket. Stopping.")]
    public static partial void BoundToNetwork(ILogger logger, string addresses);

    [LoggerMessage(EventId = 7103, Level = LogLevel.Warning,
        Message = "Refresh on miss for session {SessionId} did not complete in time; answering from the current view.")]
    public static partial void MissRefreshTimedOut(ILogger logger, Guid sessionId);
}
