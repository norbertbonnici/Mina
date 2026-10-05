using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Mina.EndpointAgent.Configuration;
using Mina.EndpointAgent.Proxy;

namespace Mina.EndpointAgent.Session;

/// <summary>
/// Owns the research session lifecycle on the endpoint: establish, renew before the lease lapses,
/// and end. It holds the only tunnel the loopback proxy can use, so dropping the session is what
/// closes the protected path (ARCHITECTURE §5). Nothing here can fall back to direct connectivity —
/// a failure clears the session and the proxy then has nothing to forward through.
/// </summary>
public sealed partial class ResearchSessionManager : ISessionControl, IAsyncDisposable
{
    private readonly ControlPlaneClient _controlPlane;
    private readonly MinaAgentOptions _options;
    private readonly TimeProvider _clock;
    private readonly ILogger<ResearchSessionManager> _logger;
    private readonly SemaphoreSlim _mutex = new(1, 1);
    private readonly X509Certificate2 _egressCaCertificate;

    private ActiveSession? _current;
    private int _disposed;

    public ResearchSessionManager(
        ControlPlaneClient controlPlane,
        IOptions<MinaAgentOptions> options,
        TimeProvider clock,
        ILogger<ResearchSessionManager> logger)
    {
        ArgumentNullException.ThrowIfNull(options);
        _controlPlane = controlPlane ?? throw new ArgumentNullException(nameof(controlPlane));
        _options = options.Value;
        _clock = clock ?? throw new ArgumentNullException(nameof(clock));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));

        if (string.IsNullOrWhiteSpace(_options.EgressCaCertificatePem))
        {
            throw new InvalidOperationException(
                "Mina:Agent:EgressCaCertificatePem is required; without it the agent cannot verify " +
                "which egress it is tunnelling to.");
        }

        _egressCaCertificate = X509Certificate2.CreateFromPem(_options.EgressCaCertificatePem);
    }

    /// <summary>The live session, or null when the protected path is down.</summary>
    public ActiveSession? Current => Volatile.Read(ref _current);

    /// <summary>
    /// Explicit so callers holding the concrete manager keep the richer <see cref="ActiveSession"/>,
    /// while everything reached through <see cref="ISessionControl"/> sees only the four facts it
    /// is entitled to.
    /// </summary>
    IResearchSession? ISessionControl.Current => Current;

    /// <summary>Requests a session in the configured region and arms the tunnel.</summary>
    public Task<ActiveSession> EstablishAsync(CancellationToken cancellationToken) =>
        EstablishAsync(_options.Region, cancellationToken);

    /// <summary>
    /// Requests a session in <paramref name="region"/> and arms the tunnel. The caller chooses the
    /// region — the tray lets an analyst change it mid-shift — but the control plane decides whether
    /// that choice is allowed, and refuses the issuance if it is not (AC-008).
    /// </summary>
    public async Task<ActiveSession> EstablishAsync(string region, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(region);

        await _mutex.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var keyMaterial = new SessionKeyMaterial();
            try
            {
                var grant = await _controlPlane
                    .IssueAsync(region, keyMaterial.CreateCertificateSigningRequest(), cancellationToken)
                    .ConfigureAwait(false);

                var session = BuildSession(grant, keyMaterial);
                Swap(session);
                Log.SessionEstablished(_logger, session.SessionId, session.Region, session.LeaseExpiresAt);
                return session;
            }
            catch
            {
                keyMaterial.Dispose();
                throw;
            }
        }
        finally
        {
            _mutex.Release();
        }
    }

    /// <summary>
    /// Renews the lease when it is close to expiry, using a fresh Entra token and a fresh key pair.
    /// Returns true if a renewal happened. A failed renewal drops the session rather than letting
    /// browsing continue on a credential the control plane may have just declined to extend.
    /// </summary>
    public async Task<bool> RenewIfDueAsync(CancellationToken cancellationToken)
    {
        await _mutex.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var current = _current;
            var now = _clock.GetUtcNow();
            if (current is null || !current.IsDueForRenewal(now, _options.RenewMargin))
            {
                return false;
            }

            if (current.HasLapsed(now))
            {
                // Past the lease: the control plane will not extend it, so stop rather than pretend.
                Log.LeaseLapsed(_logger, current.SessionId);
                Swap(null);
                return false;
            }

            var keyMaterial = new SessionKeyMaterial();
            try
            {
                var grant = await _controlPlane
                    .RenewAsync(current.SessionId, keyMaterial.CreateCertificateSigningRequest(), cancellationToken)
                    .ConfigureAwait(false);

                var renewed = BuildSession(grant, keyMaterial);
                Swap(renewed);
                Log.SessionRenewed(_logger, renewed.SessionId, renewed.LeaseExpiresAt);
                return true;
            }
            catch (Exception ex) when (ex is ControlPlaneException or HttpRequestException or NoAccessTokenAvailableException
                                       || (ex is OperationCanceledException && !cancellationToken.IsCancellationRequested))
            {
                // A renewal that timed out is a renewal that did not happen. Treat it exactly like a
                // refusal and drop the session, rather than letting the timeout escape and leave a
                // session alive on a credential the control plane may have declined to extend.
                // The same applies to having no token yet (M2-4): the tray has not signed in or
                // refreshed, which is a transient condition the retry loop already handles, not a
                // reason to let an unhandled exception escape the worker.
                keyMaterial.Dispose();
                Log.RenewalFailed(_logger, current.SessionId, ex.Message);
                Swap(null); // fail closed
                return false;
            }
        }
        finally
        {
            _mutex.Release();
        }
    }

    /// <summary>Ends the session with the control plane and closes the protected path.</summary>
    /// <remarks>
    /// Tolerates <see cref="_mutex"/> already being disposed, both on entry and on release. This is
    /// called from both <see cref="DisposeAsync"/> and <see cref="ProtectedPathWorker"/>'s own
    /// shutdown <c>finally</c> — two independent callers by design, per the comment inside the
    /// method below — so under a slow or forceful stop, one can genuinely still be running (for
    /// example blocked on the control-plane call further down) after the other has already disposed
    /// the manager. <see cref="ObjectDisposedException"/> here can only mean the manager was torn
    /// down already, which only happens at host shutdown, so it is the same "shutting down anyway"
    /// case the <see cref="OperationCanceledException"/> handling below already covers — not a
    /// programming error to surface, since surfacing it is exactly what crashed the process live on
    /// 2026-09-05.
    /// </remarks>
    public async Task EndAsync(CancellationToken cancellationToken)
    {
        try
        {
            await _mutex.WaitAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (ObjectDisposedException)
        {
            return;
        }

        try
        {
            var current = _current;
            if (current is null)
            {
                return;
            }

            // Close locally first: even if the control plane is unreachable, this endpoint stops
            // carrying research traffic.
            Swap(null);
            try
            {
                await _controlPlane.EndAsync(current.SessionId, cancellationToken).ConfigureAwait(false);
                Log.SessionEnded(_logger, current.SessionId);
            }
            catch (Exception ex) when (ex is ControlPlaneException or HttpRequestException or NoAccessTokenAvailableException
                                       || (ex is OperationCanceledException && !cancellationToken.IsCancellationRequested))
            {
                // Deliberately the same filter as RenewIfDueAsync's. The local close above has
                // already happened, so the session is off this endpoint however this call went, and
                // none of these is a reason to fault the caller. The two arms that were missing both
                // had callers: no token yet (M2-4) escaped into TrayControlService.EndSessionAsync
                // and skipped its state.Suspend(), so the worker re-established the session the
                // analyst had just ended; and a timed-out DELETE did the same. EndAsync is also
                // called from DisposeAsync and from ProtectedPathWorker's shutdown finally, where an
                // escaping exception faults the BackgroundService instead of closing it down.
                Log.EndNotAcknowledged(_logger, current.SessionId, ex.Message);
            }
        }
        finally
        {
            try
            {
                _mutex.Release();
            }
            catch (ObjectDisposedException)
            {
                // Disposed by the other caller while this one was still inside the critical
                // section (see the remarks above) -- nothing left to coordinate with.
            }
        }
    }

    private ActiveSession BuildSession(SessionGrantResponse grant, SessionKeyMaterial keyMaterial)
    {
        var pkcs12 = keyMaterial.ToClientCertificatePkcs12(grant.CertificatePem);
        var tunnel = new MtlsTunnelConnectionFactory(
            new EgressEndpoint(grant.EgressHost, grant.EgressPort, grant.EgressServerName),
            // A fresh instance per handshake: the factory disposes what this returns.
            () => X509CertificateLoader.LoadPkcs12(pkcs12, password: null),
            _egressCaCertificate);

        return new ActiveSession(grant, keyMaterial, tunnel);
    }

    private void Swap(ActiveSession? next)
    {
        var previous = Interlocked.Exchange(ref _current, next);
        previous?.Dispose();
    }

    /// <summary>
    /// Idempotent by construction, not merely by convention. <c>Program.cs</c> registers this type
    /// as both <c>ResearchSessionManager</c> and <c>ISessionControl</c> (the second a factory that
    /// resolves the same singleton) — two service-type slots over one instance. The built-in
    /// <c>ServiceProvider</c> tracks disposables per registration, not per object identity, so both
    /// slots call <c>DisposeAsync</c> on host shutdown. Found live 2026-09-05
    /// (<c>Stop-Service -Force</c>, captured in the Application Event Log): the second call's own
    /// <see cref="EndAsync"/> reached <see cref="_mutex"/> after the first call had already disposed
    /// it, throwing <see cref="ObjectDisposedException"/> unhandled and taking the whole process
    /// down. Guarded here — removing one of the two registrations was the other option, but this is
    /// the fix that holds regardless of how many places end up resolving this singleton, now or
    /// later, and matches the general .NET disposal guideline that <c>Dispose</c>/<c>DisposeAsync</c>
    /// must tolerate being called more than once.
    /// </summary>
    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            return;
        }

        try
        {
            await EndAsync(CancellationToken.None).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            // shutting down anyway
        }

        Swap(null);
        _egressCaCertificate.Dispose();
        _mutex.Dispose();
    }

    private static partial class Log
    {
        [LoggerMessage(Level = LogLevel.Information,
            Message = "Research session {SessionId} established in {Region}; lease expires {LeaseExpiresAt:o}.")]
        public static partial void SessionEstablished(
            ILogger logger, Guid sessionId, string region, DateTimeOffset leaseExpiresAt);

        [LoggerMessage(Level = LogLevel.Information,
            Message = "Research session {SessionId} renewed; lease now expires {LeaseExpiresAt:o}.")]
        public static partial void SessionRenewed(ILogger logger, Guid sessionId, DateTimeOffset leaseExpiresAt);

        [LoggerMessage(Level = LogLevel.Warning,
            Message = "Renewal of session {SessionId} failed ({Reason}); closing the protected path.")]
        public static partial void RenewalFailed(ILogger logger, Guid sessionId, string reason);

        [LoggerMessage(Level = LogLevel.Warning,
            Message = "Lease for session {SessionId} lapsed before renewal; closing the protected path.")]
        public static partial void LeaseLapsed(ILogger logger, Guid sessionId);

        [LoggerMessage(Level = LogLevel.Information, Message = "Research session {SessionId} ended.")]
        public static partial void SessionEnded(ILogger logger, Guid sessionId);

        [LoggerMessage(Level = LogLevel.Warning,
            Message = "Session {SessionId} closed locally but the control plane did not acknowledge ({Reason}).")]
        public static partial void EndNotAcknowledged(ILogger logger, Guid sessionId, string reason);
    }
}
