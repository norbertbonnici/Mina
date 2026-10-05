using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Options;
using Mina.ControlPlane.Domain.Regions;
using Mina.ControlPlane.Domain.Sessions;
using Mina.ControlPlane.Pki;

namespace Mina.ControlPlane.Application.Sessions;

/// <summary>Options governing session issuance.</summary>
public sealed class SessionServiceOptions
{
    public const string Section = "Mina:Session";

    /// <summary>App role a caller must hold to open a research session.</summary>
    public string AnalystRole { get; set; } = "Mina.Analyst";

    /// <summary>Lease/certificate TTL for a session (ARCHITECTURE §4: ≈ 60 minutes).</summary>
    public TimeSpan LeaseTtl { get; set; } = TimeSpan.FromMinutes(60);

    /// <summary>
    /// How many lapsed sessions one expiry sweep closes. The sweep repeats, so a backlog drains
    /// over several passes rather than in one unbounded read.
    /// </summary>
    public int ExpirySweepBatchSize { get; set; } = 200;

    /// <summary>
    /// Conditional Access authentication-context id (for example <c>c1</c>) that a token must carry
    /// in its <c>acrs</c> claim before a session is issued. Empty disables the check.
    /// </summary>
    /// <remarks>
    /// This is the only way a resource API can require that a CA policy granting on "device marked
    /// as compliant" was actually satisfied for the presenting token — an Entra access token has no
    /// compliance claim, and a <c>deviceid</c> proves registration only. It is opt-in because it has
    /// a tenant-side prerequisite: an authentication context must exist and a CA policy must be
    /// bound to it. Turning it on without that configuration refuses every session, which is the
    /// safe direction but is a deployment step, not a default.
    ///
    /// The value is fail-closed and self-verifying in a way the <c>deviceid</c> check is not: if the
    /// policy is deleted, mis-scoped, or excludes a group, the claim stops arriving and sessions
    /// stop being issued. Without it, a missing policy is invisible to the platform.
    /// </remarks>
    public string RequiredAuthContextId { get; set; } = string.Empty;
}

/// <summary>
/// The control-plane use case that turns an authenticated, authorised request into a research
/// session: it checks role, that the token is device-bound, the Conditional Access authentication
/// context when one is required, and region selectability, signs the
/// endpoint's CSR into a short-lived session certificate, records the session, and audits the
/// outcome. Renewal and termination re-run the same authorisation. All decisions are made here,
/// server-side; nothing trusts the request body beyond the CSR (whose signature is verified).
/// </summary>
public sealed class SessionService(
    RegionPolicy regionPolicy,
    SessionCertificateIssuer certificateIssuer,
    ISessionRepository repository,
    IEgressDirectory egressDirectory,
    ISessionAuditSink audit,
    IOptions<SessionServiceOptions> options,
    TimeProvider timeProvider)
{
    private readonly RegionPolicy _regionPolicy = regionPolicy ?? throw new ArgumentNullException(nameof(regionPolicy));
    private readonly SessionCertificateIssuer _certificateIssuer =
        certificateIssuer ?? throw new ArgumentNullException(nameof(certificateIssuer));

    private readonly ISessionRepository _repository = repository ?? throw new ArgumentNullException(nameof(repository));
    private readonly IEgressDirectory _egressDirectory =
        egressDirectory ?? throw new ArgumentNullException(nameof(egressDirectory));

    private readonly ISessionAuditSink _audit = audit ?? throw new ArgumentNullException(nameof(audit));
    private readonly SessionServiceOptions _options =
        (options ?? throw new ArgumentNullException(nameof(options))).Value;

    private readonly TimeProvider _timeProvider = timeProvider ?? throw new ArgumentNullException(nameof(timeProvider));

    public async Task<SessionGrant> IssueAsync(
        SessionPrincipal principal, SessionIssueRequest request, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(principal);
        ArgumentNullException.ThrowIfNull(request);

        await AuthoriseAsync(principal, request.Region, cancellationToken).ConfigureAwait(false);

        var egress = _egressDirectory.Resolve(request.Region)
            ?? throw new SessionAuthorizationException(
                SessionDenialReason.RegionNotSelectable, $"No egress endpoint for region '{request.Region}'.");

        var now = _timeProvider.GetUtcNow();
        var sessionId = Guid.NewGuid();

        using var certificate = IssueCertificate(sessionId, request.CertificateSigningRequest, now);
        var session = ResearchSession.Issue(
            sessionId,
            principal.UserObjectId,
            principal.UserPrincipalName,
            principal.DeviceId,
            request.Region,
            now,
            _options.LeaseTtl,
            certificate.SerialNumber);

        // Audit first: if the event cannot be recorded, the session is never created, so no
        // session can exist that the trail does not know about (EVENT_SCHEMAS §6).
        await _audit.SessionStartedAsync(session, cancellationToken).ConfigureAwait(false);
        await _repository.AddAsync(session, cancellationToken).ConfigureAwait(false);

        return ToGrant(session, certificate, egress);
    }

    public async Task<SessionGrant> RenewAsync(
        SessionPrincipal principal, Guid sessionId, byte[] csr, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(principal);
        ArgumentNullException.ThrowIfNull(csr);

        var session = await RequireOwnedSessionAsync(principal, sessionId, cancellationToken).ConfigureAwait(false);
        await AuthoriseAsync(principal, session.Region, cancellationToken).ConfigureAwait(false);

        var egress = _egressDirectory.Resolve(session.Region)
            ?? throw new SessionAuthorizationException(
                SessionDenialReason.RegionNotSelectable, $"No egress endpoint for region '{session.Region}'.");

        var now = _timeProvider.GetUtcNow();
        using var certificate = IssueCertificate(session.Id, csr, now);
        session.Renew(now, _options.LeaseTtl, certificate.SerialNumber);

        await _audit.SessionRenewedAsync(session, cancellationToken).ConfigureAwait(false);
        await _repository.UpdateAsync(session, cancellationToken).ConfigureAwait(false);

        return ToGrant(session, certificate, egress);
    }

    public async Task EndAsync(
        SessionPrincipal principal, Guid sessionId, SessionEndReason reason, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(principal);

        var session = await RequireOwnedSessionAsync(principal, sessionId, cancellationToken).ConfigureAwait(false);
        session.End(_timeProvider.GetUtcNow(), reason);

        await _audit.SessionEndedAsync(session, cancellationToken).ConfigureAwait(false);
        await _repository.UpdateAsync(session, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Ids of sessions whose lease has elapsed. Split from <see cref="ExpireAsync"/> so the caller
    /// can close each one in its own unit of work, for the same reason the suppression sweep does:
    /// a rejected commit leaves the failed change tracked, and every later commit in the same sweep
    /// then re-attempts it.
    /// </summary>
    public async Task<IReadOnlyList<Guid>> ListLapsedForExpiryAsync(CancellationToken cancellationToken)
    {
        var lapsed = await _repository
            .ListLapsedAsync(_timeProvider.GetUtcNow(), _options.ExpirySweepBatchSize, cancellationToken)
            .ConfigureAwait(false);

        return [.. lapsed.Select(s => s.Id)];
    }

    /// <summary>
    /// Closes one lapsed session. Returns false when it is no longer lapsed-and-active — the
    /// analyst ended it, or another instance got there first — which is an ordinary race, not a
    /// failure.
    /// </summary>
    public async Task<bool> ExpireAsync(Guid sessionId, CancellationToken cancellationToken)
    {
        var session = await _repository.FindAsync(sessionId, cancellationToken).ConfigureAwait(false);
        if (session is null || !session.TryExpire(_timeProvider.GetUtcNow()))
        {
            return false;
        }

        // Mutation before the audit write, then one commit: appending the event flushes the session
        // change with it, so the terminal event and the state it describes land together or not at
        // all. Writing the event first would commit it alone and leave the session for a second
        // commit that can fail.
        await _audit.SessionEndedAsync(session, cancellationToken).ConfigureAwait(false);
        await _repository.UpdateAsync(session, cancellationToken).ConfigureAwait(false);
        return true;
    }

    private async Task AuthoriseAsync(SessionPrincipal principal, string region, CancellationToken cancellationToken)
    {
        if (!principal.Roles.Contains(_options.AnalystRole))
        {
            await DenyAsync(principal, SessionDenialReason.NotAuthorisedRole, region, cancellationToken)
                .ConfigureAwait(false);
        }

        if (!principal.DeviceBound)
        {
            await DenyAsync(principal, SessionDenialReason.DeviceNotBound, region, cancellationToken)
                .ConfigureAwait(false);
        }

        // When configured, the token must also prove that a Conditional Access policy bound to this
        // authentication context was satisfied — which is what actually evidences Intune compliance.
        if (!string.IsNullOrWhiteSpace(_options.RequiredAuthContextId)
            && principal.AuthenticationContexts?.Contains(_options.RequiredAuthContextId) != true)
        {
            await DenyAsync(principal, SessionDenialReason.AuthenticationContextRequired, region, cancellationToken)
                .ConfigureAwait(false);
        }

        if (!_regionPolicy.IsSelectable(region))
        {
            await DenyAsync(principal, SessionDenialReason.RegionNotSelectable, region, cancellationToken)
                .ConfigureAwait(false);
        }
    }

    private async Task DenyAsync(
        SessionPrincipal principal, SessionDenialReason reason, string? region, CancellationToken cancellationToken)
    {
        await _audit.AuthorizationDeniedAsync(principal, reason, region, cancellationToken).ConfigureAwait(false);
        throw new SessionAuthorizationException(reason);
    }

    private async Task<ResearchSession> RequireOwnedSessionAsync(
        SessionPrincipal principal, Guid sessionId, CancellationToken cancellationToken)
    {
        var session = await _repository.FindAsync(sessionId, cancellationToken).ConfigureAwait(false);
        if (session is null)
        {
            throw new SessionAuthorizationException(SessionDenialReason.SessionNotFound);
        }

        if (!string.Equals(session.UserObjectId, principal.UserObjectId, StringComparison.Ordinal))
        {
            // Do not reveal existence to a non-owner: audit and deny.
            await _audit.AuthorizationDeniedAsync(principal, SessionDenialReason.NotSessionOwner, session.Region, cancellationToken)
                .ConfigureAwait(false);
            throw new SessionAuthorizationException(SessionDenialReason.NotSessionOwner);
        }

        return session;
    }

    private X509Certificate2 IssueCertificate(Guid sessionId, byte[] csr, DateTimeOffset now)
    {
        try
        {
            return _certificateIssuer.IssueFromCsr(sessionId, csr, now, _options.LeaseTtl);
        }
        catch (Exception ex) when (ex is System.Security.Cryptography.CryptographicException or ArgumentException)
        {
            throw new SessionAuthorizationException(
                SessionDenialReason.InvalidCertificateRequest, "Invalid certificate signing request.");
        }
    }

    private static SessionGrant ToGrant(ResearchSession session, X509Certificate2 certificate, EgressEndpointInfo egress) =>
        new(
            session.Id,
            certificate.Export(X509ContentType.Cert),
            session.CertificateSerialNumber,
            session.Region,
            egress,
            session.LeaseExpiresAt,
            session.Mode);
}
