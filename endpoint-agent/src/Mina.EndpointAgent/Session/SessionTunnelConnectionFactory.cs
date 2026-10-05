using Mina.EndpointAgent.Proxy;

namespace Mina.EndpointAgent.Session;

/// <summary>
/// Routes each proxied request through whatever session is live at that moment. With no session it
/// throws, and the loopback proxy turns that into an HTTP error for the browser — never a direct
/// connection. This is the single choke point that makes "no session" mean "no browsing"
/// (FR-007, AC-004).
/// </summary>
public sealed class SessionTunnelConnectionFactory(ResearchSessionManager sessions) : ITunnelConnectionFactory
{
    private readonly ResearchSessionManager _sessions = sessions ?? throw new ArgumentNullException(nameof(sessions));

    public Task<Stream> ConnectAsync(ConnectTarget target, CancellationToken cancellationToken)
    {
        var session = _sessions.Current
            ?? throw new NoActiveSessionException(
                "No active research session; refusing to connect rather than using ordinary egress.");

        return session.Tunnel.ConnectAsync(target, cancellationToken);
    }
}

/// <summary>Raised when browsing is attempted with no live research session.</summary>
public sealed class NoActiveSessionException : Exception
{
    public NoActiveSessionException()
    {
    }

    public NoActiveSessionException(string message)
        : base(message)
    {
    }

    public NoActiveSessionException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}
