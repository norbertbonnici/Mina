namespace Mina.EndpointAgent.Proxy;

/// <summary>
/// Opens a tunnelled duplex stream to a research target through the Azure egress. Every path to
/// the internet for the research browser goes through an implementation of this interface; there
/// is no DIRECT alternative, which is what makes the loopback proxy fail closed (ARCHITECTURE §5).
/// </summary>
public interface ITunnelConnectionFactory
{
    /// <summary>
    /// Establishes a tunnel to <paramref name="target"/>. Returns a duplex stream carrying the
    /// tunnelled bytes, or throws if the tunnel cannot be established (no session, egress
    /// unreachable, authentication rejected) — callers must translate a throw into a proxy
    /// error, never a direct connection.
    /// </summary>
    Task<Stream> ConnectAsync(ConnectTarget target, CancellationToken cancellationToken);
}
