using System.Net;
using System.Net.Sockets;

namespace Mina.EndpointAgent.Proxy;

/// <summary>
/// Decides whether a process connecting to the loopback proxy is allowed to use it. This is the
/// control that stops the loopback listener becoming a local open proxy for other endpoint
/// processes (THREAT_MODEL B1 spoof).
/// </summary>
public interface IPeerAuthorizer
{
    ValueTask<bool> AuthorizeAsync(Socket clientSocket, CancellationToken cancellationToken);
}

/// <summary>
/// PoC authorizer (M1): admits connections that originate from the loopback interface. The
/// authoritative check — resolve the peer PID to its image path and verify it is the managed
/// research browser running the research user-data-dir — is Windows-specific and lands with the
/// hardened service in M2-4 (ARCHITECTURE §3.1). This implementation is deliberately not that
/// control and must not be shipped as if it were.
/// </summary>
public sealed class LoopbackPeerAuthorizer : IPeerAuthorizer
{
    public ValueTask<bool> AuthorizeAsync(Socket clientSocket, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(clientSocket);
        var authorized = clientSocket.RemoteEndPoint is IPEndPoint ep && IPAddress.IsLoopback(ep.Address);
        return ValueTask.FromResult(authorized);
    }
}
