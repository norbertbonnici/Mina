namespace Mina.EndpointAgent.Ipc;

/// <summary>
/// What the pipe server hands each request to. An interface so the transport — framing, ACLs,
/// timeouts, misbehaving peers — can be tested against a control that does nothing, and the
/// control's rules can be tested without a pipe.
/// </summary>
public interface ITrayControl
{
    /// <summary>
    /// Runs one validated tray operation. <paramref name="clientIdentity"/> is the pipe peer's
    /// account where the platform can report it, for the agent's own log.
    /// </summary>
    Task<TrayResponse> ExecuteAsync(TrayRequest request, string? clientIdentity, CancellationToken cancellationToken);
}
