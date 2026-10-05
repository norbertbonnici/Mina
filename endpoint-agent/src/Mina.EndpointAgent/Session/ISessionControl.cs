namespace Mina.EndpointAgent.Session;

/// <summary>
/// What a live research session tells the rest of the agent about itself. Deliberately narrow: the
/// tray reports these four facts and nothing else, and the tunnel and key material behind the
/// session are not reachable through this view.
/// </summary>
public interface IResearchSession
{
    Guid SessionId { get; }

    string Region { get; }

    /// <summary>Logging mode as stamped by the control plane at issuance.</summary>
    string Mode { get; }

    DateTimeOffset LeaseExpiresAt { get; }
}

/// <summary>
/// The slice of the session lifecycle the tray needs: read the current session, and end it. There
/// is no "establish" here on purpose — starting a session is the worker's decision, taken from the
/// runtime state, so a tray command can ask for one but cannot drive one directly.
/// </summary>
public interface ISessionControl
{
    IResearchSession? Current { get; }

    Task EndAsync(CancellationToken cancellationToken);
}
