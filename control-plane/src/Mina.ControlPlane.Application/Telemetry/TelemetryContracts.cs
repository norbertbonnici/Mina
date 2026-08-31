namespace Mina.ControlPlane.Application.Telemetry;

/// <summary>
/// One connection an egress node reports. <paramref name="Hostname"/> is null when the node is
/// correctly withholding destinations for a suppressed session — it then contributes only to
/// aggregate counts.
/// </summary>
public sealed record TelemetryItem(
    Guid SessionId,
    DateTimeOffset OccurredAt,
    string? Hostname,
    int Port,
    long BytesUp,
    long BytesDown,
    int DurationMs);

/// <summary>A batch of observations from one egress node.</summary>
public sealed record TelemetryBatch(string Region, IReadOnlyList<TelemetryItem> Items);

/// <summary>What the control plane did with a batch.</summary>
/// <param name="Recorded">Hostname observations stored.</param>
/// <param name="Aggregated">Items reduced to counts because the session is suppressed.</param>
/// <param name="Unattributable">Items dropped because their session is unknown.</param>
/// <param name="SuppressionMismatches">
/// Items that arrived carrying a hostname for a session the control plane has suppressed. Each one
/// means a node is still collecting what it was told to stop collecting (threat N5).
/// </param>
public sealed record TelemetryIngestResult(
    int Recorded, int Aggregated, int Unattributable, int SuppressionMismatches);

/// <summary>
/// A session as an egress node needs to see it: whether to admit it, and whether to withhold
/// destinations for it.
/// </summary>
public sealed record NodeSessionEntry(Guid SessionId, bool Suppressed, DateTimeOffset LeaseExpiresAt);

/// <summary>Raised when a node-facing operation is refused.</summary>
public sealed class NodeAuthorizationException : Exception
{
    public NodeAuthorizationException()
        : base("The caller is not an authorised egress node.")
    {
    }

    public NodeAuthorizationException(string message)
        : base(message)
    {
    }

    public NodeAuthorizationException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}
