namespace Mina.ControlPlane.Domain.Telemetry;

/// <summary>
/// One connection an egress node made on a session's behalf, recorded at hostname granularity
/// (`mina.hostname.v1`). This is data class C3 in LOGGING_AND_PRIVACY: destinations, never URL
/// paths, because nothing in this design decrypts TLS.
/// </summary>
public sealed class HostnameObservation
{
    /// <summary>Longest DNS name, and the storage column's width.</summary>
    public const int MaxHostnameLength = 253;

    private HostnameObservation(
        Guid id,
        Guid sessionId,
        string region,
        DateTimeOffset occurredAt,
        string hostname,
        int port,
        long bytesUp,
        long bytesDown,
        int durationMs)
    {
        Id = id;
        SessionId = sessionId;
        Region = region;
        OccurredAt = occurredAt;
        Hostname = hostname;
        Port = port;
        BytesUp = bytesUp;
        BytesDown = bytesDown;
        DurationMs = durationMs;
    }

    public Guid Id { get; }

    public Guid SessionId { get; }

    public string Region { get; }

    public DateTimeOffset OccurredAt { get; }

    public string Hostname { get; }

    public int Port { get; }

    public long BytesUp { get; }

    public long BytesDown { get; }

    public int DurationMs { get; }

    public static HostnameObservation Record(
        Guid sessionId,
        string region,
        DateTimeOffset occurredAt,
        string hostname,
        int port,
        long bytesUp,
        long bytesDown,
        int durationMs)
    {
        if (sessionId == Guid.Empty)
        {
            throw new ArgumentException("A session id is required.", nameof(sessionId));
        }

        ArgumentException.ThrowIfNullOrWhiteSpace(region);
        ArgumentException.ThrowIfNullOrWhiteSpace(hostname);
        if (hostname.Length > MaxHostnameLength)
        {
            throw new ArgumentException(
                $"A hostname cannot exceed {MaxHostnameLength} characters.", nameof(hostname));
        }

        return new HostnameObservation(
            Guid.NewGuid(), sessionId, region, occurredAt, hostname, port,
            Math.Max(0, bytesUp), Math.Max(0, bytesDown), Math.Max(0, durationMs));
    }
}

/// <summary>
/// Traffic on a suppressed session, reduced to counts (`mina.hostname.suppressed.v1`). Suppression
/// removes the destinations, not the accountability: how much a session did is still recorded, and
/// the session, identity, device and approval trail remain in the audit store regardless
/// (ADR-0003 — there are no permanent logging exemptions).
/// </summary>
public sealed class SuppressedTrafficSummary
{
    private SuppressedTrafficSummary(
        Guid id, Guid sessionId, string region, DateTimeOffset intervalStart, int connectionCount, long bytesTotal)
    {
        Id = id;
        SessionId = sessionId;
        Region = region;
        IntervalStart = intervalStart;
        ConnectionCount = connectionCount;
        BytesTotal = bytesTotal;
    }

    public Guid Id { get; }

    public Guid SessionId { get; }

    public string Region { get; }

    public DateTimeOffset IntervalStart { get; }

    public int ConnectionCount { get; private set; }

    public long BytesTotal { get; private set; }

    public static SuppressedTrafficSummary Record(
        Guid sessionId, string region, DateTimeOffset intervalStart, int connectionCount, long bytesTotal)
    {
        if (sessionId == Guid.Empty)
        {
            throw new ArgumentException("A session id is required.", nameof(sessionId));
        }

        ArgumentException.ThrowIfNullOrWhiteSpace(region);
        return new SuppressedTrafficSummary(
            Guid.NewGuid(), sessionId, region, intervalStart, Math.Max(0, connectionCount), Math.Max(0, bytesTotal));
    }

    public void Add(int connections, long bytes)
    {
        ConnectionCount += Math.Max(0, connections);
        BytesTotal += Math.Max(0, bytes);
    }
}
