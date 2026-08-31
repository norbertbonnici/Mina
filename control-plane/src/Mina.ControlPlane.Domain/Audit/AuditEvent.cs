using System.Globalization;
using System.Security.Cryptography;
using System.Text;

namespace Mina.ControlPlane.Domain.Audit;

/// <summary>Severity as carried in the audit envelope (EVENT_SCHEMAS §2).</summary>
public enum AuditSeverity
{
    Info,
    Notice,
    Warning,
    High,
    Critical,
}

/// <summary>Which part of the platform raised an event.</summary>
public enum AuditComponent
{
    ControlPlane,
    EgressNode,
    EndpointAgent,
    ManagementUi,
    Platform,
}

/// <summary>
/// One governance event, in the envelope of EVENT_SCHEMAS §2 and linked into a hash chain.
/// </summary>
/// <remarks>
/// Each event carries the hash of the one before it, so altering or removing a record breaks every
/// link after it. That does not prevent tampering — a writer with sufficient privilege could rewrite
/// the whole chain — which is why the chain is periodically anchored by exporting a range and its
/// hash to write-once storage. Together they make silent alteration detectable, which is what
/// THREAT_MODEL asks of the audit trail.
/// </remarks>
public sealed class AuditEvent
{
    /// <summary>The hash a chain starts from.</summary>
    public const string GenesisHash = "0000000000000000000000000000000000000000000000000000000000000000";

    private AuditEvent(
        Guid id,
        long sequence,
        string eventType,
        AuditSeverity severity,
        AuditComponent component,
        DateTimeOffset occurredAt,
        string environment,
        string? region,
        string? userObjectId,
        string? userPrincipalName,
        string? deviceId,
        Guid? sessionId,
        string data,
        string previousHash,
        string hash)
    {
        Id = id;
        Sequence = sequence;
        EventType = eventType;
        Severity = severity;
        Component = component;
        OccurredAt = occurredAt;
        Environment = environment;
        Region = region;
        UserObjectId = userObjectId;
        UserPrincipalName = userPrincipalName;
        DeviceId = deviceId;
        SessionId = sessionId;
        Data = data;
        PreviousHash = previousHash;
        Hash = hash;
    }

    public Guid Id { get; }

    /// <summary>Position in the chain. Unique, and gapless in an intact trail.</summary>
    public long Sequence { get; }

    public string EventType { get; }

    public AuditSeverity Severity { get; }

    public AuditComponent Component { get; }

    public DateTimeOffset OccurredAt { get; }

    public string Environment { get; }

    public string? Region { get; }

    public string? UserObjectId { get; }

    public string? UserPrincipalName { get; }

    public string? DeviceId { get; }

    public Guid? SessionId { get; }

    /// <summary>Event-specific payload as JSON. Never URL or hostname content (see the sinks).</summary>
    public string Data { get; }

    public string PreviousHash { get; }

    public string Hash { get; }

    public static AuditEvent Append(
        long sequence,
        string previousHash,
        string eventType,
        AuditSeverity severity,
        AuditComponent component,
        DateTimeOffset occurredAt,
        string environment,
        string? region = null,
        string? userObjectId = null,
        string? userPrincipalName = null,
        string? deviceId = null,
        Guid? sessionId = null,
        string data = "{}")
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(eventType);
        ArgumentException.ThrowIfNullOrWhiteSpace(environment);
        ArgumentException.ThrowIfNullOrWhiteSpace(previousHash);
        ArgumentOutOfRangeException.ThrowIfNegative(sequence);

        var id = Guid.NewGuid();
        var hash = ComputeHash(
            id, sequence, eventType, severity, component, occurredAt, environment, region,
            userObjectId, userPrincipalName, deviceId, sessionId, data, previousHash);

        return new AuditEvent(
            id, sequence, eventType, severity, component, occurredAt, environment, region,
            userObjectId, userPrincipalName, deviceId, sessionId, data, previousHash, hash);
    }

    /// <summary>Recomputes this event's hash from its own fields, for chain verification.</summary>
    public string RecomputeHash() => ComputeHash(
        Id, Sequence, EventType, Severity, Component, OccurredAt, Environment, Region,
        UserObjectId, UserPrincipalName, DeviceId, SessionId, Data, PreviousHash);

    /// <summary>Field separator; a control character none of the joined values can contain.</summary>
    private const char Separator = '\u001F';

    /// <summary>
    /// Hashes a canonical rendering of the event. Fields are written in a fixed order with explicit
    /// separators rather than serialised as JSON, so the digest cannot shift because a serialiser
    /// changed its property order or formatting.
    /// </summary>

    private static string ComputeHash(
        Guid id,
        long sequence,
        string eventType,
        AuditSeverity severity,
        AuditComponent component,
        DateTimeOffset occurredAt,
        string environment,
        string? region,
        string? userObjectId,
        string? userPrincipalName,
        string? deviceId,
        Guid? sessionId,
        string data,
        string previousHash)
    {
        var canonical = new StringBuilder()
            .Append(id.ToString("D")).Append(Separator)
            .Append(sequence.ToString(CultureInfo.InvariantCulture)).Append(Separator)
            .Append(eventType).Append(Separator)
            .Append(severity.ToString()).Append(Separator)
            .Append(component.ToString()).Append(Separator)
            .Append(occurredAt.ToUniversalTime().ToString("O", CultureInfo.InvariantCulture)).Append(Separator)
            .Append(environment).Append(Separator)
            .Append(region ?? string.Empty).Append(Separator)
            .Append(userObjectId ?? string.Empty).Append(Separator)
            .Append(userPrincipalName ?? string.Empty).Append(Separator)
            .Append(deviceId ?? string.Empty).Append(Separator)
            .Append(sessionId?.ToString("D") ?? string.Empty).Append(Separator)
            .Append(data).Append(Separator)
            .Append(previousHash)
            .ToString();

        return Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(canonical)));
    }
}
