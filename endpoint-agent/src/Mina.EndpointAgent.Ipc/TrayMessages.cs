using System.Text.Json.Serialization;

namespace Mina.EndpointAgent.Ipc;

/// <summary>
/// One request from the tray. A flat shape with optional fields, rather than a polymorphic
/// hierarchy: the agent switches on <see cref="Op"/> and validates the fields that operation needs,
/// so an unexpected combination is refused rather than deserialised into something meaningful.
/// </summary>
public sealed record TrayRequest
{
    /// <summary>One of <see cref="TrayOperations"/>.</summary>
    public string Op { get; init; } = TrayOperations.Status;

    /// <summary>Region for <see cref="TrayOperations.SelectRegion"/>.</summary>
    public string? Region { get; init; }

    /// <summary>Case or request reference for <see cref="TrayOperations.RequestSensitive"/>.</summary>
    public string? JustificationReference { get; init; }

    /// <summary>Requested suppression window, in minutes.</summary>
    public int? Minutes { get; init; }

    /// <summary>Entra access token for <see cref="TrayOperations.SubmitAccessToken"/>.</summary>
    public string? AccessToken { get; init; }

    /// <summary>
    /// When <see cref="AccessToken"/> expires. The agent will not use a token past this, so a tray
    /// that never refreshes shows up as the same "waiting for sign-in" state as one that never
    /// signed in at all, rather than a silently stale credential.
    /// </summary>
    public DateTimeOffset? AccessTokenExpiresOn { get; init; }
}

/// <summary>
/// The agent's answer. Every successful operation carries the resulting <see cref="Status"/>, so
/// the tray renders from one authority instead of predicting what its own command did.
/// </summary>
public sealed record TrayResponse
{
    public bool Ok { get; init; }

    /// <summary>A sentence for the analyst when <see cref="Ok"/> is false.</summary>
    public string? Error { get; init; }

    /// <summary>One of <see cref="TrayErrorCodes"/>, for the tray to branch on.</summary>
    public string? Code { get; init; }

    public AgentStatusDto? Status { get; init; }

    public static TrayResponse Success(AgentStatusDto status) => new() { Ok = true, Status = status };

    public static TrayResponse Failure(string code, string error, AgentStatusDto? status = null) =>
        new() { Ok = false, Code = code, Error = error, Status = status };
}

/// <summary>
/// Everything the tray is allowed to know. Session key material, the client certificate and the
/// Entra token are deliberately absent: the pipe is reachable by the interactive user, so anything
/// crossing it is readable by any code running as that user (SR-006).
/// </summary>
public sealed record AgentStatusDto
{
    /// <summary>One of <see cref="ProtectedPathStates"/>.</summary>
    public string State { get; init; } = ProtectedPathStates.Stopped;

    /// <summary>Region the agent is using, or will use on the next attempt.</summary>
    public string Region { get; init; } = string.Empty;

    /// <summary>"Normal" or "Sensitive", as reported by the control plane — never asserted here.</summary>
    public string Mode { get; init; } = "Normal";

    public Guid? SessionId { get; init; }

    public DateTimeOffset? LeaseExpiresAt { get; init; }

    /// <summary>Loopback port the research browser is pinned to; 0 when the path is closed.</summary>
    public int ProxyPort { get; init; }

    /// <summary>Why the path is not up. A platform fact — never a destination the analyst visited.</summary>
    public string? Reason { get; init; }

    public int ConsecutiveFailures { get; init; }

    /// <summary>When the agent will try again, so the tray can count down instead of guessing.</summary>
    public DateTimeOffset? NextAttemptAt { get; init; }

    /// <summary>Regions the control plane says this analyst may pick (AC-008).</summary>
    public IReadOnlyList<string> SelectableRegions { get; init; } = [];

    /// <summary>The suppression request in flight, if any.</summary>
    public SensitiveRequestDto? Sensitive { get; init; }

    /// <summary>
    /// Longest suppression window the agent will forward. Reported rather than compiled into the
    /// tray so the ceiling lives in one place; the control plane holds the real policy behind it.
    /// </summary>
    public int MaxSensitiveMinutes { get; init; }

    /// <summary>When the agent took this reading, so a stale panel is detectable.</summary>
    public DateTimeOffset ObservedAt { get; init; }

    /// <summary>
    /// Set when the control plane answered a session request with an `insufficient_claims`
    /// challenge the token currently held could not satisfy (ARCHITECTURE §4) — the raw
    /// claims-challenge JSON the tray must pass to MSAL's <c>.WithClaims(...)</c> on its next
    /// acquisition. Null when nothing is outstanding.
    /// </summary>
    public string? RequiredClaims { get; init; }
}

/// <summary>A sensitive-session request as the requesting analyst sees it.</summary>
public sealed record SensitiveRequestDto
{
    public Guid RequestId { get; init; }

    /// <summary>Control-plane state: Requested, Approved, Denied, Cancelled, ActiveSuppressed, Ended.</summary>
    public string State { get; init; } = string.Empty;

    public string JustificationReference { get; init; } = string.Empty;

    public int RequestedMinutes { get; init; }

    /// <summary>Who decided it. Recorded whatever the outcome — approvals are never anonymous.</summary>
    public string? ApproverUpn { get; init; }

    public DateTimeOffset? ApprovedAt { get; init; }

    /// <summary>When suppression ends. Reaching it terminates the session (ADR-0003).</summary>
    public DateTimeOffset? ExpiresAt { get; init; }

    public DateTimeOffset? ActivatedAt { get; init; }
}

/// <summary>
/// Source-generated serialisation for the pipe. Reflection-free so the tray and agent can be
/// published trimmed, and so the shape of the contract is fixed at compile time.
/// </summary>
[JsonSourceGenerationOptions(
    PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase,
    DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull)]
[JsonSerializable(typeof(TrayRequest))]
[JsonSerializable(typeof(TrayResponse))]
public sealed partial class TrayJsonContext : JsonSerializerContext;
