using System.Text.Json;
using Microsoft.Extensions.Options;
using Mina.ControlPlane.Domain.Audit;

namespace Mina.ControlPlane.Application.Audit;

/// <summary>Audit configuration.</summary>
public sealed class AuditOptions
{
    public const string Section = "Mina:Audit";

    /// <summary>Environment name stamped on every event (dev/test/prod).</summary>
    public string Environment { get; set; } = "dev";

    /// <summary>How many times to retry when another writer takes the sequence first.</summary>
    public int MaxAppendAttempts { get; set; } = 5;
}

/// <summary>What to record, before it is placed in the chain.</summary>
public sealed record AuditEventDraft(
    string EventType,
    AuditSeverity Severity,
    AuditComponent Component,
    string? Region = null,
    string? UserObjectId = null,
    string? UserPrincipalName = null,
    string? DeviceId = null,
    Guid? SessionId = null,
    object? Data = null);

/// <summary>Raised when an event could not be recorded, so its action must not proceed.</summary>
public sealed class AuditWriteException : Exception
{
    public AuditWriteException(string message)
        : base(message)
    {
    }

    public AuditWriteException(string message, Exception innerException)
        : base(message, innerException)
    {
    }

    public AuditWriteException()
        : base("The audit event could not be recorded.")
    {
    }
}

/// <summary>
/// Places events into the audit chain.
/// </summary>
/// <remarks>
/// Callers write the event *before* performing the action it describes, and a failure here throws
/// rather than being swallowed — so a governance action cannot proceed unlogged (EVENT_SCHEMAS §6).
/// The deliberate consequence is that a failure between the two can leave an event for an action
/// that did not complete: over-recording is the safe direction for an audit trail, under-recording
/// is not.
/// </remarks>
public sealed class AuditWriter(IAuditEventStore store, IOptions<AuditOptions> options, TimeProvider clock)
{
    private static readonly JsonSerializerOptions DataSerializerOptions = new(JsonSerializerDefaults.Web);

    private readonly IAuditEventStore _store = store ?? throw new ArgumentNullException(nameof(store));
    private readonly AuditOptions _options = (options ?? throw new ArgumentNullException(nameof(options))).Value;
    private readonly TimeProvider _clock = clock ?? throw new ArgumentNullException(nameof(clock));

    public async Task<AuditEvent> WriteAsync(AuditEventDraft draft, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(draft);

        var data = draft.Data is null ? "{}" : JsonSerializer.Serialize(draft.Data, DataSerializerOptions);
        var attempts = Math.Max(1, _options.MaxAppendAttempts);

        for (var attempt = 1; attempt <= attempts; attempt++)
        {
            AuditChainTip tip;
            try
            {
                tip = await _store.GetTipAsync(cancellationToken).ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                // Reading the tip is as much a part of writing the event as the insert is: if the
                // chain cannot be read, the event was not recorded and the caller must treat that
                // the same way. Leaving this outside the guard meant a store that could not be read
                // surfaced as a raw provider exception, which no caller — and none of the tests
                // asserting the fail-closed property — recognises as an audit failure.
                throw new AuditWriteException(
                    $"Could not read the audit chain tip to append '{draft.EventType}'.", ex);
            }

            var auditEvent = AuditEvent.Append(
                tip.Sequence + 1,
                tip.Hash,
                draft.EventType,
                draft.Severity,
                draft.Component,
                _clock.GetUtcNow(),
                _options.Environment,
                draft.Region,
                draft.UserObjectId,
                draft.UserPrincipalName,
                draft.DeviceId,
                draft.SessionId,
                data);

            try
            {
                await _store.AppendAsync(auditEvent, cancellationToken).ConfigureAwait(false);
                return auditEvent;
            }
            catch (AuditSequenceConflictException conflict)
            {
                if (attempt == attempts)
                {
                    // Callers should not have to reason about sequence contention: what matters to
                    // them is that the event was not recorded, so the action must not proceed.
                    throw new AuditWriteException(
                        $"Could not append '{draft.EventType}' to the audit chain after {attempts} attempts.",
                        conflict);
                }

                // Another writer took this position; re-read the tip and chain onto the new one.
            }
            catch (Exception ex) when (ex is not (AuditWriteException or OperationCanceledException))
            {
                // Anything that is not contention is a real failure of the store, and retrying it
                // would only delay the refusal. Surfacing every such failure as one type is what
                // lets callers — and the tests that prove "no action proceeds unlogged" — treat
                // "the event was not recorded" as a single condition.
                throw new AuditWriteException(
                    $"Could not append '{draft.EventType}' to the audit chain.", ex);
            }
        }

        throw new AuditWriteException($"Could not append '{draft.EventType}' to the audit chain.");
    }
}
