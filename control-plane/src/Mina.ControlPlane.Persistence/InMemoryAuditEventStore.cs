using Mina.ControlPlane.Domain.Audit;

namespace Mina.ControlPlane.Persistence;

/// <summary>
/// In-memory audit store for local development. Appends are serialised so the chain stays
/// well-formed; nothing here is durable, which is why the API warns when it is in use.
/// </summary>
public sealed class InMemoryAuditEventStore : IAuditEventStore
{
    private readonly List<AuditEvent> _events = [];
    private readonly Lock _gate = new();

    public Task<AuditChainTip> GetTipAsync(CancellationToken cancellationToken)
    {
        lock (_gate)
        {
            return Task.FromResult(_events.Count == 0
                ? AuditChainTip.Empty
                : new AuditChainTip(_events[^1].Sequence, _events[^1].Hash));
        }
    }

    public Task AppendAsync(AuditEvent auditEvent, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(auditEvent);
        lock (_gate)
        {
            if (_events.Exists(e => e.Sequence == auditEvent.Sequence))
            {
                throw new AuditSequenceConflictException();
            }

            _events.Add(auditEvent);
        }

        return Task.CompletedTask;
    }

    public Task<IReadOnlyList<AuditEvent>> ReadAsync(
        long fromSequence, int limit, CancellationToken cancellationToken)
    {
        lock (_gate)
        {
            return Task.FromResult<IReadOnlyList<AuditEvent>>(
                [.. _events.Where(e => e.Sequence >= fromSequence).OrderBy(e => e.Sequence).Take(limit)]);
        }
    }

    public Task<IReadOnlyList<AuditEvent>> ReadRecentAsync(int limit, CancellationToken cancellationToken)
    {
        lock (_gate)
        {
            return Task.FromResult<IReadOnlyList<AuditEvent>>(
                [.. _events.OrderByDescending(e => e.Sequence).Take(limit)]);
        }
    }
}
