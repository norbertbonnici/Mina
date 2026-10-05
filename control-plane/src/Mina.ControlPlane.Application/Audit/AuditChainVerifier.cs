using Mina.ControlPlane.Domain.Audit;

namespace Mina.ControlPlane.Application.Audit;

/// <summary>
/// Walks the audit chain and reports the first place it stops adding up.
/// </summary>
/// <remarks>
/// Three things are checked per event: that its recorded hash still matches its own contents (so an
/// altered field shows up), that it links to its predecessor's hash (so a replaced event shows up),
/// and that sequences are contiguous (so a deleted event shows up as a gap rather than passing
/// unnoticed).
/// </remarks>
public sealed class AuditChainVerifier(IAuditEventStore store)
{
    private const int PageSize = 500;

    private readonly IAuditEventStore _store = store ?? throw new ArgumentNullException(nameof(store));

    public async Task<AuditChainVerification> VerifyAsync(CancellationToken cancellationToken)
    {
        var expectedSequence = 0L;
        var expectedPreviousHash = AuditEvent.GenesisHash;
        var verified = 0L;

        while (true)
        {
            var page = await _store.ReadAsync(expectedSequence, PageSize, cancellationToken).ConfigureAwait(false);
            if (page.Count == 0)
            {
                return new AuditChainVerification(verified, null, null);
            }

            foreach (var auditEvent in page)
            {
                if (auditEvent.Sequence != expectedSequence)
                {
                    return new AuditChainVerification(
                        verified, expectedSequence,
                        $"Expected sequence {expectedSequence} but found {auditEvent.Sequence}: an event is missing.");
                }

                if (!string.Equals(auditEvent.PreviousHash, expectedPreviousHash, StringComparison.Ordinal))
                {
                    return new AuditChainVerification(
                        verified, auditEvent.Sequence,
                        "The event does not link to its predecessor: the chain was re-written or re-ordered.");
                }

                if (!string.Equals(auditEvent.RecomputeHash(), auditEvent.Hash, StringComparison.Ordinal))
                {
                    return new AuditChainVerification(
                        verified, auditEvent.Sequence,
                        "The event's contents do not match its recorded hash: it was altered after being written.");
                }

                expectedPreviousHash = auditEvent.Hash;
                expectedSequence++;
                verified++;
            }
        }
    }
}
