using System.Security.Cryptography;
using System.Text.Json;
using Mina.ControlPlane.Domain.Audit;

namespace Mina.ControlPlane.Application.Audit;

/// <summary>What comparing the chain against its anchors in write-once storage found.</summary>
/// <param name="Checked">Anchors examined.</param>
/// <param name="Matched">Anchors whose export still matches the chain.</param>
/// <param name="Problems">One line per anchor that does not match, in chain order.</param>
public sealed record AuditAnchorVerification(int Checked, int Matched, IReadOnlyList<string> Problems)
{
    public static AuditAnchorVerification None { get; } = new(0, 0, []);

    /// <summary>
    /// True when every anchor examined still agrees with the chain. An anchor set of zero is
    /// vacuously consistent, which is why this is reported alongside <see cref="Checked"/> rather
    /// than on its own: "nothing disagreed" and "nothing was checked" are different answers.
    /// </summary>
    public bool AllMatched => Problems.Count == 0;
}

/// <summary>
/// Compares the audit chain against the exports already written to write-once storage.
/// </summary>
/// <remarks>
/// The hash chain on its own only proves internal consistency: a writer privileged enough to alter
/// an event can recompute every hash after it, and the chain then verifies perfectly. What they
/// cannot do is reach into immutable storage and change an export that was written before the
/// alteration. This is the check that uses that — re-render each anchored range from the current
/// chain and compare it against the bytes actually sitting in the export, and compare those bytes
/// against the hash the chain claims for them. Either mismatch is evidence of rewriting.
///
/// Reported separately from chain verification and never folded into it: a broken link and a chain
/// that diverges from its anchors are different findings, and an anchor that cannot be read (a
/// storage outage, a retention policy that removed it) must not be reported as an intact trail.
/// </remarks>
public sealed class AuditAnchorVerifier(IAuditEventStore store, IAuditExportSink sink)
{
    private const string AnchorEventType = "audit_export_completed";
    private const int PageSize = 500;

    private readonly IAuditEventStore _store = store ?? throw new ArgumentNullException(nameof(store));
    private readonly IAuditExportSink _sink = sink ?? throw new ArgumentNullException(nameof(sink));

    public async Task<AuditAnchorVerification> VerifyAsync(CancellationToken cancellationToken)
    {
        var problems = new List<string>();
        var checkedCount = 0;
        var matched = 0;

        await foreach (var anchor in ReadAnchorsAsync(cancellationToken).ConfigureAwait(false))
        {
            checkedCount++;
            var problem = await CheckAsync(anchor, cancellationToken).ConfigureAwait(false);
            if (problem is null)
            {
                matched++;
            }
            else
            {
                problems.Add(problem);
            }
        }

        return new AuditAnchorVerification(checkedCount, matched, problems);
    }

    private async Task<string?> CheckAsync(Anchor anchor, CancellationToken cancellationToken)
    {
        var stored = await _sink.ReadAsync(anchor.Name, cancellationToken).ConfigureAwait(false);
        if (stored is null)
        {
            return $"Anchor at sequence {anchor.AtSequence}: the export '{anchor.Name}' is not in storage. "
                   + "An anchor that cannot be read proves nothing about the range it covers.";
        }

        var storedHash = Convert.ToHexStringLower(SHA256.HashData(stored.Value.Span));
        if (!string.Equals(storedHash, anchor.ContentHash, StringComparison.OrdinalIgnoreCase))
        {
            return $"Anchor at sequence {anchor.AtSequence}: the export '{anchor.Name}' hashes to {storedHash}, "
                   + $"but the chain records {anchor.ContentHash}. One of the two was altered after the export.";
        }

        var count = checked((int)(anchor.To - anchor.From + 1));
        var events = await _store.ReadAsync(anchor.From, count, cancellationToken).ConfigureAwait(false);
        if (events.Count != count)
        {
            return $"Anchor at sequence {anchor.AtSequence}: the export covers sequences {anchor.From}..{anchor.To} "
                   + $"({count} events) but the store returns {events.Count}. Events have been removed.";
        }

        var currentHash = Convert.ToHexStringLower(SHA256.HashData(AuditExportFormat.Render(events)));
        return string.Equals(currentHash, anchor.ContentHash, StringComparison.OrdinalIgnoreCase)
            ? null
            : $"Anchor at sequence {anchor.AtSequence}: sequences {anchor.From}..{anchor.To} now render to "
              + $"{currentHash}, but the export written at the time holds {anchor.ContentHash}. "
              + "The chain has been rewritten since it was anchored.";
    }

    /// <summary>
    /// Walks the chain for export events. The anchors are themselves audit events, so this reads
    /// the same trail it is checking — which is the point: an attacker who removes the anchor events
    /// to hide a rewrite removes them from a chain whose sequence gaps are checked separately.
    /// </summary>
    private async IAsyncEnumerable<Anchor> ReadAnchorsAsync(
        [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken cancellationToken)
    {
        var next = 0L;
        while (true)
        {
            var page = await _store.ReadAsync(next, PageSize, cancellationToken).ConfigureAwait(false);
            if (page.Count == 0)
            {
                yield break;
            }

            foreach (var auditEvent in page)
            {
                if (string.Equals(auditEvent.EventType, AnchorEventType, StringComparison.Ordinal)
                    && TryParse(auditEvent, out var anchor))
                {
                    yield return anchor;
                }
            }

            next = page[^1].Sequence + 1;
        }
    }

    private static bool TryParse(AuditEvent auditEvent, out Anchor anchor)
    {
        anchor = default!;
        try
        {
            using var document = JsonDocument.Parse(auditEvent.Data);
            var root = document.RootElement;
            if (!root.TryGetProperty("from", out var from)
                || !root.TryGetProperty("to", out var to)
                || !root.TryGetProperty("contentHash", out var hash)
                || !root.TryGetProperty("name", out var name))
            {
                return false;
            }

            anchor = new Anchor(
                auditEvent.Sequence, from.GetInt64(), to.GetInt64(), hash.GetString()!, name.GetString()!);
            return true;
        }
        catch (Exception ex) when (ex is JsonException or InvalidOperationException or FormatException)
        {
            // A malformed anchor event is not something to crash verification over; the chain check
            // covers whether the event itself was tampered with.
            return false;
        }
    }

    private sealed record Anchor(long AtSequence, long From, long To, string ContentHash, string Name);
}
