using Microsoft.Extensions.Options;
using Mina.ControlPlane.Application.Audit;
using Mina.ControlPlane.Domain.Audit;

namespace Mina.ControlPlane.Application.Tests;

/// <summary>
/// The audit chain's job is to make silent alteration detectable. These cover what that means in
/// practice: an intact trail verifies, and altering, replacing or removing an event does not.
/// </summary>
public class AuditChainTests
{
    private static readonly DateTimeOffset T0 = new(2026, 8, 31, 9, 0, 0, TimeSpan.Zero);

    private static (AuditWriter Writer, MutableAuditStore Store, AuditChainVerifier Verifier) Build()
    {
        var store = new MutableAuditStore();
        var writer = new AuditWriter(store, Options.Create(new AuditOptions { Environment = "test" }), new FixedClock(T0));
        return (writer, store, new AuditChainVerifier(store));
    }

    private static AuditEventDraft Draft(string type = "session_started") =>
        new(type, AuditSeverity.Info, AuditComponent.ControlPlane, Data: new { note = "x" });

    [Fact]
    public async Task The_first_event_chains_from_genesis()
    {
        var (writer, _, _) = Build();

        var first = await writer.WriteAsync(Draft(), default);

        Assert.Equal(0, first.Sequence);
        Assert.Equal(AuditEvent.GenesisHash, first.PreviousHash);
        Assert.Equal(first.RecomputeHash(), first.Hash);
    }

    [Fact]
    public async Task Each_event_links_to_the_one_before_it()
    {
        var (writer, _, verifier) = Build();

        var first = await writer.WriteAsync(Draft(), default);
        var second = await writer.WriteAsync(Draft("session_ended"), default);

        Assert.Equal(1, second.Sequence);
        Assert.Equal(first.Hash, second.PreviousHash);
        Assert.True((await verifier.VerifyAsync(default)).IsIntact);
    }

    [Fact]
    public async Task An_intact_chain_verifies()
    {
        var (writer, _, verifier) = Build();
        for (var i = 0; i < 25; i++)
        {
            await writer.WriteAsync(Draft(), default);
        }

        var result = await verifier.VerifyAsync(default);

        Assert.True(result.IsIntact);
        Assert.Equal(25, result.Verified);
        Assert.Null(result.BrokenAtSequence);
    }

    [Fact]
    public async Task Altering_an_event_breaks_verification_at_that_event()
    {
        var (writer, store, verifier) = Build();
        await writer.WriteAsync(Draft(), default);
        var target = await writer.WriteAsync(Draft("sensitive_approved"), default);
        await writer.WriteAsync(Draft(), default);

        // Someone edits the record in place — say, to hide who approved something.
        store.ReplaceData(target.Sequence, """{"approver_upn":"someone.else@example.org"}""");

        var result = await verifier.VerifyAsync(default);

        Assert.False(result.IsIntact);
        Assert.Equal(target.Sequence, result.BrokenAtSequence);
        Assert.Contains("altered", result.Reason!, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Removing_an_event_breaks_verification_as_a_gap()
    {
        var (writer, store, verifier) = Build();
        await writer.WriteAsync(Draft(), default);
        var removed = await writer.WriteAsync(Draft("authz_denied"), default);
        await writer.WriteAsync(Draft(), default);

        store.Remove(removed.Sequence);

        var result = await verifier.VerifyAsync(default);

        Assert.False(result.IsIntact);
        Assert.Equal(removed.Sequence, result.BrokenAtSequence);
        Assert.Contains("missing", result.Reason!, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Rewriting_the_tail_still_breaks_the_link_to_the_untouched_prefix()
    {
        var (writer, store, verifier) = Build();
        await writer.WriteAsync(Draft(), default);
        var replaced = await writer.WriteAsync(Draft("session_revoked"), default);

        // A convincing forgery of one event: internally consistent, but it no longer follows its
        // predecessor, because its predecessor's hash is not what this one claims.
        store.Replace(AuditEvent.Append(
            replaced.Sequence, "f".PadLeft(64, 'f'), "session_ended", AuditSeverity.Info,
            AuditComponent.ControlPlane, T0, "test"));

        var result = await verifier.VerifyAsync(default);

        Assert.False(result.IsIntact);
        Assert.Equal(replaced.Sequence, result.BrokenAtSequence);
        Assert.Contains("predecessor", result.Reason!, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task An_empty_chain_is_intact()
    {
        var (_, _, verifier) = Build();

        var result = await verifier.VerifyAsync(default);

        Assert.True(result.IsIntact);
        Assert.Equal(0, result.Verified);
    }

    [Fact]
    public async Task A_writer_that_loses_the_race_retries_onto_the_new_tip()
    {
        var store = new MutableAuditStore();
        var writer = new AuditWriter(store, Options.Create(new AuditOptions()), new FixedClock(T0));
        await writer.WriteAsync(Draft(), default);

        // The next append hits a conflict once, as though another instance got there first.
        store.FailNextAppendWithConflict();
        var written = await writer.WriteAsync(Draft("session_ended"), default);

        Assert.Equal(1, written.Sequence);
        Assert.True((await new AuditChainVerifier(store).VerifyAsync(default)).IsIntact);
    }

    [Fact]
    public async Task A_write_that_cannot_be_recorded_throws_rather_than_passing_silently()
    {
        var store = new MutableAuditStore { AlwaysConflict = true };
        var writer = new AuditWriter(
            store, Options.Create(new AuditOptions { MaxAppendAttempts = 3 }), new FixedClock(T0));

        // The caller must see this: an action whose event cannot be recorded must not proceed.
        await Assert.ThrowsAsync<AuditWriteException>(() => writer.WriteAsync(Draft(), default));
    }

    private sealed class FixedClock(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => now;
    }

    /// <summary>An audit store that also allows the tampering these tests need to simulate.</summary>
    private sealed class MutableAuditStore : IAuditEventStore
    {
        private readonly List<AuditEvent> _events = [];
        private bool _failNext;

        public bool AlwaysConflict { get; init; }

        public void FailNextAppendWithConflict() => _failNext = true;

        public Task<AuditChainTip> GetTipAsync(CancellationToken cancellationToken) =>
            Task.FromResult(_events.Count == 0
                ? AuditChainTip.Empty
                : new AuditChainTip(_events[^1].Sequence, _events[^1].Hash));

        public Task AppendAsync(AuditEvent auditEvent, CancellationToken cancellationToken)
        {
            if (AlwaysConflict || _failNext)
            {
                _failNext = false;
                throw new AuditSequenceConflictException();
            }

            _events.Add(auditEvent);
            return Task.CompletedTask;
        }

        public Task<IReadOnlyList<AuditEvent>> ReadAsync(
            long fromSequence, int limit, CancellationToken cancellationToken) =>
            Task.FromResult<IReadOnlyList<AuditEvent>>(
                [.. _events.Where(e => e.Sequence >= fromSequence).OrderBy(e => e.Sequence).Take(limit)]);

        public Task<IReadOnlyList<AuditEvent>> ReadRecentAsync(int limit, CancellationToken cancellationToken) =>
            Task.FromResult<IReadOnlyList<AuditEvent>>([.. _events.OrderByDescending(e => e.Sequence).Take(limit)]);

        public void Remove(long sequence) => _events.RemoveAll(e => e.Sequence == sequence);

        public void Replace(AuditEvent replacement)
        {
            Remove(replacement.Sequence);
            _events.Add(replacement);
            _events.Sort((a, b) => a.Sequence.CompareTo(b.Sequence));
        }

        /// <summary>Edits an event's payload in place, leaving its recorded hash stale.</summary>
        public void ReplaceData(long sequence, string data)
        {
            var index = _events.FindIndex(e => e.Sequence == sequence);
            var original = _events[index];
            var tampered = AuditEvent.Append(
                original.Sequence, original.PreviousHash, original.EventType, original.Severity,
                original.Component, original.OccurredAt, original.Environment, original.Region,
                original.UserObjectId, original.UserPrincipalName, original.DeviceId, original.SessionId, data);

            // Keep the original hash so the row looks untouched to anyone not recomputing it.
            _events[index] = new AuditEventWithForcedHash(tampered, original.Hash).Build();
        }
    }

    /// <summary>Builds an event whose stored hash deliberately does not match its contents.</summary>
    private sealed class AuditEventWithForcedHash(AuditEvent source, string forcedHash)
    {
        public AuditEvent Build()
        {
            // Reflection is the only way to forge this, which is the point: nothing in the domain
            // lets a caller write an event whose hash does not match it.
            var instance = (AuditEvent)System.Runtime.CompilerServices.RuntimeHelpers
                .GetUninitializedObject(typeof(AuditEvent));

            foreach (var field in typeof(AuditEvent).GetFields(
                System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic))
            {
                field.SetValue(instance, field.GetValue(source));
            }

            typeof(AuditEvent)
                .GetField($"<{nameof(AuditEvent.Hash)}>k__BackingField",
                    System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic)!
                .SetValue(instance, forcedHash);

            return instance;
        }
    }
}
