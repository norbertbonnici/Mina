using Microsoft.EntityFrameworkCore;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Options;
using Mina.ControlPlane.Application.Audit;
using Mina.ControlPlane.Domain.Audit;
using Mina.ControlPlane.Persistence;

namespace Mina.ControlPlane.Persistence.Tests;

/// <summary>
/// The export is what anchors the chain outside the database. These cover that it captures
/// everything new, hashes what it wrote, records the anchor back into the trail, and refuses to
/// overwrite an anchor once written.
/// </summary>
public sealed class AuditExportTests
{
    private static readonly DateTimeOffset T0 = new(2026, 8, 31, 9, 0, 0, TimeSpan.Zero);

    private sealed class MemoryExportSink : IAuditExportSink
    {
        public Dictionary<string, byte[]> Written { get; } = [];

        public long? LastExported { get; set; }

        public Task WriteAsync(string name, ReadOnlyMemory<byte> content, CancellationToken cancellationToken)
        {
            if (!Written.TryAdd(name, content.ToArray()))
            {
                throw new InvalidOperationException($"'{name}' already exists; exports are write-once.");
            }

            return Task.CompletedTask;
        }

        public Task<long?> GetLastExportedSequenceAsync(CancellationToken cancellationToken) =>
            Task.FromResult(LastExported);

        public Task<ReadOnlyMemory<byte>?> ReadAsync(string name, CancellationToken cancellationToken) =>
            Task.FromResult(Written.TryGetValue(name, out var content)
                ? (ReadOnlyMemory<byte>?)content
                : null);
    }

    private sealed class FixedClock(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => now;
    }

    // Each test gets its own database: these assert on the whole chain, so they cannot share one.
    private static (AuditWriter Writer, AuditExportService Exporter, MemoryExportSink Sink,
        SqliteDatabaseFixture Db, MinaDbContext Context, AuditAnchorVerifier Anchors) Build()
    {
        var db = new SqliteDatabaseFixture();
        var context = db.CreateContext();
        var store = new EfAuditEventStore(context);
        var options = Options.Create(new AuditOptions { Environment = "test" });
        var writer = new AuditWriter(store, options, new FixedClock(T0));
        var sink = new MemoryExportSink();
        return (writer, new AuditExportService(store, sink, writer, options, new FixedClock(T0)), sink, db, context,
            new AuditAnchorVerifier(store, sink));
    }

    private static AuditEventDraft Draft(string type) =>
        new(type, AuditSeverity.Info, AuditComponent.ControlPlane, Data: new { note = type });

    [Fact]
    public async Task Exporting_an_empty_chain_does_nothing()
    {
        var (_, exporter, sink, db, context, _) = Build();
        using var _db = db;
        await using (context)
        {
            var result = await exporter.ExportAsync(default);

            Assert.False(result.ExportedAnything);
            Assert.Empty(sink.Written);
        }
    }

    [Fact]
    public async Task An_export_captures_the_events_and_records_its_own_hash_back_into_the_chain()
    {
        var (writer, exporter, sink, db, context, _) = Build();
        using var _db = db;
        await using (context)
        {
            await writer.WriteAsync(Draft("session_started"), default);
            await writer.WriteAsync(Draft("session_ended"), default);

            var result = await exporter.ExportAsync(default);

            Assert.True(result.ExportedAnything);
            Assert.Equal(2, result.EventCount);
            Assert.Equal(0, result.FromSequence);
            Assert.Equal(1, result.ToSequence);

            // The hash the exporter reported is the hash of what it actually wrote.
            var content = Assert.Single(sink.Written).Value;
            Assert.Equal(Convert.ToHexStringLower(SHA256.HashData(content)), result.ContentHash);

            // Two lines out, one per event, each carrying its chain links.
            var lines = Encoding.UTF8.GetString(content).Split('\n', StringSplitOptions.RemoveEmptyEntries);
            Assert.Equal(2, lines.Length);
            Assert.Contains("mina.audit.v1", lines[0], StringComparison.Ordinal);
            Assert.Contains("previous_hash", lines[0], StringComparison.Ordinal);

            // And the anchor itself is auditable: the export appended its own event.
            var store = new EfAuditEventStore(db.CreateContext());
            var events = await store.ReadAsync(0, 100, default);
            var anchor = events.Single(e => e.EventType == "audit_export_completed");
            Assert.Contains(result.ContentHash, anchor.Data, StringComparison.Ordinal);
        }
    }

    [Fact]
    public async Task A_second_export_continues_from_where_the_first_stopped()
    {
        var (writer, exporter, sink, db, context, _) = Build();
        using var _db = db;
        await using (context)
        {
            await writer.WriteAsync(Draft("first"), default);
            var first = await exporter.ExportAsync(default);

            // The sink reports what it holds, as the real one does by listing what it has stored.
            sink.LastExported = first.ToSequence;
            await writer.WriteAsync(Draft("second"), default);

            var second = await exporter.ExportAsync(default);

            Assert.Equal(first.ToSequence + 1, second.FromSequence);
            Assert.Equal(2, sink.Written.Count);
        }
    }

    [Fact]
    public async Task An_export_cannot_be_overwritten()
    {
        var (_, _, sink, db, context, _) = Build();
        using var _db = db;
        await using (context)
        {
            await sink.WriteAsync("test/audit-anchor.jsonl", new byte[] { 1 }, default);

            // Anchoring depends on the written copy being immutable: a sink that silently replaced
            // one would anchor nothing.
            await Assert.ThrowsAsync<InvalidOperationException>(
                () => sink.WriteAsync("test/audit-anchor.jsonl", new byte[] { 2 }, default));
        }
    }

    [Fact]
    public async Task Anchors_verify_against_the_chain_they_were_taken_from()
    {
        var (writer, exporter, _, db, context, anchors) = Build();
        using var _db = db;
        await using (context)
        {
            await writer.WriteAsync(Draft("session_started"), default);
            await writer.WriteAsync(Draft("session_ended"), default);
            await exporter.ExportAsync(default);

            var result = await anchors.VerifyAsync(default);

            Assert.Equal(1, result.Checked);
            Assert.Equal(1, result.Matched);
            Assert.True(result.AllMatched);
        }
    }

    [Fact]
    public async Task A_wholesale_rewrite_passes_the_chain_check_and_is_caught_by_the_anchors()
    {
        var (writer, exporter, sink, db, context, anchors) = Build();
        using var _db = db;
        await using (context)
        {
            await writer.WriteAsync(Draft("suppression_approved"), default);
            await writer.WriteAsync(Draft("session_ended"), default);
            await exporter.ExportAsync(default);

            var store = new EfAuditEventStore(context);
            var anchorData = (await store.ReadAsync(0, 100, default))
                .Single(e => e.EventType == "audit_export_completed").Data;

            // The attack the hash chain alone cannot survive: someone with write access to the
            // database replaces the trail and recomputes every link, keeping the anchor event's
            // recorded hash — which they cannot change in write-once storage — as it was.
            await context.Set<AuditEvent>().ExecuteDeleteAsync(default);
            context.ChangeTracker.Clear();

            var rewritten = new EfAuditEventStore(context);
            var previous = AuditEvent.GenesisHash;
            foreach (var (type, data, sequence) in new[]
            {
                ("session_started", "{\"note\":\"nothing to see\"}", 0L),
                ("session_ended", "{\"note\":\"session_ended\"}", 1L),
                ("audit_export_completed", anchorData, 2L),
            })
            {
                var replacement = AuditEvent.Append(
                    sequence, previous, type, AuditSeverity.Info, AuditComponent.ControlPlane, T0, "test",
                    data: data);
                await rewritten.AppendAsync(replacement, default);
                previous = replacement.Hash;
            }

            // The chain is perfectly self-consistent: every link recomputes, no gaps.
            var chain = await new AuditChainVerifier(rewritten).VerifyAsync(default);
            Assert.True(chain.IsIntact);

            // The export in write-once storage says otherwise, and that is the whole point of it.
            var result = await anchors.VerifyAsync(default);
            Assert.Equal(1, result.Checked);
            Assert.Equal(0, result.Matched);
            Assert.False(result.AllMatched);
            Assert.Contains("rewritten since it was anchored", Assert.Single(result.Problems), StringComparison.Ordinal);
            Assert.Single(sink.Written);
        }
    }

    [Fact]
    public async Task An_anchor_whose_export_is_gone_is_reported_rather_than_counted_as_verified()
    {
        var (writer, exporter, sink, db, context, anchors) = Build();
        using var _db = db;
        await using (context)
        {
            await writer.WriteAsync(Draft("session_started"), default);
            await exporter.ExportAsync(default);

            // A retention policy, a storage outage, a deleted container: whatever the cause, the
            // range it covered is no longer anchored and saying nothing would overstate the trail.
            sink.Written.Clear();

            var result = await anchors.VerifyAsync(default);

            Assert.Equal(1, result.Checked);
            Assert.Equal(0, result.Matched);
            Assert.Contains("not in storage", Assert.Single(result.Problems), StringComparison.Ordinal);
        }
    }

    [Fact]
    public async Task An_export_refuses_to_run_when_the_store_is_behind_its_own_anchors()
    {
        var (writer, exporter, sink, db, context, _) = Build();
        using var _db = db;
        await using (context)
        {
            await writer.WriteAsync(Draft("session_started"), default);

            // The sink holds anchors up to sequence 40 but the store ends at 0: events that were
            // exported have been removed. Reading onwards from 41 finds nothing, so before this
            // check the export reported "nothing to do" and the truncation passed unnoticed.
            sink.LastExported = 40;

            var ex = await Assert.ThrowsAsync<AuditAnchorException>(() => exporter.ExportAsync(default));
            Assert.Contains("missing from the store", ex.Message, StringComparison.Ordinal);
        }
    }
}
