using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Options;
using Mina.ControlPlane.Application.Audit;
using Mina.ControlPlane.Domain.Audit;
using Mina.ControlPlane.Persistence;

namespace Mina.ControlPlane.Persistence.Tests;

/// <summary>
/// M3-5: forwarding the audit chain to Wazuh. Mirrors <c>AuditExportTests</c>'s shape -- a real
/// SQLite-backed chain, and either a fake or the real filesystem sink depending on what each test is
/// proving.
/// </summary>
public sealed class WazuhDeliveryTests
{
    private static readonly DateTimeOffset T0 = new(2026, 9, 7, 9, 0, 0, TimeSpan.Zero);

    private sealed class MemorySink : IWazuhEventSink
    {
        public List<byte[]> Delivered { get; } = [];

        public long? LastDelivered { get; private set; }

        public Task DeliverAsync(ReadOnlyMemory<byte> content, long throughSequence, CancellationToken cancellationToken)
        {
            Delivered.Add(content.ToArray());
            LastDelivered = throughSequence;
            return Task.CompletedTask;
        }

        public Task<long?> GetLastDeliveredSequenceAsync(CancellationToken cancellationToken) =>
            Task.FromResult(LastDelivered);
    }

    private sealed class FixedClock(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => now;
    }

    private static (AuditWriter Writer, WazuhDeliveryService Deliverer, MemorySink Sink, SqliteDatabaseFixture Db,
        MinaDbContext Context) Build(WazuhDeliveryOptions? options = null)
    {
        var db = new SqliteDatabaseFixture();
        var context = db.CreateContext();
        var store = new EfAuditEventStore(context);
        var writer = new AuditWriter(
            store, Options.Create(new AuditOptions { Environment = "test" }), new FixedClock(T0));
        var sink = new MemorySink();
        var deliverer = new WazuhDeliveryService(
            store, sink, Options.Create(options ?? new WazuhDeliveryOptions { EventFilePath = "wazuh-events.jsonl" }));
        return (writer, deliverer, sink, db, context);
    }

    private static AuditEventDraft Draft(string type, AuditSeverity severity = AuditSeverity.Info) =>
        new(type, severity, AuditComponent.ControlPlane, Data: new { note = type });

    [Fact]
    public async Task Delivering_with_no_target_configured_does_nothing()
    {
        var (writer, deliverer, sink, db, context) = Build(new WazuhDeliveryOptions { EventFilePath = null });
        using var _db = db;
        await using (context)
        {
            await writer.WriteAsync(Draft("session_started"), default);

            var result = await deliverer.DeliverAsync(default);

            Assert.False(result.DeliveredAnything);
            Assert.Empty(sink.Delivered);
        }
    }

    [Fact]
    public async Task Delivering_an_empty_chain_does_nothing()
    {
        var (_, deliverer, sink, db, context) = Build();
        using var _db = db;
        await using (context)
        {
            var result = await deliverer.DeliverAsync(default);

            Assert.False(result.DeliveredAnything);
            Assert.Empty(sink.Delivered);
        }
    }

    [Fact]
    public async Task A_delivery_captures_new_events_in_the_documented_envelope_shape()
    {
        var (writer, deliverer, sink, db, context) = Build();
        using var _db = db;
        await using (context)
        {
            await writer.WriteAsync(
                new AuditEventDraft(
                    "sensitive_suppression_mismatch", AuditSeverity.Critical, AuditComponent.ControlPlane,
                    Region: "westeurope", SessionId: Guid.NewGuid(), Data: new { discarded_items = 3 }),
                default);

            var result = await deliverer.DeliverAsync(default);

            Assert.True(result.DeliveredAnything);
            Assert.Equal(1, result.EventCount);

            var line = Assert.Single(sink.Delivered);
            var text = Encoding.UTF8.GetString(line);
            var json = JsonDocument.Parse(text.TrimEnd()).RootElement;

            Assert.Equal("mina.audit.v1", json.GetProperty("schema").GetString());
            Assert.Equal("sensitive_suppression_mismatch", json.GetProperty("event_type").GetString());
            // EVENT_SCHEMAS.md documents these lowercase/kebab-case; found the shipped audit export
            // format using AuditComponent's PascalCase ToString() instead while building this, but
            // did not touch it -- that format's exact bytes are hashed into the WORM anchor chain,
            // so this renderer is deliberately its own, unconstrained copy.
            Assert.Equal("critical", json.GetProperty("severity").GetString());
            Assert.Equal("control-plane", json.GetProperty("component").GetString());
            Assert.Equal("westeurope", json.GetProperty("region").GetString());
            Assert.Contains("\"discarded_items\":3", json.GetProperty("data").GetString(), StringComparison.Ordinal);

            // Wazuh never receives URL/hostname content -- this event type carries none to begin
            // with (proven at the source in M3-7's SensitiveSessionHygieneTests), so what matters
            // here is that rendering did not introduce anything of its own.
            Assert.DoesNotContain(".example", text, StringComparison.Ordinal);
        }
    }

    [Fact]
    public async Task A_second_delivery_continues_from_where_the_first_stopped()
    {
        var (writer, deliverer, sink, db, context) = Build();
        using var _db = db;
        await using (context)
        {
            await writer.WriteAsync(Draft("first"), default);
            var first = await deliverer.DeliverAsync(default);

            await writer.WriteAsync(Draft("second"), default);
            var second = await deliverer.DeliverAsync(default);

            Assert.Equal(first.ToSequence + 1, second.FromSequence);
            Assert.Equal(2, sink.Delivered.Count);
        }
    }

    [Fact]
    public async Task A_batch_larger_than_the_configured_size_is_delivered_over_several_passes()
    {
        var (writer, deliverer, sink, db, context) =
            Build(new WazuhDeliveryOptions { EventFilePath = "wazuh-events.jsonl", BatchSize = 2 });
        using var _db = db;
        await using (context)
        {
            for (var i = 0; i < 5; i++)
            {
                await writer.WriteAsync(Draft($"event-{i}"), default);
            }

            var first = await deliverer.DeliverAsync(default);
            var second = await deliverer.DeliverAsync(default);
            var third = await deliverer.DeliverAsync(default);
            var fourth = await deliverer.DeliverAsync(default);

            Assert.Equal(2, first.EventCount);
            Assert.Equal(2, second.EventCount);
            Assert.Equal(1, third.EventCount);
            Assert.False(fourth.DeliveredAnything);
            Assert.Equal(3, sink.Delivered.Count);
        }
    }

    [Theory]
    [InlineData(0)]
    [InlineData(10_001)]
    public void An_out_of_range_batch_size_is_rejected(int batchSize) =>
        Assert.NotEmpty(new WazuhDeliveryOptions { EventFilePath = "x", BatchSize = batchSize }.Validate());

    [Fact]
    public void An_interval_under_one_second_is_rejected() =>
        Assert.NotEmpty(new WazuhDeliveryOptions
        {
            EventFilePath = "x",
            Interval = TimeSpan.FromMilliseconds(500),
        }.Validate());

    [Fact]
    public void The_shipped_configuration_has_delivery_disabled() =>
        Assert.False(new WazuhDeliveryOptions().IsConfigured);
}
