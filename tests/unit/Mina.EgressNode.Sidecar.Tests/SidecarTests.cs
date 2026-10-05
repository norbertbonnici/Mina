using Mina.EgressNode.Sidecar;

namespace Mina.EgressNode.Sidecar.Tests;

public class AccessLogParserTests
{
    private const string SessionId = "6f1c2b7e-6c9a-4a3d-9a1e-2b7c4d5e6f70";

    private static string Line(
        string authority, string? certUri = null, long bytesUp = 100, long bytesDown = 900, int responseCode = 200) =>
        $$"""
        {"schema":"mina.hostname.v1","authority":"{{authority}}","bytes_up":{{bytesUp}},"bytes_down":{{bytesDown}},"duration_ms":42,"response_code":{{responseCode}},"client_cert_uri":"{{certUri ?? $"mina:session:{SessionId}"}}"}
        """;

    [Fact]
    public void Parses_a_hostname_record_and_attributes_it_to_the_session()
    {
        var entry = AccessLogParser.TryParse(Line("example.org:443"));

        Assert.NotNull(entry);
        Assert.Equal(Guid.Parse(SessionId), entry.SessionId);
        Assert.Equal("example.org", entry.Hostname);
        Assert.Equal(443, entry.Port);
        Assert.Equal(100, entry.BytesUp);
        Assert.Equal(900, entry.BytesDown);
        Assert.Equal(42, entry.DurationMs);
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("[2026-08-31 19:00:00.000][1][info][main] starting")] // Envoy's own output
    [InlineData("{not json")]
    [InlineData("""{"schema":"something.else","authority":"example.org:443"}""")]
    public void Ignores_anything_that_is_not_an_access_log_record(string line)
    {
        Assert.Null(AccessLogParser.TryParse(line));
    }

    [Fact]
    public void Drops_a_record_with_no_session_because_it_cannot_be_attributed()
    {
        Assert.Null(AccessLogParser.TryParse(Line("example.org:443", certUri: "")));
        Assert.Null(AccessLogParser.TryParse(Line("example.org:443", certUri: "spiffe://something/else")));
    }

    [Theory]
    [InlineData(403)]   // admission refused: revoked or unknown session
    [InlineData(503)]   // admission errored: the sidecar was not answering
    [InlineData(0)]     // no response recorded
    public void Drops_a_refused_connect_so_it_is_not_recorded_as_a_visit(int responseCode)
    {
        // A refused tunnel is not browsing history. Recording it would turn a revoked session's
        // rejected attempt into a destination the analyst "reached".
        Assert.Null(AccessLogParser.TryParse(Line("example.org:443", responseCode: responseCode)));
    }

    [Fact]
    public void Keeps_a_successful_connect()
    {
        Assert.NotNull(AccessLogParser.TryParse(Line("example.org:443", responseCode: 200)));
    }

    [Theory]
    [InlineData("example.org")]     // no port: not a CONNECT tunnel record
    [InlineData(":443")]            // no host
    [InlineData("example.org:abc")] // unparseable port
    public void Drops_a_record_whose_authority_is_not_host_and_port(string authority)
    {
        Assert.Null(AccessLogParser.TryParse(Line(authority)));
    }

    private static string RedactedLine(string suppressed = "\"true\"", string? certUri = null, string extra = "") =>
        $$"""
        {"schema":"mina.hostname.v1","suppressed":{{suppressed}},"bytes_up":100,"bytes_down":900,"duration_ms":42,"response_code":200,"client_cert_uri":"{{certUri ?? $"mina:session:{SessionId}"}}"{{extra}}}
        """;

    [Theory]
    [InlineData("\"true\"")]  // what Envoy's json_format literal renders
    [InlineData("true")]        // a bare JSON boolean, should the format ever carry one
    public void A_redacted_line_yields_a_counts_only_entry_with_no_destination(string suppressed)
    {
        // Envoy writes this shape for a session the sidecar flagged suppressed at admission: no
        // authority at all. The entry still attributes the bytes to the session.
        var entry = AccessLogParser.TryParse(RedactedLine(suppressed));

        Assert.NotNull(entry);
        Assert.Equal(Guid.Parse(SessionId), entry.SessionId);
        Assert.Null(entry.Hostname);
        Assert.Equal(0, entry.Port);
        Assert.Equal(100, entry.BytesUp);
        Assert.Equal(900, entry.BytesDown);
    }

    [Fact]
    public void A_line_marked_suppressed_never_yields_a_destination_even_if_one_is_present()
    {
        // Defence against a misrendered log: the flag wins over the field.
        var entry = AccessLogParser.TryParse(RedactedLine(extra: ",\"authority\":\"should-not-appear.example:443\""));

        Assert.NotNull(entry);
        Assert.Null(entry.Hostname);
        Assert.Equal(0, entry.Port);
    }

    [Fact]
    public void A_redacted_line_with_no_session_is_still_dropped()
    {
        Assert.Null(AccessLogParser.TryParse(RedactedLine(certUri: "")));
    }

    [Fact]
    public void A_line_with_neither_authority_nor_suppressed_flag_is_dropped()
    {
        Assert.Null(AccessLogParser.TryParse(RedactedLine(suppressed: "false")));
        Assert.Null(AccessLogParser.TryParse(RedactedLine(suppressed: "\"no\"")));
    }

    [Fact]
    public void Handles_an_ipv4_literal_authority()
    {
        var entry = AccessLogParser.TryParse(Line("203.0.113.10:8443"));

        Assert.NotNull(entry);
        Assert.Equal("203.0.113.10", entry.Hostname);
        Assert.Equal(8443, entry.Port);
    }
}

public class NodeSessionViewTests
{
    [Fact]
    public void Before_the_first_refresh_every_session_is_treated_as_suppressed()
    {
        var allowlist = new NodeSessionView();

        // Fail safe: withholding a destination is recoverable; recording one that should have been
        // suppressed is not.
        Assert.True(allowlist.MustWithholdDestination(Guid.NewGuid()));
    }

    [Fact]
    public void After_a_refresh_only_suppressed_sessions_withhold()
    {
        var normal = Guid.NewGuid();
        var sensitive = Guid.NewGuid();
        var allowlist = new NodeSessionView();

        allowlist.Update(
        [
            new NodeSession(normal, Suppressed: false, DateTimeOffset.UtcNow.AddHours(1)),
            new NodeSession(sensitive, Suppressed: true, DateTimeOffset.UtcNow.AddHours(1)),
        ], TimeProvider.System);

        Assert.False(allowlist.MustWithholdDestination(normal));
        Assert.True(allowlist.MustWithholdDestination(sensitive));
    }

    [Fact]
    public void A_session_the_node_has_never_heard_of_withholds()
    {
        var allowlist = new NodeSessionView();
        allowlist.Update([new NodeSession(Guid.NewGuid(), false, DateTimeOffset.UtcNow.AddHours(1))], TimeProvider.System);

        Assert.True(allowlist.MustWithholdDestination(Guid.NewGuid()));
    }

    [Fact]
    public void A_refresh_removes_sessions_that_have_gone_away()
    {
        var gone = Guid.NewGuid();
        var allowlist = new NodeSessionView();
        allowlist.Update([new NodeSession(gone, false, DateTimeOffset.UtcNow.AddHours(1))], TimeProvider.System);
        Assert.False(allowlist.MustWithholdDestination(gone));

        allowlist.Update([], TimeProvider.System);

        Assert.True(allowlist.MustWithholdDestination(gone));
        Assert.Equal(0, allowlist.KnownSessions);
    }

    [Fact]
    public void A_session_becoming_suppressed_takes_effect_on_the_next_refresh()
    {
        var session = Guid.NewGuid();
        var allowlist = new NodeSessionView();
        allowlist.Update([new NodeSession(session, false, DateTimeOffset.UtcNow.AddHours(1))], TimeProvider.System);
        Assert.False(allowlist.MustWithholdDestination(session));

        allowlist.Update([new NodeSession(session, true, DateTimeOffset.UtcNow.AddHours(1))], TimeProvider.System);

        Assert.True(allowlist.MustWithholdDestination(session));
    }
}

public class TelemetryBatcherTests
{
    private static readonly DateTimeOffset T0 = new(2026, 8, 31, 9, 0, 0, TimeSpan.Zero);

    private static AccessLogEntry Entry(Guid sessionId) =>
        new(sessionId, "target.example", 443, 100, 900, 42);

    [Fact]
    public void An_unsuppressed_session_keeps_its_destination()
    {
        var session = Guid.NewGuid();
        var allowlist = new NodeSessionView();
        allowlist.Update([new NodeSession(session, false, T0.AddHours(1))], new FixedClock(T0));
        var batcher = new TelemetryBatcher(allowlist, new FixedClock(T0));

        batcher.Add(Entry(session));

        var item = Assert.Single(batcher.Drain());
        Assert.Equal("target.example", item.Hostname);
        Assert.Equal(900, item.BytesDown);
    }

    [Fact]
    public void A_suppressed_session_loses_its_destination_before_it_is_queued()
    {
        var session = Guid.NewGuid();
        var allowlist = new NodeSessionView();
        allowlist.Update([new NodeSession(session, true, T0.AddHours(1))], new FixedClock(T0));
        var batcher = new TelemetryBatcher(allowlist, new FixedClock(T0));

        batcher.Add(Entry(session));

        var item = Assert.Single(batcher.Drain());
        Assert.Null(item.Hostname);
        // The counts survive: suppression removes the destination, not the accountability.
        Assert.Equal(100, item.BytesUp);
        Assert.Equal(900, item.BytesDown);
        Assert.Equal(session, item.SessionId);
    }

    [Fact]
    public void An_entry_envoy_already_redacted_is_queued_without_a_destination_whatever_the_view_says()
    {
        // The view says "not suppressed" (it may be one refresh behind the admission decision that
        // produced the redacted line); the line carried no hostname, so none can be shipped.
        var session = Guid.NewGuid();
        var allowlist = new NodeSessionView();
        allowlist.Update([new NodeSession(session, false, T0.AddHours(1))], new FixedClock(T0));
        var batcher = new TelemetryBatcher(allowlist, new FixedClock(T0));

        batcher.Add(new AccessLogEntry(session, Hostname: null, 0, 100, 900, 42));

        var item = Assert.Single(batcher.Drain());
        Assert.Null(item.Hostname);
        Assert.Equal(900, item.BytesDown);
    }

    [Fact]
    public void Draining_empties_the_batcher()
    {
        var session = Guid.NewGuid();
        var allowlist = new NodeSessionView();
        allowlist.Update([new NodeSession(session, false, T0.AddHours(1))], new FixedClock(T0));
        var batcher = new TelemetryBatcher(allowlist, new FixedClock(T0));

        batcher.Add(Entry(session));
        batcher.Add(Entry(session));
        Assert.Equal(2, batcher.PendingCount);

        Assert.Equal(2, batcher.Drain().Count);
        Assert.Equal(0, batcher.PendingCount);
        Assert.Empty(batcher.Drain());
    }

    private sealed class FixedClock(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => now;
    }
}
