using System.Diagnostics;
using Microsoft.Extensions.Logging;
using Mina.Observability;
using OpenTelemetry;
using OpenTelemetry.Logs;
using OpenTelemetry.Trace;

namespace Mina.Observability.Tests;

/// <summary>
/// The scrubber running where it actually runs: inside the export pipeline. These emit spans and
/// logs carrying research destinations and assert that what an exporter receives has none of them —
/// the content scan AC-014 asks for, at the point of export rather than after the fact.
/// </summary>
public class ScrubbingPipelineTests
{
    private const string ResearchTarget = "sensitive-research-target.example";
    private const string SourceName = "Mina.Observability.Tests";

    [Fact]
    public void A_span_attribute_holding_a_destination_does_not_reach_the_exporter()
    {
        var exported = new List<Activity>();
        using var provider = Sdk.CreateTracerProviderBuilder()
            .AddSource(SourceName)
            .AddProcessor(new ScrubbingActivityProcessor())
            .AddInMemoryExporter(exported)
            .Build();

        using (var source = new ActivitySource(SourceName))
        using (var activity = source.StartActivity("outbound"))
        {
            activity?.SetTag("server.address", ResearchTarget);
            activity?.SetTag("url.full", $"https://{ResearchTarget}/case/12345");
            activity?.SetTag("http.route", "/api/sessions"); // ours: must survive
        }

        provider.ForceFlush();

        var span = Assert.Single(exported);
        var rendered = string.Join(' ', span.Tags.Select(t => $"{t.Key}={t.Value}"));
        Assert.DoesNotContain(ResearchTarget, rendered, StringComparison.Ordinal);
        Assert.Contains("/api/sessions", rendered, StringComparison.Ordinal);
    }

    [Fact]
    public void A_log_message_mentioning_a_destination_does_not_reach_the_exporter()
    {
        var exported = new List<LogRecord>();
        using var factory = LoggerFactory.Create(builder => builder.AddOpenTelemetry(otel =>
        {
            otel.IncludeFormattedMessage = true;
            otel.AddProcessor(new ScrubbingLogProcessor());
            otel.AddInMemoryExporter(exported);
        }));

        // Exactly the shape of leak that matters: the agent logs the target it tunnelled to.
        factory.CreateLogger("Mina.EndpointAgent")
            .LogInformation("Tunnel established to {Target}.", $"{ResearchTarget}:443");

        var record = Assert.Single(exported);
        var rendered = record.FormattedMessage + " " + string.Join(
            ' ', (record.Attributes ?? []).Select(a => $"{a.Key}={a.Value}"));

        Assert.DoesNotContain(ResearchTarget, rendered, StringComparison.Ordinal);
        Assert.Contains("Tunnel established", rendered, StringComparison.Ordinal);
    }

    [Fact]
    public void An_unanticipated_attribute_is_still_scrubbed()
    {
        var exported = new List<Activity>();
        using var provider = Sdk.CreateTracerProviderBuilder()
            .AddSource(SourceName)
            .AddProcessor(new ScrubbingActivityProcessor())
            .AddInMemoryExporter(exported)
            .Build();

        using (var source = new ActivitySource(SourceName))
        using (var activity = source.StartActivity("work"))
        {
            // No deny-list entry covers this key; the value check is what saves it.
            activity?.SetTag("debug.note", $"retrying against {ResearchTarget}");
        }

        provider.ForceFlush();

        var span = Assert.Single(exported);
        Assert.DoesNotContain(
            ResearchTarget,
            string.Join(' ', span.Tags.Select(t => t.Value)),
            StringComparison.Ordinal);
    }

    [Fact]
    public void Operational_spans_pass_through_unchanged()
    {
        var exported = new List<Activity>();
        using var provider = Sdk.CreateTracerProviderBuilder()
            .AddSource(SourceName)
            .AddProcessor(new ScrubbingActivityProcessor())
            .AddInMemoryExporter(exported)
            .Build();

        using (var source = new ActivitySource(SourceName))
        using (var activity = source.StartActivity("SessionEstablish"))
        {
            activity?.SetTag("mina.region", "westeurope");
            activity?.SetTag("outcome", "granted");
            activity?.SetTag("http.response.status_code", "201");
        }

        provider.ForceFlush();

        var span = Assert.Single(exported);
        var tags = span.Tags.ToDictionary(t => t.Key, t => t.Value);
        Assert.Equal("westeurope", tags["mina.region"]);
        Assert.Equal("granted", tags["outcome"]);
        Assert.Equal("201", tags["http.response.status_code"]);
    }
}
