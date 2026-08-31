using System.Diagnostics;
using System.Diagnostics.Metrics;
using OpenTelemetry;
using OpenTelemetry.Logs;

namespace Mina.Observability;

/// <summary>Counts what the scrubber removed — the leak canary of EVENT_SCHEMAS §5.</summary>
/// <remarks>
/// A non-zero count is not a breach: it means the scrubber did its job. It is a signal that
/// something upstream is putting destinations into operational telemetry, which is worth finding
/// and fixing at the source rather than relying on the scrubber forever. A count that suddenly
/// climbs is the alert worth having.
/// </remarks>
public static class ScrubMetrics
{
    public const string MeterName = "Mina.Observability";

    private static readonly Meter Meter = new(MeterName);

    private static readonly Counter<long> Drops =
        Meter.CreateCounter<long>("mina_telemetry_scrub_drops_total", "items",
            "Attributes or log bodies redacted before export because they contained a destination.");

    public static void RecordRedaction(string signal) => Drops.Add(1, new KeyValuePair<string, object?>("signal", signal));
}

/// <summary>
/// Redacts destinations from span attributes as spans finish, before any exporter sees them.
/// </summary>
public sealed class ScrubbingActivityProcessor : BaseProcessor<Activity>
{
    public override void OnEnd(Activity data)
    {
        ArgumentNullException.ThrowIfNull(data);

        // Materialise first: tags cannot be rewritten while they are being enumerated.
        List<KeyValuePair<string, string>>? replacements = null;
        foreach (var tag in data.Tags)
        {
            var (scrubbed, redacted) = TelemetryScrubber.ScrubAttribute(tag.Key, tag.Value);
            if (redacted)
            {
                (replacements ??= []).Add(new KeyValuePair<string, string>(tag.Key, scrubbed));
            }
        }

        if (replacements is null)
        {
            return;
        }

        foreach (var (key, value) in replacements)
        {
            data.SetTag(key, value);
            ScrubMetrics.RecordRedaction("trace");
        }
    }
}

/// <summary>
/// Redacts destinations from log records — both their attributes and the message body, since a
/// hostname is as likely to be interpolated into a message as attached as an attribute.
/// </summary>
public sealed class ScrubbingLogProcessor : BaseProcessor<LogRecord>
{
    public override void OnEnd(LogRecord data)
    {
        ArgumentNullException.ThrowIfNull(data);

        if (data.Attributes is { } attributes)
        {
            List<KeyValuePair<string, object?>>? rewritten = null;
            for (var i = 0; i < attributes.Count; i++)
            {
                var attribute = attributes[i];
                if (attribute.Value is not string text)
                {
                    continue;
                }

                var (scrubbed, redacted) = TelemetryScrubber.ScrubAttribute(attribute.Key, text);
                if (!redacted)
                {
                    continue;
                }

                rewritten ??= [.. attributes];
                rewritten[i] = new KeyValuePair<string, object?>(attribute.Key, scrubbed);
                ScrubMetrics.RecordRedaction("log");
            }

            if (rewritten is not null)
            {
                data.Attributes = rewritten;
            }
        }

        if (data.FormattedMessage is { } message)
        {
            var (scrubbed, redacted) = TelemetryScrubber.ScrubText(message);
            if (redacted)
            {
                data.FormattedMessage = scrubbed;
                ScrubMetrics.RecordRedaction("log");
            }
        }

        if (data.Body is { } body)
        {
            var (scrubbed, redacted) = TelemetryScrubber.ScrubText(body);
            if (redacted)
            {
                data.Body = scrubbed;
                ScrubMetrics.RecordRedaction("log");
            }
        }
    }
}
