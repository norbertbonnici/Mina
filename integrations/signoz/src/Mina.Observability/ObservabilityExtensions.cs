using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using OpenTelemetry.Logs;
using OpenTelemetry.Metrics;
using OpenTelemetry.Resources;
using OpenTelemetry.Trace;

namespace Mina.Observability;

/// <summary>Where operational telemetry goes and how it is labelled.</summary>
public sealed class ObservabilityOptions
{
    public const string Section = "Mina:Observability";

    /// <summary>OTLP endpoint of the SigNoz collector. Telemetry is not exported when unset.</summary>
    public Uri? OtlpEndpoint { get; set; }

    /// <summary>Value for <c>service.name</c>.</summary>
    public string ServiceName { get; set; } = "mina-control-plane";

    /// <summary>Value for <c>deployment.environment</c>.</summary>
    public string Environment { get; set; } = "dev";

    /// <summary>Value for <c>mina.region</c>, where the component belongs to one.</summary>
    public string? Region { get; set; }
}

public static class ObservabilityExtensions
{
    /// <summary>
    /// Wires OpenTelemetry for SigNoz, with the scrub processors installed on both the trace and
    /// log pipelines.
    /// </summary>
    /// <remarks>
    /// The scrubbers are added first, so they run before any exporter — including one someone adds
    /// later — sees a span or log record. There is no configuration switch to disable them: an
    /// operational pipeline that could be pointed at analysts' destinations by flipping a setting
    /// would be exactly the accident AC-014 exists to prevent.
    ///
    /// This matters most for the endpoint agent, which necessarily knows every destination it
    /// tunnels to and logs them while debugging. Set <paramref name="aspNetCore"/> to false for
    /// worker hosts like the agent and the node sidecar, which have no HTTP server to instrument.
    /// </remarks>
    public static IServiceCollection AddMinaObservability(
        this IServiceCollection services, IConfiguration configuration, bool aspNetCore = true)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configuration);

        services.Configure<ObservabilityOptions>(configuration.GetSection(ObservabilityOptions.Section));
        var options = configuration.GetSection(ObservabilityOptions.Section).Get<ObservabilityOptions>()
            ?? new ObservabilityOptions();

        services.AddSingleton<MinaMetrics>();

        var resource = ResourceBuilder.CreateDefault()
            .AddService(options.ServiceName)
            .AddAttributes(BuildResourceAttributes(options));

        services.AddOpenTelemetry()
            .WithTracing(tracing =>
            {
                tracing
                    .SetResourceBuilder(resource)
                    .AddProcessor(new ScrubbingActivityProcessor());

                if (aspNetCore)
                {
                    tracing.AddAspNetCoreInstrumentation();
                }

                if (options.OtlpEndpoint is not null)
                {
                    tracing.AddOtlpExporter(exporter => exporter.Endpoint = options.OtlpEndpoint);
                }
            })
            .WithMetrics(metrics =>
            {
                metrics
                    .SetResourceBuilder(resource)
                    .AddMeter(MinaMetrics.MeterName)
                    .AddMeter(ScrubMetrics.MeterName)
                    .AddRuntimeInstrumentation();

                if (aspNetCore)
                {
                    metrics.AddAspNetCoreInstrumentation();
                }

                if (options.OtlpEndpoint is not null)
                {
                    metrics.AddOtlpExporter(exporter => exporter.Endpoint = options.OtlpEndpoint);
                }
            });

        services.AddLogging(logging => logging.AddOpenTelemetry(otel =>
        {
            otel.SetResourceBuilder(resource);
            otel.IncludeFormattedMessage = true;
            otel.AddProcessor(new ScrubbingLogProcessor());

            if (options.OtlpEndpoint is not null)
            {
                otel.AddOtlpExporter(exporter => exporter.Endpoint = options.OtlpEndpoint);
            }
        }));

        return services;
    }

    private static IEnumerable<KeyValuePair<string, object>> BuildResourceAttributes(ObservabilityOptions options)
    {
        yield return new KeyValuePair<string, object>("deployment.environment", options.Environment);
        if (!string.IsNullOrWhiteSpace(options.Region))
        {
            yield return new KeyValuePair<string, object>("mina.region", options.Region);
        }
    }
}
