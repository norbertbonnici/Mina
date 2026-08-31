using System.Text.RegularExpressions;

namespace Mina.Observability;

/// <summary>
/// Removes anything that looks like a research destination from operational telemetry before it
/// leaves the platform for SigNoz.
/// </summary>
/// <remarks>
/// SigNoz is an operational tool, not an investigative one: it must never receive the hostnames
/// analysts reached (LOGGING_AND_PRIVACY §6, AC-014). Those belong to data class C3, which has its
/// own store, retention and access controls.
///
/// The rule is deliberately strict. Rather than trying to enumerate every attribute that might one
/// day carry a destination, anything that *looks* like a hostname or URL is redacted unless its
/// attribute name is on a short allow-list of values known to be ours — service names, regions,
/// route templates. A redacted operational attribute is an inconvenience; a leaked destination is
/// not recoverable, so the default leans to redaction.
/// </remarks>
public static partial class TelemetryScrubber
{
    public const string Redacted = "[redacted]";

    /// <summary>
    /// Attribute names whose values are platform facts, not research destinations, and so are left
    /// alone even when they resemble one.
    /// </summary>
    private static readonly HashSet<string> AllowedKeys = new(StringComparer.OrdinalIgnoreCase)
    {
        "service.name",
        "service.version",
        "service.instance.id",
        "deployment.environment",
        "deployment.environment.name",
        "mina.region",
        "http.route",
        "http.request.method",
        "http.response.status_code",
        "otel.status_code",
        "otel.scope.name",
        "telemetry.sdk.name",
        "telemetry.sdk.language",
        "telemetry.sdk.version",
    };

    /// <summary>
    /// Attribute names that carry a destination often enough to redact wholesale, whatever the
    /// value looks like — an IP address or an opaque identifier is no more shareable than a name.
    /// </summary>
    private static readonly HashSet<string> AlwaysRedactedKeys = new(StringComparer.OrdinalIgnoreCase)
    {
        "url.full",
        "url.path",
        "url.query",
        "http.url",
        "http.target",
        "server.address",
        "network.peer.address",
        "client.address",
        "mina.hostname",
        "authority",
        "host",
    };

    /// <summary>Scrubs one attribute value, returning the result and whether anything was removed.</summary>
    public static (string Value, bool Redacted) ScrubAttribute(string key, string? value)
    {
        if (string.IsNullOrEmpty(value))
        {
            return (value ?? string.Empty, false);
        }

        if (AlwaysRedactedKeys.Contains(key))
        {
            return (Redacted, true);
        }

        if (AllowedKeys.Contains(key))
        {
            return (value, false);
        }

        return ScrubText(value);
    }

    /// <summary>
    /// Replaces hostname- and URL-shaped substrings inside free text — a log message, say — leaving
    /// the rest readable so the record still says what happened.
    /// </summary>
    public static (string Value, bool Redacted) ScrubText(string? text)
    {
        if (string.IsNullOrEmpty(text))
        {
            return (text ?? string.Empty, false);
        }

        var scrubbed = DestinationPattern().Replace(text, Redacted);
        return (scrubbed, !string.Equals(scrubbed, text, StringComparison.Ordinal));
    }

    /// <summary>Whether a value would be redacted — used by tests and content scans.</summary>
    public static bool LooksLikeDestination(string? value) =>
        !string.IsNullOrEmpty(value) && DestinationPattern().IsMatch(value);

    /// <summary>
    /// Matches the four shapes a destination takes in text: a URL with a scheme, a dotted name with
    /// a port, an IPv4 address, and a bare domain name.
    /// </summary>
    /// <remarks>
    /// The bare-domain branch requires the final label to be lower-case, which is what keeps
    /// ordinary log text intact: <c>example.org</c> is redacted while <c>Mina.ControlPlane.Api</c>
    /// and <c>System.InvalidOperationException</c> are not, because their last label is
    /// capitalised. Common file suffixes are excluded for the same reason, so a message about
    /// <c>appsettings.json</c> still reads. IPv4 addresses are redacted whether or not they are
    /// internal: losing <c>127.0.0.1</c> from a log line costs little next to letting a research
    /// target through.
    /// </remarks>
    [GeneratedRegex(
        """
        \b(?:
            [A-Za-z][A-Za-z0-9+.\-]*://\S+
          | (?:[A-Za-z0-9](?:[A-Za-z0-9\-]*[A-Za-z0-9])?\.)+[A-Za-z]{2,24}:\d{1,5}
          | \d{1,3}(?:\.\d{1,3}){3}(?::\d{1,5})?
          | (?:[A-Za-z0-9](?:[A-Za-z0-9\-]*[A-Za-z0-9])?\.)+
            (?!(?:json|xml|yaml|yml|cs|csproj|sln|slnx|dll|exe|pdb|log|txt|md|config|html|css|js|razor)\b)
            [a-z]{2,24}\b
        )
        """,
        RegexOptions.CultureInvariant | RegexOptions.IgnorePatternWhitespace)]
    private static partial Regex DestinationPattern();
}
