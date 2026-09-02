using System.Globalization;
using System.Text.Json;

namespace Mina.EgressNode.Sidecar;

/// <summary>One connection as Envoy recorded it.</summary>
/// <param name="SessionId">From the client certificate's session SAN — how traffic is attributed.</param>
public sealed record AccessLogEntry(
    Guid SessionId,
    string Hostname,
    int Port,
    long BytesUp,
    long BytesDown,
    int DurationMs);

/// <summary>
/// Reads Envoy's `mina.hostname.v1` access-log records. Envoy writes one JSON object per
/// connection to stdout; anything else on that stream (startup output, warnings) is ignored.
/// </summary>
public static class AccessLogParser
{
    private const string SessionUriPrefix = "mina:session:";

    /// <summary>Parses one line, or returns null if it is not an attributable access-log record.</summary>
    public static AccessLogEntry? TryParse(string line)
    {
        if (string.IsNullOrWhiteSpace(line) || !line.StartsWith('{'))
        {
            return null;
        }

        try
        {
            using var document = JsonDocument.Parse(line);
            var root = document.RootElement;

            if (!root.TryGetProperty("schema", out var schema) || schema.GetString() != "mina.hostname.v1")
            {
                return null;
            }

            // A refused CONNECT is not a visit. Since M4-11 a revoked or unknown session's tunnel
            // is answered 403 by admission, and a sidecar outage 503; recording those as hostname
            // telemetry would turn attempts that never connected into destinations the analyst
            // "reached". The refusal is Envoy's access log and the sidecar's denial log; it is not
            // browsing history. Only a 2xx CONNECT — a tunnel that opened — is shipped.
            var responseCode = (int)ReadLong(root, "response_code");
            if (responseCode is < 200 or >= 300)
            {
                return null;
            }

            if (!TryReadAuthority(root, out var hostname, out var port)
                || !TryReadSession(root, out var sessionId))
            {
                // Without a session the record cannot be attributed to a user, so it is not sent:
                // the control plane would only discard it.
                return null;
            }

            return new AccessLogEntry(
                sessionId,
                hostname,
                port,
                ReadLong(root, "bytes_up"),
                ReadLong(root, "bytes_down"),
                (int)ReadLong(root, "duration_ms"));
        }
        catch (JsonException)
        {
            return null;
        }
    }

    private static bool TryReadAuthority(JsonElement root, out string hostname, out int port)
    {
        hostname = string.Empty;
        port = 0;

        if (!root.TryGetProperty("authority", out var element) || element.GetString() is not { Length: > 0 } authority)
        {
            return false;
        }

        var separator = authority.LastIndexOf(':');
        if (separator <= 0
            || !int.TryParse(authority[(separator + 1)..], NumberStyles.None, CultureInfo.InvariantCulture, out port))
        {
            // CONNECT authorities always carry a port; anything else is not a tunnel record.
            return false;
        }

        hostname = authority[..separator];
        return hostname.Length > 0;
    }

    private static bool TryReadSession(JsonElement root, out Guid sessionId)
    {
        sessionId = Guid.Empty;
        if (!root.TryGetProperty("client_cert_uri", out var element) || element.GetString() is not { } value)
        {
            return false;
        }

        var index = value.IndexOf(SessionUriPrefix, StringComparison.Ordinal);
        if (index < 0)
        {
            return false;
        }

        var candidate = value[(index + SessionUriPrefix.Length)..].TrimEnd(',', ' ', '"', ']');
        return Guid.TryParse(candidate, out sessionId);
    }

    private static long ReadLong(JsonElement root, string property)
    {
        if (!root.TryGetProperty(property, out var element))
        {
            return 0;
        }

        return element.ValueKind switch
        {
            JsonValueKind.Number => element.TryGetInt64(out var number) ? number : 0,
            JsonValueKind.String => long.TryParse(
                element.GetString(), NumberStyles.Integer, CultureInfo.InvariantCulture, out var parsed) ? parsed : 0,
            _ => 0,
        };
    }
}
