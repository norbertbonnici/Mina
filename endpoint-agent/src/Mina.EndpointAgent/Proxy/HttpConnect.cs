using System.Globalization;
using System.Text;

namespace Mina.EndpointAgent.Proxy;

/// <summary>The authority (host and port) named in an HTTP <c>CONNECT</c> request line.</summary>
public readonly record struct ConnectTarget(string Host, int Port)
{
    public override string ToString() => $"{Host}:{Port}";
}

/// <summary>
/// Minimal, allocation-light helpers for the HTTP/1.1 <c>CONNECT</c> preamble used on both legs
/// of the tunnel (browser → loopback proxy, and loopback proxy → egress). Deliberately not a
/// general HTTP parser: it reads only the request/response head, byte by byte, so it never
/// consumes tunnelled payload that follows the blank line.
/// </summary>
public static class HttpConnect
{
    private const int MaxPreambleBytes = 16 * 1024;

    public static readonly ReadOnlyMemory<byte> ConnectionEstablished =
        Encoding.ASCII.GetBytes("HTTP/1.1 200 Connection Established\r\n\r\n");

    public static ReadOnlyMemory<byte> BuildConnectRequest(ConnectTarget target)
    {
        var authority = target.ToString();
        return Encoding.ASCII.GetBytes(
            $"CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n");
    }

    public static ReadOnlyMemory<byte> BuildErrorResponse(int statusCode, string reason)
    {
        var body = $"HTTP/1.1 {statusCode} {reason}\r\nConnection: close\r\nContent-Length: 0\r\n\r\n";
        return Encoding.ASCII.GetBytes(body);
    }

    /// <summary>Reads and parses a <c>CONNECT</c> request head from <paramref name="stream"/>.</summary>
    public static async Task<ConnectTarget> ReadConnectRequestAsync(Stream stream, CancellationToken ct)
    {
        var head = await ReadHeadAsync(stream, ct).ConfigureAwait(false);
        var firstLine = head.Split("\r\n", StringSplitOptions.None)[0];
        var parts = firstLine.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length < 3 || !parts[0].Equals("CONNECT", StringComparison.Ordinal))
        {
            throw new HttpConnectException($"Only CONNECT is supported; received '{firstLine}'.");
        }

        return ParseAuthority(parts[1]);
    }

    /// <summary>Reads a response head and returns its status code (e.g. 200).</summary>
    public static async Task<int> ReadResponseStatusAsync(Stream stream, CancellationToken ct)
    {
        var head = await ReadHeadAsync(stream, ct).ConfigureAwait(false);
        var firstLine = head.Split("\r\n", StringSplitOptions.None)[0];
        var parts = firstLine.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length < 2 || !parts[0].StartsWith("HTTP/", StringComparison.Ordinal)
            || !int.TryParse(parts[1], NumberStyles.None, CultureInfo.InvariantCulture, out var status))
        {
            throw new HttpConnectException($"Malformed status line: '{firstLine}'.");
        }

        return status;
    }

    internal static ConnectTarget ParseAuthority(string authority)
    {
        var colon = authority.LastIndexOf(':');
        if (colon <= 0 || colon == authority.Length - 1)
        {
            throw new HttpConnectException($"CONNECT target '{authority}' must be host:port.");
        }

        var host = authority[..colon];
        if (!int.TryParse(authority[(colon + 1)..], NumberStyles.None, CultureInfo.InvariantCulture, out var port)
            || port is < 1 or > 65535)
        {
            throw new HttpConnectException($"CONNECT target '{authority}' has an invalid port.");
        }

        return new ConnectTarget(host, port);
    }

    private static async Task<string> ReadHeadAsync(Stream stream, CancellationToken ct)
    {
        var buffer = new byte[MaxPreambleBytes];
        var count = 0;
        var single = new byte[1];
        while (count < MaxPreambleBytes)
        {
            var read = await stream.ReadAsync(single, ct).ConfigureAwait(false);
            if (read == 0)
            {
                throw new HttpConnectException("Connection closed before the request head completed.");
            }

            buffer[count++] = single[0];
            if (count >= 4
                && buffer[count - 4] == (byte)'\r' && buffer[count - 3] == (byte)'\n'
                && buffer[count - 2] == (byte)'\r' && buffer[count - 1] == (byte)'\n')
            {
                return Encoding.ASCII.GetString(buffer, 0, count - 4);
            }
        }

        throw new HttpConnectException("Request head exceeded the maximum permitted size.");
    }
}

/// <summary>Raised when a CONNECT preamble is malformed or unsupported.</summary>
public sealed class HttpConnectException : Exception
{
    public HttpConnectException()
    {
    }

    public HttpConnectException(string message)
        : base(message)
    {
    }

    public HttpConnectException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}
