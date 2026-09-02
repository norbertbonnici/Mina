using System.Buffers;
using System.Text.Json;

namespace Mina.EndpointAgent.Ipc;

/// <summary>Raised when the peer sends something that is not a well-formed frame.</summary>
public sealed class TrayProtocolException : Exception
{
    public TrayProtocolException()
    {
    }

    public TrayProtocolException(string message)
        : base(message)
    {
    }

    public TrayProtocolException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}

/// <summary>
/// Newline-delimited JSON framing, used identically by both ends. Reads are bounded by
/// <see cref="TrayProtocol.MaxFrameBytes"/> so neither side can be held open, or grown without
/// limit, by a peer that never terminates a frame.
/// </summary>
public static class TrayFraming
{
    private const byte Newline = (byte)'\n';

    public static async Task WriteAsync<T>(
        Stream stream, T message, System.Text.Json.Serialization.Metadata.JsonTypeInfo<T> typeInfo,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(stream);

        var json = JsonSerializer.SerializeToUtf8Bytes(message, typeInfo);
        if (json.Length + 1 > TrayProtocol.MaxFrameBytes)
        {
            throw new TrayProtocolException(
                $"Frame of {json.Length} bytes exceeds the {TrayProtocol.MaxFrameBytes}-byte limit.");
        }

        var buffer = new byte[json.Length + 1];
        json.CopyTo(buffer, 0);
        buffer[^1] = Newline;

        await stream.WriteAsync(buffer, cancellationToken).ConfigureAwait(false);
        await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Reads one frame. Returns null when the peer closed cleanly between frames, which is normal —
    /// the tray disconnects whenever its panel closes.
    /// </summary>
    public static async Task<T?> ReadAsync<T>(
        Stream stream, System.Text.Json.Serialization.Metadata.JsonTypeInfo<T> typeInfo,
        CancellationToken cancellationToken)
        where T : class
    {
        ArgumentNullException.ThrowIfNull(stream);

        var accumulated = new ArrayBufferWriter<byte>(512);
        var chunk = ArrayPool<byte>.Shared.Rent(1024);
        try
        {
            while (true)
            {
                var read = await stream.ReadAsync(chunk.AsMemory(), cancellationToken).ConfigureAwait(false);
                if (read == 0)
                {
                    if (accumulated.WrittenCount == 0)
                    {
                        return null;
                    }

                    throw new TrayProtocolException("The peer closed the pipe part-way through a frame.");
                }

                var span = chunk.AsSpan(0, read);
                var newlineAt = span.IndexOf(Newline);
                if (newlineAt < 0)
                {
                    Append(accumulated, span);
                    continue;
                }

                Append(accumulated, span[..newlineAt]);

                // Anything after the newline would be a second frame written before this one was
                // answered. The protocol is strictly request/response, so that is a protocol error
                // rather than something to buffer.
                if (newlineAt + 1 != read)
                {
                    throw new TrayProtocolException("The peer sent a second frame before the first was answered.");
                }

                return Deserialize(accumulated.WrittenSpan, typeInfo);
            }
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(chunk);
        }
    }

    private static void Append(ArrayBufferWriter<byte> accumulated, ReadOnlySpan<byte> span)
    {
        if (accumulated.WrittenCount + span.Length > TrayProtocol.MaxFrameBytes)
        {
            throw new TrayProtocolException(
                $"Frame exceeds the {TrayProtocol.MaxFrameBytes}-byte limit before any newline.");
        }

        accumulated.Write(span);
    }

    private static T Deserialize<T>(
        ReadOnlySpan<byte> utf8, System.Text.Json.Serialization.Metadata.JsonTypeInfo<T> typeInfo)
        where T : class
    {
        try
        {
            return JsonSerializer.Deserialize(utf8, typeInfo)
                ?? throw new TrayProtocolException("The peer sent a null frame.");
        }
        catch (JsonException ex)
        {
            // Deliberately does not echo the payload: it came from another local process, and
            // repeating it into the agent's log would let that process write the agent's log.
            throw new TrayProtocolException(
                $"The peer sent {utf8.Length} bytes that are not valid JSON.", ex);
        }
    }
}
