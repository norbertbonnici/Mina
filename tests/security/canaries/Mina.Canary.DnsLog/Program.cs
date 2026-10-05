// DNS canary (TEST_STRATEGY §2): a minimal authoritative responder for the canary zone.
// Logs every query's resolver source address and QNAME as JSON lines, and answers A queries
// with a fixed address so lookups succeed. Leak tests resolve unique subdomains from the
// research context and assert the observed resolver is an Azure egress address — never a
// corporate resolver (AC-005). UDP only; deliberately not a general-purpose DNS server.
//
// Usage: Mina.Canary.DnsLog [port] [answer-ip]   (defaults: 5353, 192.0.2.53)

using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;

var port = args.Length > 0 ? int.Parse(args[0], CultureInfo.InvariantCulture) : 5353;
var answerIp = IPAddress.Parse(args.Length > 1 ? args[1] : "192.0.2.53");

using var socket = new UdpClient(new IPEndPoint(IPAddress.Any, port));
Console.Error.WriteLine($"mina-canary-dnslog listening on udp/{port}, answering A queries with {answerIp}");

while (true)
{
    UdpReceiveResult datagram;
    try
    {
        datagram = await socket.ReceiveAsync().ConfigureAwait(false);
    }
    catch (SocketException)
    {
        continue; // e.g. ICMP port-unreachable surfaced from a previous send
    }

    var query = datagram.Buffer;
    var question = DnsWire.ParseQuestion(query);
    if (question is not { } q)
    {
        continue;
    }

    Console.WriteLine(JsonSerializer.Serialize(new
    {
        observed_at_utc = DateTimeOffset.UtcNow,
        resolver = datagram.RemoteEndPoint.ToString(),
        qname = q.Name,
        qtype = q.Type,
    }));

    var response = DnsWire.BuildResponse(query, q, answerIp);
    try
    {
        await socket.SendAsync(response, response.Length, datagram.RemoteEndPoint).ConfigureAwait(false);
    }
    catch (SocketException)
    {
        // resolver went away; nothing to do
    }
}

internal readonly record struct DnsQuestion(string Name, ushort Type, int SectionEnd);

internal static class DnsWire
{
    private const int HeaderLength = 12;

    /// <summary>Parses the first question of a query; null for anything malformed.</summary>
    public static DnsQuestion? ParseQuestion(byte[] message)
    {
        if (message.Length < HeaderLength + 5)
        {
            return null;
        }

        var qdCount = (message[4] << 8) | message[5];
        if (qdCount < 1)
        {
            return null;
        }

        var name = new StringBuilder();
        var offset = HeaderLength;
        while (true)
        {
            if (offset >= message.Length)
            {
                return null;
            }

            int labelLength = message[offset];
            if ((labelLength & 0xC0) != 0)
            {
                return null; // compression is invalid in a query's first question
            }

            offset++;
            if (labelLength == 0)
            {
                break;
            }

            if (offset + labelLength > message.Length)
            {
                return null;
            }

            if (name.Length > 0)
            {
                name.Append('.');
            }

            name.Append(Encoding.ASCII.GetString(message, offset, labelLength));
            offset += labelLength;
        }

        if (offset + 4 > message.Length)
        {
            return null;
        }

        var qtype = (ushort)((message[offset] << 8) | message[offset + 1]);
        return new DnsQuestion(name.ToString(), qtype, offset + 4);
    }

    /// <summary>
    /// Builds a NOERROR authoritative response echoing the question; A queries (type 1) get a
    /// single answer record pointing at <paramref name="answerIp"/>, everything else gets an
    /// empty answer section.
    /// </summary>
    public static byte[] BuildResponse(byte[] query, DnsQuestion question, IPAddress answerIp)
    {
        var answerA = question.Type == 1;
        var length = question.SectionEnd + (answerA ? 16 : 0);
        var response = new byte[length];
        Array.Copy(query, response, question.SectionEnd);

        response[2] = (byte)(0x84 | (query[2] & 0x01)); // QR=1, AA=1, preserve RD
        response[3] = 0x00;                             // RA=0, RCODE=NOERROR
        response[4] = 0x00;
        response[5] = 0x01;                             // QDCOUNT=1
        response[6] = 0x00;
        response[7] = (byte)(answerA ? 1 : 0);          // ANCOUNT
        response[8] = response[9] = response[10] = response[11] = 0; // NSCOUNT/ARCOUNT

        if (answerA)
        {
            var o = question.SectionEnd;
            response[o++] = 0xC0; // name: pointer to offset 12
            response[o++] = 0x0C;
            response[o++] = 0x00; // TYPE A
            response[o++] = 0x01;
            response[o++] = 0x00; // CLASS IN
            response[o++] = 0x01;
            response[o++] = 0x00; // TTL 60s
            response[o++] = 0x00;
            response[o++] = 0x00;
            response[o++] = 0x3C;
            response[o++] = 0x00; // RDLENGTH 4
            response[o++] = 0x04;
            answerIp.GetAddressBytes().CopyTo(response, o);
        }

        return response;
    }
}
