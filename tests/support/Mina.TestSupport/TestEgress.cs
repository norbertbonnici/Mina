using System.Collections.Concurrent;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using Mina.EndpointAgent.Proxy;

namespace Mina.TestSupport;

/// <summary>
/// An in-process stand-in for the Envoy egress: a mutual-TLS listener that requires a client
/// certificate chaining to the given CA, accepts an HTTP/1.1 <c>CONNECT</c>, dials the target and
/// pipes. It enforces the same contract the real egress config does, so agent-side behaviour can be
/// proven without Envoy in the loop; the committed Envoy config is validated separately, and an
/// interop test drives the agent through a real Envoy.
/// </summary>
public sealed class TestEgress : IAsyncDisposable
{
    private readonly TcpListener _listener;
    private readonly X509Certificate2 _serverCertificate;
    private readonly X509Certificate2 _trustedCa;
    private readonly CancellationTokenSource _cts = new();
    private readonly Task _loop;
    private readonly ConcurrentQueue<string> _observedAuthorities = new();
    private int _clientAuthFailures;

    public TestEgress(X509Certificate2 serverCertificate, X509Certificate2 trustedCa)
    {
        _serverCertificate = serverCertificate;
        _trustedCa = trustedCa;
        _listener = new TcpListener(IPAddress.Loopback, 0);
        _listener.Start();
        _loop = AcceptLoopAsync(_cts.Token);
    }

    public IPEndPoint Endpoint => (IPEndPoint)_listener.LocalEndpoint;

    public int ClientAuthFailures => Volatile.Read(ref _clientAuthFailures);

    /// <summary>
    /// The CONNECT authorities this egress was asked for — the same plaintext hostname the real
    /// egress records as hostname telemetry (ADR-0002 Option 1), with no TLS interception.
    /// </summary>
    public IReadOnlyCollection<string> ObservedAuthorities => _observedAuthorities.ToArray();

    private async Task AcceptLoopAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            Socket socket;
            try
            {
                socket = await _listener.AcceptSocketAsync(ct).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (SocketException)
            {
                continue;
            }

            _ = HandleAsync(socket, ct);
        }
    }

    private async Task HandleAsync(Socket socket, CancellationToken ct)
    {
        using var connection = socket;
        var tls = new SslStream(new NetworkStream(socket, ownsSocket: false), leaveInnerStreamOpen: false);
        await using (tls.ConfigureAwait(false))
        {
            try
            {
                await tls.AuthenticateAsServerAsync(new SslServerAuthenticationOptions
                {
                    ServerCertificate = _serverCertificate,
                    ClientCertificateRequired = true,
                    RemoteCertificateValidationCallback = ValidateClient,
                }, ct).ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is AuthenticationException or IOException)
            {
                Interlocked.Increment(ref _clientAuthFailures);
                return;
            }

            ConnectTarget target;
            try
            {
                target = await HttpConnect.ReadConnectRequestAsync(tls, ct).ConfigureAwait(false);
            }
            catch (HttpConnectException)
            {
                return;
            }

            _observedAuthorities.Enqueue(target.ToString());

            using var upstream = new Socket(SocketType.Stream, ProtocolType.Tcp);
            try
            {
                await upstream.ConnectAsync(target.Host, target.Port, ct).ConfigureAwait(false);
            }
            catch (SocketException)
            {
                await tls.WriteAsync(HttpConnect.BuildErrorResponse(502, "Bad Gateway"), ct).ConfigureAwait(false);
                return;
            }

            await using var upstreamStream = new NetworkStream(upstream, ownsSocket: false);
            await tls.WriteAsync(HttpConnect.ConnectionEstablished, ct).ConfigureAwait(false);
            await tls.FlushAsync(ct).ConfigureAwait(false);

            using var linked = CancellationTokenSource.CreateLinkedTokenSource(ct);
            var a = tls.CopyToAsync(upstreamStream, linked.Token);
            var b = upstreamStream.CopyToAsync(tls, linked.Token);
            await Task.WhenAny(a, b).ConfigureAwait(false);
            await linked.CancelAsync().ConfigureAwait(false);
            try
            {
                await Task.WhenAll(a, b).ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is IOException or OperationCanceledException)
            {
                // expected on teardown
            }
        }
    }

    private bool ValidateClient(object sender, X509Certificate? certificate, X509Chain? chain, SslPolicyErrors errors)
    {
        if (certificate is null)
        {
            return false;
        }

        using var presented = X509CertificateLoader.LoadCertificate(certificate.GetRawCertData());
        using var verify = new X509Chain();
        verify.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
        verify.ChainPolicy.CustomTrustStore.Add(_trustedCa);
        verify.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        return verify.Build(presented);
    }

    public async ValueTask DisposeAsync()
    {
        await _cts.CancelAsync().ConfigureAwait(false);
        _listener.Stop();
        try
        {
            await _loop.ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            // expected
        }

        _cts.Dispose();
    }
}
