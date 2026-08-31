using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using Mina.EndpointAgent.Proxy;

namespace Mina.Transport.Tests;

/// <summary>
/// An in-process stand-in for the Envoy egress: mutual-TLS listener that requires a client
/// certificate chaining to the given CA, accepts an HTTP/1.1 <c>CONNECT</c>, dials the target
/// and pipes. It exercises the exact contract the agent's tunnel client depends on (mTLS client
/// auth + CONNECT termination), so the agent side is proven without needing the real Envoy in
/// the loop. The real Envoy config is validated separately.
/// </summary>
internal sealed class TestEgress : IAsyncDisposable
{
    private readonly TcpListener _listener;
    private readonly X509Certificate2 _serverCertificate;
    private readonly X509Certificate2 _trustedCa;
    private readonly CancellationTokenSource _cts = new();
    private readonly Task _loop;

    public TestEgress(X509Certificate2 serverCertificate, X509Certificate2 trustedCa)
    {
        _serverCertificate = serverCertificate;
        _trustedCa = trustedCa;
        _listener = new TcpListener(IPAddress.Loopback, 0);
        _listener.Start();
        _loop = AcceptLoopAsync(_cts.Token);
    }

    public int ClientAuthFailures { get; private set; }

    public IPEndPoint Endpoint => (IPEndPoint)_listener.LocalEndpoint;

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
                ClientAuthFailures++;
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

/// <summary>A trivial TCP echo server standing in for a research target on the internet.</summary>
internal sealed class TcpEchoServer : IAsyncDisposable
{
    private readonly TcpListener _listener;
    private readonly CancellationTokenSource _cts = new();
    private readonly Task _loop;

    public TcpEchoServer()
    {
        _listener = new TcpListener(IPAddress.Loopback, 0);
        _listener.Start();
        _loop = AcceptLoopAsync(_cts.Token);
    }

    public int Port => ((IPEndPoint)_listener.LocalEndpoint).Port;

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

            _ = EchoAsync(socket, ct);
        }
    }

    private static async Task EchoAsync(Socket socket, CancellationToken ct)
    {
        using var connection = socket;
        await using var stream = new NetworkStream(socket, ownsSocket: false);
        var buffer = new byte[4096];
        try
        {
            int read;
            while ((read = await stream.ReadAsync(buffer, ct).ConfigureAwait(false)) > 0)
            {
                await stream.WriteAsync(buffer.AsMemory(0, read), ct).ConfigureAwait(false);
            }
        }
        catch (Exception ex) when (ex is IOException or OperationCanceledException or SocketException)
        {
            // client went away
        }
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
