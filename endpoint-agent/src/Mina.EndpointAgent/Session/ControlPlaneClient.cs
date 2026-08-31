using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Cryptography;

namespace Mina.EndpointAgent.Session;

/// <summary>A session grant as returned by the control plane.</summary>
public sealed record SessionGrantResponse(
    Guid SessionId,
    string CertificatePem,
    string CertificateSerialNumber,
    string Region,
    string EgressHost,
    int EgressPort,
    string EgressServerName,
    DateTimeOffset LeaseExpiresAt,
    string Mode);

/// <summary>Raised when the control plane refuses or cannot service a session request.</summary>
public sealed class ControlPlaneException : Exception
{
    public ControlPlaneException()
    {
    }

    public ControlPlaneException(string message)
        : base(message)
    {
    }

    public ControlPlaneException(string message, Exception innerException)
        : base(message, innerException)
    {
    }

    public ControlPlaneException(string message, HttpStatusCode statusCode)
        : base(message)
    {
        StatusCode = statusCode;
    }

    public HttpStatusCode? StatusCode { get; }
}

/// <summary>
/// Talks to the control-plane session API. Every call carries a freshly acquired Entra token, and
/// every issuance/renewal sends a CSR whose private key stays on the endpoint.
/// </summary>
public sealed class ControlPlaneClient(HttpClient httpClient, IAccessTokenProvider tokenProvider)
{
    private readonly HttpClient _httpClient = httpClient ?? throw new ArgumentNullException(nameof(httpClient));

    private readonly IAccessTokenProvider _tokenProvider =
        tokenProvider ?? throw new ArgumentNullException(nameof(tokenProvider));

    public async Task<SessionGrantResponse> IssueAsync(string region, byte[] csr, CancellationToken cancellationToken)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, "api/sessions")
        {
            Content = JsonContent.Create(new { region, csrPem = ToPem(csr) }),
        };

        return await SendForGrantAsync(request, cancellationToken).ConfigureAwait(false);
    }

    public async Task<SessionGrantResponse> RenewAsync(Guid sessionId, byte[] csr, CancellationToken cancellationToken)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, $"api/sessions/{sessionId}/renew")
        {
            Content = JsonContent.Create(new { csrPem = ToPem(csr) }),
        };

        return await SendForGrantAsync(request, cancellationToken).ConfigureAwait(false);
    }

    public async Task EndAsync(Guid sessionId, CancellationToken cancellationToken)
    {
        using var request = new HttpRequestMessage(HttpMethod.Delete, $"api/sessions/{sessionId}");
        using var response = await SendAsync(request, cancellationToken).ConfigureAwait(false);
        if (!response.IsSuccessStatusCode && response.StatusCode != HttpStatusCode.NotFound)
        {
            throw new ControlPlaneException(
                $"Ending session {sessionId} failed with {(int)response.StatusCode}.", response.StatusCode);
        }
    }

    private async Task<SessionGrantResponse> SendForGrantAsync(
        HttpRequestMessage request, CancellationToken cancellationToken)
    {
        using var response = await SendAsync(request, cancellationToken).ConfigureAwait(false);
        if (!response.IsSuccessStatusCode)
        {
            throw new ControlPlaneException(
                $"The control plane refused the session request with {(int)response.StatusCode}.",
                response.StatusCode);
        }

        return await response.Content.ReadFromJsonAsync<SessionGrantResponse>(cancellationToken).ConfigureAwait(false)
            ?? throw new ControlPlaneException("The control plane returned an empty session grant.");
    }

    private async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var token = await _tokenProvider.GetAccessTokenAsync(cancellationToken).ConfigureAwait(false);
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        return await _httpClient.SendAsync(request, cancellationToken).ConfigureAwait(false);
    }

    private static string ToPem(byte[] csr) => PemEncoding.WriteString("CERTIFICATE REQUEST", csr);
}
