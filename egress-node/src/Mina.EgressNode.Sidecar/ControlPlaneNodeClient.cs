using System.Net.Http.Headers;
using System.Net.Http.Json;

namespace Mina.EgressNode.Sidecar;

/// <summary>One observation as reported to the control plane; a null hostname means withheld.</summary>
public sealed record TelemetryItem(
    Guid SessionId,
    DateTimeOffset OccurredAt,
    string? Hostname,
    int Port,
    long BytesUp,
    long BytesDown,
    int DurationMs);

/// <summary>What the control plane did with a batch.</summary>
public sealed record TelemetryAccepted(int Recorded, int Aggregated, int Unattributable, int SuppressionMismatches);

/// <summary>Supplies the node's Entra token (its managed identity in Azure).</summary>
public interface INodeTokenProvider
{
    Task<string> GetTokenAsync(CancellationToken cancellationToken);
}

/// <summary>The node's client for the control plane: fetch the allowlist, post telemetry.</summary>
public sealed class ControlPlaneNodeClient(HttpClient httpClient, INodeTokenProvider tokens)
{
    private readonly HttpClient _httpClient = httpClient ?? throw new ArgumentNullException(nameof(httpClient));
    private readonly INodeTokenProvider _tokens = tokens ?? throw new ArgumentNullException(nameof(tokens));

    public async Task<IReadOnlyList<NodeSession>> GetSessionsAsync(string region, CancellationToken cancellationToken)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, $"api/nodes/{region}/sessions");
        using var response = await SendAsync(request, cancellationToken).ConfigureAwait(false);
        response.EnsureSuccessStatusCode();

        return await response.Content.ReadFromJsonAsync<List<NodeSession>>(cancellationToken).ConfigureAwait(false)
            ?? [];
    }

    public async Task<TelemetryAccepted> PostTelemetryAsync(
        string region, IReadOnlyList<TelemetryItem> items, CancellationToken cancellationToken)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, "api/nodes/telemetry")
        {
            Content = JsonContent.Create(new { region, items }),
        };

        using var response = await SendAsync(request, cancellationToken).ConfigureAwait(false);
        response.EnsureSuccessStatusCode();

        return await response.Content.ReadFromJsonAsync<TelemetryAccepted>(cancellationToken).ConfigureAwait(false)
            ?? new TelemetryAccepted(0, 0, 0, 0);
    }

    private async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var token = await _tokens.GetTokenAsync(cancellationToken).ConfigureAwait(false);
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        return await _httpClient.SendAsync(request, cancellationToken).ConfigureAwait(false);
    }
}
