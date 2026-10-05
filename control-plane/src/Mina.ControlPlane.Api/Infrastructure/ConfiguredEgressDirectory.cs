using Microsoft.Extensions.Options;
using Mina.ControlPlane.Api.Configuration;
using Mina.ControlPlane.Application.Sessions;

namespace Mina.ControlPlane.Api.Infrastructure;

/// <summary>Resolves a region to its egress ingress endpoint from bound configuration.</summary>
public sealed class ConfiguredEgressDirectory(IOptions<MinaEgressOptions> options) : IEgressDirectory
{
    private readonly MinaEgressOptions _options = options.Value;

    public EgressEndpointInfo? Resolve(string region)
    {
        if (string.IsNullOrWhiteSpace(region) || !_options.Regions.TryGetValue(region, out var endpoint))
        {
            return null;
        }

        return new EgressEndpointInfo(endpoint.Host, endpoint.Port, endpoint.ServerName);
    }
}
