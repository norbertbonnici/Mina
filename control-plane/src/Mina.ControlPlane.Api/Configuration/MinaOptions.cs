namespace Mina.ControlPlane.Api.Configuration;

/// <summary>Approved (D-08) and currently-active egress regions, bound from configuration.</summary>
public sealed class MinaRegionOptions
{
    public const string Section = "Mina:Regions";

    public IList<string> Approved { get; init; } = [];

    public IList<string> Active { get; init; } = [];
}

/// <summary>Egress ingress endpoints per region, bound from configuration.</summary>
public sealed class MinaEgressOptions
{
    public const string Section = "Mina:Egress";

    public IDictionary<string, EgressEndpointConfig> Regions { get; init; } =
        new Dictionary<string, EgressEndpointConfig>(StringComparer.OrdinalIgnoreCase);
}

/// <summary>Config shape for one region's egress ingress.</summary>
public sealed class EgressEndpointConfig
{
    public string Host { get; init; } = string.Empty;

    public int Port { get; init; } = 443;

    public string ServerName { get; init; } = string.Empty;
}
