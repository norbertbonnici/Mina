using Mina.Observability;

namespace Mina.Observability.Tests;

/// <summary>
/// AC-014 rests on this: SigNoz must never receive the destinations analysts reached. The scrubber
/// leans towards redaction, so these cover both halves — that destinations do not survive, and that
/// ordinary operational text does.
/// </summary>
public class TelemetryScrubberTests
{
    [Theory]
    [InlineData("example.org")]
    [InlineData("www.iana.org")]
    [InlineData("subdomain.example.co.uk")]
    [InlineData("www.iana.org:443")]
    [InlineData("https://example.org/some/path?q=secret")]
    [InlineData("http://internal-thing.example:8080")]
    [InlineData("203.0.113.10")]
    [InlineData("203.0.113.10:8443")]
    [InlineData("127.0.0.1:18080")]
    public void A_destination_is_recognised(string value)
    {
        Assert.True(TelemetryScrubber.LooksLikeDestination(value));

        var (scrubbed, redacted) = TelemetryScrubber.ScrubText(value);
        Assert.True(redacted);
        Assert.DoesNotContain(value, scrubbed, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("Mina.ControlPlane.Api")]              // our own type and logger names
    [InlineData("System.InvalidOperationException")]
    [InlineData("Mina.EndpointAgent.Proxy.HttpConnect")]
    [InlineData("1.18.0")]                              // versions
    [InlineData("appsettings.json")]                    // file names
    [InlineData("Mina.slnx")]
    [InlineData("westeurope")]                          // regions
    [InlineData("mina-control-plane-api")]              // service names
    [InlineData("session_started")]
    [InlineData("")]
    public void Ordinary_operational_text_survives(string value)
    {
        Assert.False(TelemetryScrubber.LooksLikeDestination(value));

        var (scrubbed, redacted) = TelemetryScrubber.ScrubText(value);
        Assert.False(redacted);
        Assert.Equal(value, scrubbed);
    }

    [Fact]
    public void A_destination_inside_a_message_is_removed_and_the_rest_stays_readable()
    {
        var (scrubbed, redacted) = TelemetryScrubber.ScrubText(
            "Tunnel established to example.org:443 for session 8c9f");

        Assert.True(redacted);
        Assert.DoesNotContain("example.org", scrubbed, StringComparison.Ordinal);
        // The message still says what happened.
        Assert.Contains("Tunnel established to", scrubbed, StringComparison.Ordinal);
        Assert.Contains("session 8c9f", scrubbed, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("url.full")]
    [InlineData("http.url")]
    [InlineData("server.address")]
    [InlineData("network.peer.address")]
    [InlineData("mina.hostname")]
    public void Attributes_that_carry_destinations_are_redacted_whatever_they_contain(string key)
    {
        // Not just names: an opaque value under one of these keys is no more shareable.
        var (scrubbed, redacted) = TelemetryScrubber.ScrubAttribute(key, "anything-at-all");

        Assert.True(redacted);
        Assert.Equal(TelemetryScrubber.Redacted, scrubbed);
    }

    [Theory]
    [InlineData("service.name", "mina-control-plane-api")]
    [InlineData("deployment.environment", "prod")]
    [InlineData("mina.region", "westeurope")]
    [InlineData("http.route", "/api/sessions/{id}/renew")]
    [InlineData("http.response.status_code", "200")]
    public void Platform_facts_are_left_alone(string key, string value)
    {
        var (scrubbed, redacted) = TelemetryScrubber.ScrubAttribute(key, value);

        Assert.False(redacted);
        Assert.Equal(value, scrubbed);
    }

    [Fact]
    public void An_unknown_attribute_holding_a_destination_is_still_redacted()
    {
        // The point of the value check: a new attribute nobody thought to deny-list cannot leak.
        var (scrubbed, redacted) = TelemetryScrubber.ScrubAttribute(
            "some.attribute.nobody.anticipated", "research-target.example");

        Assert.True(redacted);
        Assert.DoesNotContain("research-target.example", scrubbed, StringComparison.Ordinal);
    }

    [Fact]
    public void A_null_or_empty_value_is_handled()
    {
        Assert.False(TelemetryScrubber.ScrubAttribute("anything", null).Redacted);
        Assert.False(TelemetryScrubber.ScrubText(null).Redacted);
    }
}
