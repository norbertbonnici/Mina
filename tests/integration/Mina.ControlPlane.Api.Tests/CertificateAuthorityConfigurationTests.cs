using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Mina.ControlPlane.Api.Configuration;
using Mina.ControlPlane.Hosting;
using Mina.ControlPlane.KeyVault;

namespace Mina.ControlPlane.Api.Tests;

/// <summary>
/// How the host chooses its certificate authority (M2-2c). The choice is made from configuration
/// before anything is resolved, so these are the checks that a deployment pointed at a vault uses
/// it, and that one pointed nowhere is refused rather than quietly falling back to a key it
/// regenerates on every restart.
/// </summary>
public sealed class CertificateAuthorityConfigurationTests
{
    [Fact]
    public void A_production_host_with_a_database_but_no_vault_still_refuses_to_start()
    {
        // The database guard used to be the only thing standing between a mistyped deployment and a
        // running host. This is the second one: a host that has somewhere to store sessions but no
        // certificate authority would issue session certificates from a key it forgets on restart,
        // and every certificate it had issued would stop validating at that moment.
        using var factory = new PkiProductionFactory(vaultUri: null);

        var failure = Record.Exception(() => _ = factory.Services);

        Assert.NotNull(failure);
        var message = Flatten(failure!);
        Assert.Contains("Refusing to start", message, StringComparison.Ordinal);
        Assert.Contains("Mina:Pki:KeyVaultUri", message, StringComparison.Ordinal);
    }

    [Fact]
    public void The_default_object_names_are_the_ones_terraform_creates()
    {
        // These two names are the seam between the IaC and the running host: Terraform's
        // azurerm_key_vault_key is named mina-internal-ca, and mina-ca bootstrap writes the
        // certificate to mina-internal-ca-certificate. Renaming either without the other produces a
        // host that cannot find its CA, so the default is asserted rather than left to a comment.
        var options = new MinaPkiOptions { KeyVaultUri = "https://kv-example.vault.azure.net/" };

        var vault = options.ToKeyVaultOptions();

        Assert.Equal("mina-internal-ca", vault.SigningKeyName);
        Assert.Equal("mina-internal-ca-certificate", vault.CertificateSecretName);
    }

    [Theory]
    [InlineData("kv-example.vault.azure.net")]
    [InlineData("http://kv-example.vault.azure.net/")]
    [InlineData("not a uri")]
    public void A_vault_uri_that_is_not_absolute_https_is_rejected_by_name(string configured)
    {
        // http:// in particular: the CA certificate and the signature requests would cross the
        // internet from the on-premises control plane in the clear (ADR-0006 — this host reaches
        // Key Vault over the public internet, not a private endpoint).
        var options = new MinaPkiOptions { KeyVaultUri = configured };

        var failure = Assert.Throws<InvalidOperationException>(() => options.ToKeyVaultOptions());

        Assert.Contains("Mina:Pki:KeyVaultUri", failure.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void An_unset_vault_uri_is_simply_unconfigured()
    {
        Assert.False(new MinaPkiOptions().IsConfigured);
        Assert.False(new MinaPkiOptions { KeyVaultUri = "  " }.IsConfigured);
        Assert.True(new MinaPkiOptions { KeyVaultUri = "https://kv.vault.azure.net/" }.IsConfigured);
    }

    private static string Flatten(Exception exception)
    {
        var text = new System.Text.StringBuilder();
        for (var current = exception; current is not null; current = current.InnerException)
        {
            text.AppendLine(current.Message);
        }

        return text.ToString();
    }

    /// <summary>
    /// A production host configured far enough to get past every other guard, so the one under test
    /// is the one that fires. The connection string is never opened — migrations are a deployment
    /// step, not a startup step — so it does not need a database behind it.
    /// </summary>
    private sealed class PkiProductionFactory(string? vaultUri) : WebApplicationFactory<Program>
    {
        /// <summary>A real directory: the Data Protection guard creates it rather than accepting a name.</summary>
        private static readonly Lazy<string> DataProtectionDirectory = new(() =>
            Directory.CreateTempSubdirectory("mina-pki-tests").FullName);

        protected override void ConfigureWebHost(IWebHostBuilder builder)
        {
            builder.UseEnvironment("Production");
            builder.UseSetting($"{MinaListenerOptions.Section}:NodePort", "18781");
            builder.UseSetting($"{MinaListenerOptions.Section}:ManagementPort", "18782");
            builder.UseSetting("Mina:AllowDevelopmentFallbacks", "false");

            // UseSetting, not ConfigureAppConfiguration: the guards run while Program.cs composes
            // the container, which is before configuration callbacks are applied — so a value
            // supplied the other way arrives after the guard it was meant to satisfy.
            builder.UseSetting(
                "ConnectionStrings:MinaDb", "Server=tcp:unused.example,1433;Database=mina;Encrypt=True");
            builder.UseSetting(HostingGuard.DataProtectionKeyPathKey, DataProtectionDirectory.Value);
            if (vaultUri is not null)
            {
                builder.UseSetting($"{MinaPkiOptions.Section}:KeyVaultUri", vaultUri);
            }

            builder.ConfigureAppConfiguration((_, cfg) => cfg.AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["AzureAd:Instance"] = "https://login.microsoftonline.com/",
                ["AzureAd:TenantId"] = "11111111-1111-1111-1111-111111111111",
                ["AzureAd:ClientId"] = "22222222-2222-2222-2222-222222222222",
                ["Mina:Regions:Approved:0"] = "westeurope",
                ["Mina:Regions:Active:0"] = "westeurope",
                ["Mina:Egress:Regions:westeurope:Host"] = "20.0.0.1",
                ["Mina:Egress:Regions:westeurope:ServerName"] = "westeurope.egress.mina",
            }));
        }
    }
}
