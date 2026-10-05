using System.Security.Cryptography.X509Certificates;
using Azure.Identity;
using Mina.ControlPlane.KeyVault;
using Mina.ControlPlane.Pki;

namespace Mina.Ca;

/// <summary>
/// Operator tool for the internal CA (M2-2c). Two things Terraform cannot do and the running
/// control plane deliberately must not do.
/// </summary>
/// <remarks>
/// <para>
/// Terraform creates the signing key but cannot give it a certificate: Key Vault's own certificate
/// objects are always end-entity (cA=false), so a CA certificate for a vault-held key has to be
/// assembled by something that can drive an X.509 signing request through the vault's sign
/// operation. That is <c>bootstrap</c>.
/// </para>
/// <para>
/// The control plane must not do it either. A service that can mint its own root of trust can
/// replace the root of trust, and "the API silently re-rooted the platform" is not a failure mode
/// worth having for the sake of avoiding one operator command. So the API only ever reads the CA
/// certificate; creating one is an explicit, audited act by a person with Key Vault Secrets Officer
/// rights, which the control plane's own identity is not granted.
/// </para>
/// </remarks>
public static class Program
{
    public static async Task<int> Main(string[] args)
    {
        try
        {
            return args is [var command, ..]
                ? command switch
                {
                    "bootstrap" => await BootstrapAsync(Arguments.Parse(args[1..])).ConfigureAwait(false),
                    "show" => await ShowAsync(Arguments.Parse(args[1..])).ConfigureAwait(false),
                    "rotation-check" => await RotationCheckAsync(Arguments.Parse(args[1..])).ConfigureAwait(false),
                    "-h" or "--help" or "help" => Usage(),
                    _ => Fail($"Unknown command '{command}'."),
                }
                : Usage();
        }
        catch (Exception ex) when (ex is InvalidOperationException or ArgumentException)
        {
            return Fail(ex.Message);
        }
    }

    private static async Task<int> BootstrapAsync(Arguments arguments)
    {
        var options = arguments.CaOptions();
        var commonName = arguments.Value("common-name") ?? "Mina Internal CA";
        var lifetime = TimeSpan.FromDays(arguments.Number("lifetime-days") ?? 1825);
        var replace = arguments.Flag("replace");

        var credential = new DefaultAzureCredential();
        var signer = await KeyVaultCaSigner
            .CreateAsync(options.VaultUri, options.SigningKeyName, credential)
            .ConfigureAwait(false);

        Console.WriteLine($"Signing key : {signer.KeyDescription}");
        Console.WriteLine($"Digest      : {signer.HashAlgorithm.Name}");

        // Backdated by five minutes so a control-plane host whose clock is a little behind does not
        // reject a certificate that was valid when it was written.
        var notBefore = DateTimeOffset.UtcNow.AddMinutes(-5);
        using var certificate = CertificateAuthority.SelfSignFromRemoteSigner(
            commonName, signer, notBefore, lifetime);

        if (arguments.Flag("dry-run"))
        {
            // Signing is the half that can fail in interesting ways — the vault's raw r‖s signature
            // has to be re-encoded for X.509, and the curve has to match the digest. This proves
            // that half against the real vault without writing anything or needing the rights to.
            Console.WriteLine("Stored      : no — --dry-run");
            Describe(certificate);
            Console.WriteLine();
            Console.WriteLine(certificate.ExportCertificatePem());
            return 0;
        }

        var store = new KeyVaultCaCertificateStore(options.VaultUri, credential);
        await store.StoreAsync(options.CertificateSecretName, certificate, replace).ConfigureAwait(false);

        Console.WriteLine($"Stored      : {options.VaultUri}secrets/{options.CertificateSecretName}");
        Describe(certificate);
        Console.WriteLine();
        Console.WriteLine("Distribute the PEM below as the trust root (egress nodes' ca.crt, endpoint agents).");
        Console.WriteLine(certificate.ExportCertificatePem());
        return 0;
    }

    private static async Task<int> ShowAsync(Arguments arguments)
    {
        var options = arguments.CaOptions();
        var credential = new DefaultAzureCredential();

        // Loading it the way the control plane does — including the certificate/key match check —
        // so a green `show` means the API would start, not merely that a secret exists.
        using var authority = await KeyVaultCertificateAuthority.LoadAsync(options, credential)
            .ConfigureAwait(false);
        using var certificate = authority.PublicCertificate;

        Console.WriteLine($"Vault       : {options.VaultUri}");
        Describe(certificate);
        Console.WriteLine("Certificate and signing key match; the control plane would start on this vault.");
        Console.WriteLine();
        Console.WriteLine(certificate.ExportCertificatePem());
        return 0;
    }

    private static async Task<int> RotationCheckAsync(Arguments arguments)
    {
        var options = arguments.CaOptions();
        var credential = new DefaultAzureCredential();
        var warnDays = arguments.Number("warn-days");
        var criticalDays = arguments.Number("critical-days");
        var reportSql = arguments.Value("report-sql");
        var environment = arguments.Value("environment") ?? "dev";

        // Loaded the same way `show` and the control plane itself load it -- a rotation-check that
        // used a different path could pass while the certificate the API would actually start on
        // is a different one, or vice versa.
        using var authority = await KeyVaultCertificateAuthority.LoadAsync(options, credential)
            .ConfigureAwait(false);
        using var certificate = authority.PublicCertificate;

        var status = CaRotationStatus.Classify(
            certificate.NotAfter,
            DateTimeOffset.UtcNow,
            warnDays is { } w ? TimeSpan.FromDays(w) : null,
            criticalDays is { } c ? TimeSpan.FromDays(c) : null);

        Console.WriteLine($"Vault       : {options.VaultUri}");
        Describe(certificate);
        Console.WriteLine($"Status      : {status.Urgency} ({status.DaysRemaining} day(s) remaining)");

        switch (status.Urgency)
        {
            case RotationUrgency.Critical:
                Console.WriteLine();
                Console.WriteLine("CRITICAL: plan a rollover now -- `mina-ca bootstrap --replace`, then");
                Console.WriteLine("redistribute the new CA PEM to every endpoint agent package");
                Console.WriteLine("(egress nodes pick it up on their own from /api/nodes/.../certificate,");
                Console.WriteLine("endpoint agents do not -- see OPERATIONS.md's CA rollover runbook).");
                break;
            case RotationUrgency.Warning:
                Console.WriteLine();
                Console.WriteLine("WARNING: start planning a rollover. See OPERATIONS.md's CA rollover runbook.");
                break;
            case RotationUrgency.Healthy:
            default:
                break;
        }

        // Reporting (M4-2's own deferred "monitoring-integration decision", now made): writes a
        // ca_rotation_status audit event through the same hash-chained store every other audit
        // event uses, so the API's already-running WazuhDeliveryBackgroundService picks it up and
        // ships it on its next tick -- no separate Wazuh-specific code in this tool at all.
        // Opt-in via --report-sql: this command still needs only read rights on the vault with it
        // omitted, matching the read-only contract the help text and OPERATIONS.md both promise.
        if (reportSql is not null)
        {
            Console.WriteLine();
            Console.WriteLine("Reporting  : writing ca_rotation_status to the audit chain...");
            await RotationReport.ReportAsync(
                RotationReport.ToAuditDraft(status, options.VaultUri), reportSql, environment, CancellationToken.None)
                .ConfigureAwait(false);
            Console.WriteLine("Reporting  : done.");
        }

        // Exit 0 regardless of urgency: this command succeeded at checking, which is a different
        // fact from what it found. A monitoring integration that wants a distinct exit code per
        // urgency can parse the printed Status line, or (as of M4-2's reporting half) consume the
        // ca_rotation_status audit event via --report-sql instead. A --report-sql failure is a
        // different kind of failure -- the check itself still succeeded -- and is surfaced as a
        // thrown InvalidOperationException by RotationReport.ReportAsync, caught by Main's own
        // top-level handler and returned as a non-zero exit, same as any other bad-input failure.
        return 0;
    }

    private static void Describe(X509Certificate2 certificate)
    {
        Console.WriteLine($"Subject     : {certificate.Subject}");
        Console.WriteLine($"Serial      : {certificate.SerialNumber}");
        Console.WriteLine($"Valid       : {certificate.NotBefore.ToUniversalTime():u} .. "
            + $"{certificate.NotAfter.ToUniversalTime():u}");
        Console.WriteLine($"SHA-256     : {certificate.GetCertHashString(System.Security.Cryptography.HashAlgorithmName.SHA256)}");
    }

    private static int Usage()
    {
        Console.WriteLine("""
            mina-ca — internal CA bootstrap for the Mina control plane (BACKLOG M2-2c)

              mina-ca bootstrap --vault <uri> [options]
                  Self-signs a CA certificate with the vault's signing key and stores it beside the
                  key. Run once per vault; refuses to overwrite an existing certificate.

              mina-ca show --vault <uri> [options]
                  Loads the CA exactly as the control plane does and prints it.

              mina-ca rotation-check --vault <uri> [--warn-days n] [--critical-days n]
                                     [--report-sql <connection-string>] [--environment <name>] [options]
                  Reports how close the CA certificate is to expiry (M4-2). Read-only against the
                  vault -- needs only the rights `show` needs, nothing that could write to it.
                  Prints Healthy, Warning or Critical. With --report-sql, also writes a
                  ca_rotation_status audit event (EVENT_SCHEMAS.md) to the control-plane database,
                  which the running API's own Wazuh delivery pipeline then ships on its next tick --
                  see OPERATIONS.md's "Internal CA rollover" runbook for how to schedule this.

            Options
              --vault <uri>            Key Vault URI (Terraform output key_vault_uri). Required.
              --key <name>             Signing key name. Default: mina-internal-ca
              --secret <name>          Certificate secret name. Default: mina-internal-ca-certificate
              --common-name <cn>       Subject CN for bootstrap. Default: Mina Internal CA
              --lifetime-days <n>      CA validity for bootstrap. Default: 1825 (5 years)
              --dry-run                Sign a CA certificate with the vault key and print it
                                       without storing anything. Needs only the sign permission.
              --replace                Overwrite an existing certificate. This is a CA rollover
                                       (M4-2): every certificate issued under the old root stops
                                       validating. Not a bootstrap flag.
              --warn-days <n>          rotation-check: days before expiry counted as Warning.
                                       Default: 365
              --critical-days <n>      rotation-check: days before expiry counted as Critical.
                                       Default: 90
              --report-sql <cs>        rotation-check: also write the result as a ca_rotation_status
                                       audit event over this SQL connection string (same shape the
                                       control-plane API itself uses -- e.g.
                                       "Server=<host>;Database=Mina;Authentication=Active Directory
                                       Default;Encrypt=True;TrustServerCertificate=True"). Omit to
                                       check without reporting; the printed Status line still shows.
              --environment <name>     rotation-check --report-sql: environment stamped on the
                                       written event (dev/test/prod). Default: dev

            Credentials come from DefaultAzureCredential — `az login` for an operator, the host's
            managed identity on a deployed control plane. Bootstrap needs Key Vault Crypto User (to
            sign) and Key Vault Secrets Officer (to write the certificate).
            """);
        return 0;
    }

    private static int Fail(string message)
    {
        Console.Error.WriteLine($"mina-ca: {message}");
        Console.Error.WriteLine("Run `mina-ca --help` for usage.");
        return 1;
    }

    /// <summary>Minimal <c>--name value</c> / <c>--flag</c> parsing; no dependency worth adding for it.</summary>
    private sealed class Arguments
    {
        private readonly Dictionary<string, string?> _values = new(StringComparer.Ordinal);

        public static Arguments Parse(string[] args)
        {
            var parsed = new Arguments();
            for (var i = 0; i < args.Length; i++)
            {
                if (!args[i].StartsWith("--", StringComparison.Ordinal))
                {
                    throw new ArgumentException($"Unexpected argument '{args[i]}'.");
                }

                var name = args[i][2..];
                var hasValue = i + 1 < args.Length && !args[i + 1].StartsWith("--", StringComparison.Ordinal);
                parsed._values[name] = hasValue ? args[++i] : null;
            }

            return parsed;
        }

        public string? Value(string name) => _values.GetValueOrDefault(name);

        public bool Flag(string name) => _values.ContainsKey(name);

        public int? Number(string name) =>
            Value(name) is { } text
                ? int.TryParse(text, out var value) && value > 0
                    ? value
                    : throw new ArgumentException($"--{name} must be a positive whole number.")
                : null;

        public KeyVaultCaOptions CaOptions()
        {
            var vault = Value("vault")
                ?? throw new ArgumentException("--vault <uri> is required (Terraform output key_vault_uri).");
            if (!Uri.TryCreate(vault, UriKind.Absolute, out var vaultUri))
            {
                throw new ArgumentException($"--vault '{vault}' is not an absolute URI.");
            }

            return new KeyVaultCaOptions(
                vaultUri,
                Value("key") ?? KeyVaultCaOptions.DefaultSigningKeyName,
                Value("secret") ?? KeyVaultCaOptions.DefaultCertificateSecretName);
        }
    }
}
