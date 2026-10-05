using System.Text.Json;
using System.Text.RegularExpressions;

namespace Mina.EndpointAgent.Tests;

/// <summary>
/// Drift guards over the M2-5 Intune package's install-time scripts.
/// </summary>
/// <remarks>
/// <para>
/// The scripts in <c>endpoint-agent/packaging/payload/</c> name things the C# also names — the
/// firewall rule, the Windows service, the tray executable — and nothing else checks that the two
/// sides still agree. Renaming a constant in C# leaves the PowerShell untouched and compiling, and
/// the resulting failure is not a crash: the install script would look for a rule the agent never
/// creates, or the uninstall script would fail to remove one the agent left behind. Both look like
/// success at the point they happen.
/// </para>
/// <para>
/// These are text assertions over checked-in files, which is unusual for a unit test and is the
/// point: the boundary being guarded is between two languages, so there is no type system spanning
/// it. Every one of them exists because getting it wrong is silent rather than loud.
/// </para>
/// </remarks>
public sealed class PackagingScriptTests
{
    private static string InstallScript => ReadRepoFile("endpoint-agent/packaging/payload/Install.ps1");
    private static string UninstallScript => ReadRepoFile("endpoint-agent/packaging/payload/Uninstall.ps1");
    private static string DetectScript => ReadRepoFile("endpoint-agent/packaging/payload/Detect.ps1");
    private static string BuildScript => ReadRepoFile("endpoint-agent/packaging/Build-MinaEndpointPackage.ps1");
    private static string PublishScript => ReadRepoFile("endpoint-agent/packaging/Publish-MinaEndpointApp.ps1");
    private static string EdgeAppScript => ReadRepoFile("endpoint-agent/packaging/New-EdgeBetaApp.ps1");
    private static string TrustedCertProfilesScript => ReadRepoFile("endpoint-agent/packaging/New-MinaTrustedCertificateProfiles.ps1");

    [Fact]
    public void The_publisher_can_still_read_the_version_the_build_pins_into_Detect()
    {
        // Publish-MinaEndpointApp.ps1 reads the package's version back out of the staged Detect.ps1
        // -- deliberately, since that script is the signed copy the device will actually compare
        // against. That makes the shape of Detect.ps1's declaration a contract between two files
        // that nothing else couples. If it drifts, the publisher throws at the very end of a build,
        // after a multi-minute publish, which is a slow way to learn about a one-line problem.
        var patternMatch = Regex.Match(PublishScript, @"\[Regex\]::Match\(\$detectText,\s*""(?<pattern>[^""]+)""\)");
        Assert.True(patternMatch.Success, "Publish-MinaEndpointApp.ps1 no longer reads the version with a recognisable [Regex]::Match call.");

        // PowerShell escapes a literal backslash in a double-quoted string the same way C# does in a
        // verbatim one, so the pattern text transfers as-is.
        var pattern = patternMatch.Groups["pattern"].Value;
        var found = Regex.Match(DetectScript, pattern);

        Assert.True(found.Success, $"The publisher's pattern '{pattern}' matches nothing in Detect.ps1.");
        Assert.Equal("@@PACKAGE_VERSION@@", found.Groups["v"].Value);
    }

    [Fact]
    public void Install_and_uninstall_re_launch_themselves_into_the_sixty_four_bit_host()
    {
        // The Intune Management Extension is a 32-bit process, so the install command it spawns is
        // 32-bit too -- this is the normal case, not an edge case. Measured on mina-w11-01 on
        // 2026-09-06: the first real Intune-delivered install failed on exactly this. A 32-bit host
        // resolves $env:ProgramFiles to the x86 directory and is redirected into Wow6432Node for
        // HKLM writes, so without the re-launch the package installs to the wrong place and
        // registers a tray autostart nothing will read.
        //
        // Uninstall matters just as much and less obviously: 32-bit it would find none of what it
        // is meant to remove and report success having removed nothing, leaving the containment
        // rule with no agent behind it.
        foreach (var script in new[] { InstallScript, UninstallScript })
        {
            Assert.Contains("Is64BitProcess", script, StringComparison.Ordinal);
            Assert.Contains(@"SysNative\WindowsPowerShell\v1.0\powershell.exe", script, StringComparison.Ordinal);
            Assert.Contains("$PSCommandPath", script, StringComparison.Ordinal);
            Assert.Contains("exit $childExit", script, StringComparison.Ordinal);
        }
    }

    [Fact]
    public void Detection_resolves_program_files_in_a_way_that_survives_a_thirty_two_bit_host()
    {
        // Detection is declared 64-bit so this should not arise, but if it ever did the script would
        // look in Program Files (x86), find no tray, report "not installed" on a machine that is,
        // and put Intune into a permanent reinstall loop. ProgramW6432 names the 64-bit directory
        // from either bitness. Detection needs no re-launch -- it writes nothing and touches no
        // redirected registry -- so the one variable is the whole fix.
        Assert.Contains("ProgramW6432", DetectScript, StringComparison.Ordinal);
    }

    [Fact]
    public void Install_waits_for_the_old_agent_to_exit_before_overwriting_it()
    {
        // Only an upgrade exercises this, so the first install on a device passes and the second
        // fails -- which is how it reached mina-w11-01 on 2026-09-06: "Access to the path
        // 'C:\Program Files\Mina\Agent\clrjit.dll' is denied", after the old service had already
        // been deleted. That leaves the device with no agent and the containment rule still in
        // force, which is the worst of both states.
        //
        // The service reporting Stopped and sc.exe accepting the delete both say nothing about
        // whether the process has exited, and until it has, the runtime it loaded is still mapped.
        // So the wait is on processes running from the install root, not on service-control state.
        Assert.Contains("StartsWith($InstallRoot", InstallScript, StringComparison.Ordinal);

        // And the copy is retried, because process exit removes the usual cause of a locked file
        // but not an antimalware scan or the indexer holding one a moment longer.
        Assert.Contains("Copy attempt", InstallScript, StringComparison.Ordinal);
        Assert.Contains("after 5 attempts", InstallScript, StringComparison.Ordinal);
    }

    [Fact]
    public void The_publisher_keeps_both_architecture_properties_out_of_its_update_body()
    {
        // Graph accepts applicableArchitectures when the app is created and refuses it on PATCH:
        // "can only be set via ODataAction: enableApplicableArchitectures". Sending it in an update
        // fails the entire PATCH, so every other property silently fails to update with it. Worse,
        // the failed attempt observed on 2026-09-06 left the live app reading
        // applicableArchitectures="none" -- an app that applies to no device at all, which reports
        // as healthy and installs nowhere. allowedArchitectures, the newer property that arm64
        // needs (2026-09-08), is kept out of the same body and repaired on its own afterwards.
        Assert.Contains("-notin @('applicableArchitectures', 'allowedArchitectures')", PublishScript, StringComparison.Ordinal);
        Assert.Contains("/microsoft.graph.win32LobApp/enableApplicableArchitectures", PublishScript, StringComparison.Ordinal);
    }

    [Fact]
    public void Every_runtime_declares_exactly_one_architecture_through_allowed_architectures()
    {
        // Intune has two mutually exclusive ways to say which devices an app fits, and the portal
        // shows -- and targeting uses -- the newer one, allowedArchitectures. On 2026-09-08 the x64
        // app was found holding a stale allowedArchitectures of "x64,arm64" because the build had
        // declared x64 through applicableArchitectures alone and nothing managed the other property.
        // So every runtime the build knows declares itself through allowedArchitectures, with
        // applicableArchitectures explicitly "none" (the value Graph sets as a side effect anyway).
        // A mapping that slips back to the old property would not fail; it would publish an app
        // that offers itself to the wrong devices.
        Assert.Matches(@"'win-x64'\s*=\s*@\{\s*ApplicableArchitectures\s*=\s*'none';\s*AllowedArchitectures\s*=\s*'x64'\s*\}", BuildScript);
        Assert.Matches(@"'win-arm64'\s*=\s*@\{\s*ApplicableArchitectures\s*=\s*'none';\s*AllowedArchitectures\s*=\s*'arm64'\s*\}", BuildScript);
        Assert.DoesNotMatch(@"ApplicableArchitectures\s*=\s*'(x64|arm64)'", BuildScript);
    }

    [Fact]
    public void The_publisher_repairs_in_the_order_the_side_effects_require()
    {
        // Every PATCH on a win32LobApp clears applicableArchitectures to "none", and one that carries
        // no largeIcon leaves the app without one -- the committedContentVersion PATCH after an
        // upload does both (measured 2026-09-08: an app published with its icon read back with
        // none). The verification step therefore puts things back in a fixed order: the icon by
        // PATCH, then allowedArchitectures by PATCH (which sets applicableArchitectures to "none",
        // the value every build now expects), and only then the applicableArchitectures action.
        // Reordering these compiles and runs; it just leaves one of the repairs undone by the next.
        var iconRepair = PublishScript.IndexOf("largeIcon     = $largeIcon", StringComparison.Ordinal);
        var allowedRepair = PublishScript.IndexOf("allowedArchitectures  = $desiredAllowed", StringComparison.Ordinal);
        var applicableAction = PublishScript.IndexOf("/microsoft.graph.win32LobApp/enableApplicableArchitectures", StringComparison.Ordinal);

        Assert.True(iconRepair > 0, "Publish-MinaEndpointApp.ps1 no longer repairs largeIcon in a form this guard recognises.");
        Assert.True(allowedRepair > 0, "Publish-MinaEndpointApp.ps1 no longer repairs allowedArchitectures in a form this guard recognises.");
        Assert.True(applicableAction > 0, "Publish-MinaEndpointApp.ps1 no longer invokes enableApplicableArchitectures.");
        Assert.True(iconRepair < allowedRepair, "The icon must be put back before the architecture PATCH, not after it.");
        Assert.True(allowedRepair < applicableAction, "allowedArchitectures must be repaired before applicableArchitectures is checked.");

        // And a missing icon is a reported problem, not a healthy app.
        Assert.Contains("largeIcon is missing", PublishScript, StringComparison.Ordinal);
    }

    [Fact]
    public void The_publisher_name_comes_from_configuration_not_source()
    {
        // the organisation's name in production, the lab's own name in a lab tenant: the name shown as the app's
        // publisher is a deployment fact like the tenant id, and a literal in the build script is
        // how a lab package came to carry the lab name on 2026-09-08.
        Assert.Contains("[string]$config.publisher", BuildScript, StringComparison.Ordinal);
        Assert.DoesNotMatch(@"publisher\s*=\s*'[^']+'", BuildScript);
        Assert.Matches(@"@\([^)]*'publisher'[^)]*\)", BuildScript);   // among the required config keys
    }

    [Fact]
    public void The_config_template_is_valid_json()
    {
        // The template is what a deployment copies and fills in; it carried two Windows paths with
        // single backslashes until 2026-09-08, so an unedited copy failed ConvertFrom-Json before
        // the build could say which value was wrong. The key-listing guard below reads it with a
        // regex and never noticed.
        var template = ReadRepoFile("endpoint-agent/packaging/package.config.template.json");
        using var parsed = JsonDocument.Parse(template);
        Assert.Equal(JsonValueKind.Object, parsed.RootElement.ValueKind);
        Assert.True(parsed.RootElement.TryGetProperty("publisher", out _), "The template no longer offers a publisher.");
    }

    [Fact]
    public void The_publishers_token_cache_is_protected_and_lives_outside_the_repository()
    {
        // The publisher caches the refresh token so re-publishing does not need a human inside a
        // fifteen-minute device-code window. That is a real credential at rest, and the three
        // properties that make it defensible are easy to lose in a later edit: it is encrypted with
        // DPAPI at CurrentUser scope (so the file is worthless copied to another account or
        // machine), it lives under LOCALAPPDATA, and it is never written as plaintext.
        Assert.Contains("DataProtectionScope]::CurrentUser", PublishScript, StringComparison.Ordinal);
        Assert.Contains("$env:LOCALAPPDATA", PublishScript, StringComparison.Ordinal);

        // The only thing written to the cache path is the base64 of the protected blob.
        var write = Regex.Match(PublishScript, @"\[IO\.File\]::WriteAllText\(\$path,\s*(?<what>[^,]+),");
        Assert.True(write.Success, "Write-TokenCache no longer writes the cache with a recognisable WriteAllText call.");
        Assert.Contains("ToBase64String($protected)", write.Groups["what"].Value, StringComparison.Ordinal);

        // And nothing puts the cache inside the repository, where .gitignore would be the only
        // thing between a refresh token and a commit.
        Assert.DoesNotContain("$PSScriptRoot 'graph-token", PublishScript, StringComparison.Ordinal);
    }

    [Fact]
    public void The_build_prunes_the_lock_file_out_of_the_payload()
    {
        // A packages.lock.json copied into the publish output made the payload hash -- and therefore
        // the package version -- flap between builds of identical source, because a RID publish
        // rewrites the lock file in place and the copy keeps the rewritten content even after the
        // source is restored. Since the version is what decides whether a device updates, a flapping
        // hash means every rebuild forces a reinstall everywhere. Removing this prune step would
        // bring that back silently, so it is asserted rather than trusted to stay.
        Assert.Contains("packages.lock.json", BuildScript, StringComparison.Ordinal);
        Assert.Contains("appsettings.Development.json", BuildScript, StringComparison.Ordinal);
        Assert.Contains("'*.pdb'", BuildScript, StringComparison.Ordinal);
    }

    [Fact]
    public void The_build_restores_the_lock_files_its_publish_rewrites()
    {
        // Committing the RID targets a `dotnet publish -r` leaves behind breaks
        // `dotnet restore --locked-mode`, which is CI's first step -- it happened once (08c42b0) and
        // took every downstream job with it. The snapshot/restore around the publish is what stops
        // this script doing it again, and the finally block is what stops a failed publish leaving
        // the tree dirty on the way out.
        Assert.Contains("} finally {", BuildScript, StringComparison.Ordinal);
        Assert.Contains("[IO.File]::WriteAllBytes($path, $original)", BuildScript, StringComparison.Ordinal);
    }

    [Fact]
    public void Every_script_names_the_same_firewall_rule_as_the_enforcer_that_creates_it()
    {
        // WindowsFirewallEnforcer creates it; Install.ps1 verifies it exists before reporting
        // success; Detect.ps1 treats its absence as "not installed" so Intune reinstalls;
        // Uninstall.ps1 removes it. Four references to one name, in two languages.
        var expected = $"'{EnforcerRuleName}'";

        Assert.Contains(expected, InstallScript, StringComparison.Ordinal);
        Assert.Contains(expected, UninstallScript, StringComparison.Ordinal);
        Assert.Contains(expected, DetectScript, StringComparison.Ordinal);
    }

    [Fact]
    public void Uninstall_removes_the_containment_rule()
    {
        // The rule is deliberately persistent -- it outlives any single session, and so it also
        // outlives the agent process that created it. An uninstall that removes the agent but
        // leaves the rule blocks the research browser permanently, with nothing left on the machine
        // to proxy it or explain it: fail-closed turned into fail-forever. Nothing else would clean
        // it up, so this assertion is the only thing standing between a refactor and that bug.
        Assert.Contains("Remove-NetFirewallRule -Name $FirewallRuleName", UninstallScript, StringComparison.Ordinal);

        // And that the name it removes is the one the enforcer creates, not a near-miss.
        Assert.Equal(EnforcerRuleName, ExtractPowerShellConstant(UninstallScript, "FirewallRuleName"));
    }

    [Fact]
    public void Every_script_names_the_same_windows_service_as_Program_registers()
    {
        // Program.cs is the entry point, so the name cannot be referenced as a symbol from here.
        var program = ReadRepoFile("endpoint-agent/src/Mina.EndpointAgent/Program.cs");
        var match = Regex.Match(program, @"ServiceName\s*=\s*""(?<name>[^""]+)""");
        Assert.True(match.Success, "Program.cs no longer sets options.ServiceName in a form this guard recognises.");

        var serviceName = match.Groups["name"].Value;
        Assert.Equal(serviceName, ExtractPowerShellConstant(InstallScript, "ServiceName"));
        Assert.Equal(serviceName, ExtractPowerShellConstant(UninstallScript, "ServiceName"));
        Assert.Equal(serviceName, ExtractPowerShellConstant(DetectScript, "ServiceName"));
    }

    [Fact]
    public void Every_script_names_the_tray_executable_the_tray_project_actually_produces()
    {
        // The tray's assembly name is Mina.Tray, not Mina.EndpointAgent.Tray -- exactly the kind of
        // detail that gets re-typed from memory in a script and is wrong.
        var csproj = ReadRepoFile("endpoint-agent/src/Mina.EndpointAgent.Tray/Mina.EndpointAgent.Tray.csproj");
        var match = Regex.Match(csproj, @"<AssemblyName>(?<name>[^<]+)</AssemblyName>");
        Assert.True(match.Success, "The tray project no longer declares an AssemblyName.");

        var exeName = match.Groups["name"].Value + ".exe";
        Assert.Equal(exeName, ExtractPowerShellConstant(InstallScript, "TrayExeName"));
        Assert.Equal(exeName, ExtractPowerShellConstant(UninstallScript, "TrayExeName"));
        Assert.Contains(exeName, DetectScript, StringComparison.Ordinal);
    }

    [Fact]
    public void Detect_still_carries_the_token_the_build_substitutes()
    {
        // Build-MinaEndpointPackage.ps1 replaces this with the package version before signing, so
        // the expected version ends up inside signed code rather than being read back from the
        // unsigned manifest the package also carries. The build throws if the token is missing --
        // this makes that a test failure rather than a failed build on someone's machine.
        Assert.Contains("@@PACKAGE_VERSION@@", DetectScript, StringComparison.Ordinal);
    }

    [Fact]
    public void The_config_template_offers_nowhere_to_type_a_second_research_browser_image_path()
    {
        // The image path is read from research-browser-flags.json, the same file the tray parses to
        // build the launch command line, so the WFP rule, the peer check and the actual launch
        // cannot disagree. A well-meaning "imagePath" field added to the template would reintroduce
        // exactly the divergence that design removes -- and a divergence here does not fail loudly,
        // it produces a containment rule that reads as applied while covering nothing.
        var template = ReadRepoFile("endpoint-agent/packaging/package.config.template.json");

        var configurableKeys = Regex.Matches(template, @"^\s*""(?<key>[A-Za-z][A-Za-z0-9]*)""\s*:", RegexOptions.Multiline)
            .Select(m => m.Groups["key"].Value)
            .ToList();

        // A DoesNotContain over an empty list passes for the wrong reason. Anchor on keys the
        // template certainly has, so a regex that stops matching fails here rather than going quiet.
        Assert.Contains("packageVersion", configurableKeys, StringComparer.Ordinal);
        Assert.Contains("publisher", configurableKeys, StringComparer.Ordinal);
        Assert.Contains("researchProfileDirectory", configurableKeys, StringComparer.Ordinal);

        Assert.DoesNotContain("imagePath", configurableKeys, StringComparer.OrdinalIgnoreCase);
        Assert.DoesNotContain("researchBrowserImagePath", configurableKeys, StringComparer.OrdinalIgnoreCase);
    }

    /// <summary>
    /// <c>WindowsFirewallEnforcer.RuleName</c>, read from source rather than referenced.
    /// </summary>
    /// <remarks>
    /// The enforcer is <c>[SupportedOSPlatform("windows")]</c>, and referencing even its const from
    /// this platform-neutral test assembly trips CA1416 (which is an error here). Marking this class
    /// Windows-only to silence that would be a false claim — every assertion in it is plain text
    /// comparison that is just as meaningful on CI's Linux hosts, and skipping it there would lose
    /// the guard on the platform the checks actually run on most often. Reading the constant out of
    /// the source keeps the test cross-platform and, as a side effect, fails loudly if the constant
    /// is renamed or restructured, which is the same signal a symbol reference would have given.
    /// </remarks>
    private static string EnforcerRuleName
    {
        get
        {
            var source = ReadRepoFile("endpoint-agent/src/Mina.EndpointAgent/Proxy/WindowsFirewallEnforcer.cs");
            var match = Regex.Match(source, @"const\s+string\s+RuleName\s*=\s*""(?<name>[^""]+)""");
            Assert.True(match.Success, "WindowsFirewallEnforcer no longer declares RuleName in a form this guard recognises.");
            return match.Groups["name"].Value;
        }
    }

    [Fact]
    public void The_edge_beta_app_declares_the_metadata_only_app_type_on_the_measured_channel()
    {
        // windowsMicrosoftEdgeApp, not win32LobApp: Microsoft's own service distributes and updates
        // Edge for this channel, so this app carries no content of its own -- no upload, no signing,
        // no .intunewin, unlike every other app this pipeline creates. Beta specifically, because
        // M1-5's flags and WFP containment rule were measured against Edge Beta, not Edge generally
        // -- a different default channel would silently stop matching what the agent actually looks
        // for at C:\Program Files (x86)\Microsoft\Edge Beta\Application\msedge.exe.
        Assert.Contains("'#microsoft.graph.windowsMicrosoftEdgeApp'", EdgeAppScript, StringComparison.Ordinal);
        Assert.Contains("$Channel = 'beta'", EdgeAppScript, StringComparison.Ordinal);
        // No content-upload machinery: this app type carries none, and a script that grew one would
        // mean someone copied the win32LobApp upload plumbing across without noticing it does not apply.
        Assert.DoesNotContain("contentVersions", EdgeAppScript, StringComparison.Ordinal);
        Assert.DoesNotContain("Send-BlobInBlocks", EdgeAppScript, StringComparison.Ordinal);
    }

    [Fact]
    public void The_publisher_can_wire_a_dependency_and_checks_it_survived()
    {
        // A dependency is a relationship object on its own endpoint, not a property on the app --
        // Graph's updateRelationships action, not a PATCH -- so it needs its own read-repair-verify
        // pass the same shape as the icon and the architecture properties, not an assumption that
        // setting it once is enough. Measured 2026-09-08: unlike those two, a second publish found
        // it already correct -- the repair path exists for the day that measurement turns out to be
        // wrong for some other tenant or a future Graph change, not because it is known to be needed.
        Assert.Contains("[Parameter()] [string] $DependsOnAppId", PublishScript, StringComparison.Ordinal);
        Assert.Contains("'#microsoft.graph.mobileAppDependency'", PublishScript, StringComparison.Ordinal);
        Assert.Contains("dependencyType = 'autoInstall'", PublishScript, StringComparison.Ordinal);
        Assert.Contains("/updateRelationships", PublishScript, StringComparison.Ordinal);

        // And the final verification actually re-reads the relationship rather than trusting the
        // POST that set it -- the same "read back what the tenant holds" discipline as everything
        // else in this step, and a problem here is reported, not swallowed.
        Assert.Contains("No autoInstall dependency on $DependsOnAppId", PublishScript, StringComparison.Ordinal);
    }

    [Fact]
    public void The_trusted_certificate_profiles_cover_both_stores_the_code_signing_cert_needs()
    {
        // windows81TrustedRootCertificate has no TrustedPublisher destination at all (confirmed
        // against this tenant's own Graph beta $metadata, 2026-09-10) -- Root alone is not enough
        // for a self-signed code-signing chain (New-MinaLabSigningCertificate.ps1's own output
        // already says so), so the script needs a second mechanism for that store specifically.
        Assert.Contains("'#microsoft.graph.windows81TrustedRootCertificate'", TrustedCertProfilesScript, StringComparison.Ordinal);
        Assert.Contains("'computerCertStoreRoot'", TrustedCertProfilesScript, StringComparison.Ordinal);
        // The TrustedPublisher path: a custom OMA-URI profile against the RootCATrustedCertificates
        // CSP, keyed by the certificate's own thumbprint rather than a hardcoded one -- so a
        // regenerated lab certificate (new thumbprint) produces a different URI instead of a
        // profile that silently still points at nothing anyone trusts as code-signing anymore.
        Assert.Contains("'#microsoft.graph.windows10CustomConfiguration'", TrustedCertProfilesScript, StringComparison.Ordinal);
        Assert.Contains("'#microsoft.graph.omaSettingBase64'", TrustedCertProfilesScript, StringComparison.Ordinal);
        Assert.Contains("RootCATrustedCertificates/TrustedPublisher/$codeSigningThumb/EncodedCertificate", TrustedCertProfilesScript, StringComparison.Ordinal);
        Assert.Contains("$codeSigningCert.Thumbprint", TrustedCertProfilesScript, StringComparison.Ordinal);
    }

    [Fact]
    public void The_trusted_certificate_profiles_update_by_delete_and_recreate_not_patch()
    {
        // Found live, not assumed: PATCH on this deviceConfigurations resource is broken for both
        // profile types used here -- every field tried, including a completely empty {} body, on
        // both the beta and v1.0 endpoints, returns the identical generic ModelValidationFailure.
        // A script that regressed to PATCH here would silently fail its second run onward, exactly
        // the failure mode this test exists to catch before a live re-run does.
        Assert.DoesNotContain("-Method Patch -Uri \"/deviceManagement/deviceConfigurations", TrustedCertProfilesScript, StringComparison.Ordinal);
        Assert.Contains("-Method Delete -Uri \"/deviceManagement/deviceConfigurations/$staleId\"", TrustedCertProfilesScript, StringComparison.Ordinal);
        Assert.Contains("-Method Post -Uri '/deviceManagement/deviceConfigurations'", TrustedCertProfilesScript, StringComparison.Ordinal);
    }

    /// <summary>
    /// Reads a <c>$Name = 'value'</c> assignment from a PowerShell script's constants block.
    /// </summary>
    private static string ExtractPowerShellConstant(string script, string name)
    {
        var match = Regex.Match(script, $@"\${Regex.Escape(name)}\s*=\s*'(?<value>[^']*)'");
        Assert.True(match.Success, $"Could not find a ${name} = '...' assignment in the script.");
        return match.Groups["value"].Value;
    }

    private static string ReadRepoFile(string repoRelativePath)
    {
        var dir = AppContext.BaseDirectory;
        for (var i = 0; i < 10; i++)
        {
            var candidate = Path.Combine(dir, repoRelativePath);
            if (File.Exists(candidate))
            {
                return File.ReadAllText(candidate);
            }

            dir = Path.GetDirectoryName(dir) ?? throw new DirectoryNotFoundException(
                $"Could not find {repoRelativePath} above {AppContext.BaseDirectory}.");
        }

        throw new DirectoryNotFoundException($"Could not find {repoRelativePath} above {AppContext.BaseDirectory}.");
    }
}
