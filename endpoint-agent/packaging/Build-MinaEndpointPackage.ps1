<#
.SYNOPSIS
    Builds, configures and signs the Mina endpoint Intune Win32 app payload (backlog M2-5).

.DESCRIPTION
    Produces everything Intune needs for the Mina endpoint package:

        artifacts/intune/payload/     Agent/, Tray/, Install.ps1, Uninstall.ps1, Detect.ps1,
                                      package.json
        artifacts/intune/*.intunewin  the wrapped package, when the Win32 Content Prep Tool is
                                      available
        artifacts/intune/intune-app-settings.json
                                      the exact values to enter (or later automate) in Intune

    Three properties this script exists to guarantee, none of which survive being left to whoever
    fills in a form:

    1  The research browser's image path is never re-typed. It is read from
       edge-integration/research-browser-flags.json -- the same file the tray parses at runtime to
       launch the browser -- and written into the agent's configuration from there. The agent's WFP
       rule, its proxy peer check and the actual launch therefore cannot disagree. A mismatch here
       does not fail loudly; it produces a containment rule that reads as applied while covering
       nothing, which is the failure mode M1-5 measured and warned about.

    2  The research profile directory is written to the agent and the tray from one value.
       WindowsPeerAuthorizer matches --user-data-dir as an exact literal string with no environment
       expansion on either side, so the two must be byte-identical. Writing both from a single
       source makes that structural instead of something to remember.

    3  Both are re-read from the produced artifacts and asserted afterwards, so the check is on
       what was actually built rather than on what was intended.

.PARAMETER ConfigPath
    Deployment configuration -- see package.config.template.json.

.PARAMETER SigningCertificateThumbprint
    Code-signing certificate in Cert:\CurrentUser\My or Cert:\LocalMachine\My. In the lab, one from
    New-MinaLabSigningCertificate.ps1 (PHASE0_DECISIONS A6 is still open, so there is no production certificate yet); in production, the organisation's own. Only the thumbprint changes between the two.

.PARAMETER SkipSigning
    Build an unsigned payload. Deliberately awkward to reach for: an unsigned package contradicts
    CLAUDE.md's endpoint-signing requirement, and the emitted Intune install command drops from
    AllSigned to Bypass, so the signature stops being enforced as well as absent.

.PARAMETER TimestampUrl
    RFC 3161 timestamp authority. Pass '' to skip timestamping -- a signature without one stops
    validating the day the certificate expires.

.PARAMETER IntuneWinAppUtilPath
    Microsoft's Win32 Content Prep Tool (IntuneWinAppUtil.exe). When absent the payload is still
    staged and the wrapping step is reported as skipped, since the .intunewin format is the tool's
    own and cannot be produced without it.

.EXAMPLE
    .\Build-MinaEndpointPackage.ps1 -ConfigPath .\package.config.json `
        -SigningCertificateThumbprint A1B2C3... `
        -IntuneWinAppUtilPath C:\tools\IntuneWinAppUtil.exe
#>
[CmdletBinding(DefaultParameterSetName = 'Signed')]
param(
    [Parameter(Mandatory)] [string] $ConfigPath,
    [Parameter(ParameterSetName = 'Signed', Mandatory)] [string] $SigningCertificateThumbprint,
    [Parameter(ParameterSetName = 'Unsigned', Mandatory)] [switch] $SkipSigning,
    [Parameter()] [string] $TimestampUrl = 'http://timestamp.digicert.com',
    [Parameter()] [string] $IntuneWinAppUtilPath,
    [Parameter()] [string] $OutputRoot,
    [Parameter()] [string] $Runtime = 'win-x64'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$RepoRoot = Resolve-Path (Join-Path $PSScriptRoot '..\..')
if (-not $OutputRoot) { $OutputRoot = Join-Path $RepoRoot 'artifacts\intune' }

$FlagsFile   = Join-Path $RepoRoot 'edge-integration\research-browser-flags.json'
$AgentProj   = Join-Path $RepoRoot 'endpoint-agent\src\Mina.EndpointAgent\Mina.EndpointAgent.csproj'
$TrayProj    = Join-Path $RepoRoot 'endpoint-agent\src\Mina.EndpointAgent.Tray\Mina.EndpointAgent.Tray.csproj'
$PayloadSrc  = Join-Path $PSScriptRoot 'payload'

# Intune's win32LobApp has TWO, mutually exclusive ways to declare architecture -- an app tagged
# wrong on either applies to no device (Publish-MinaEndpointApp.ps1's own verification step exists
# specifically to catch that after upload). `applicableArchitectures` is the older, create-only
# property, and Graph's own backend rejects arm64 for it outright ("Only x86, x64 are supported
# with this property" -- confirmed live against this tenant 2026-09-08). `allowedArchitectures` is
# the newer property that does accept arm64 (per Microsoft Graph's win32LobApp schema docs: sets
# applicableArchitectures to "none" as a side effect, which is expected, not a bug). Every build
# declares itself through allowedArchitectures alone, with applicableArchitectures explicitly "none"
# -- the value Graph sets anyway -- and every RID this script can actually publish gets its pair
# here, tracking -Runtime rather than assuming x64. Measured 2026-09-08: an x64 app declared through
# applicableArchitectures alone, allowedArchitectures left null, sat in the tenant with a stale
# allowedArchitectures of "x64,arm64" -- which is what the portal shows and what targeting uses. The
# property this pipeline does not manage is the one that lingers, so it manages the one that counts.
$RuntimeArchitectures = @{
    'win-x64'   = @{ ApplicableArchitectures = 'none';   AllowedArchitectures = 'x64' }
    'win-arm64' = @{ ApplicableArchitectures = 'none';   AllowedArchitectures = 'arm64' }
}
if (-not $RuntimeArchitectures.ContainsKey($Runtime)) {
    throw ("No Intune architecture mapping for -Runtime '{0}'. Supported: {1}." -f `
        $Runtime, ($RuntimeArchitectures.Keys -join ', '))
}
$TargetArchitecture = $RuntimeArchitectures[$Runtime]
# Used only for the display-name suffix below.
$ArchitectureLabel = $TargetArchitecture.AllowedArchitectures

# Two different-architecture builds cannot share one Intune app: Publish-MinaEndpointApp.ps1 finds
# the app to update by exact displayName match, so an identical name here would make publishing the
# second architecture silently add a new content version to the *first* app -- overwriting its x64
# payload with arm64 binaries under an app still labelled applicableArchitectures=x64, rather than
# creating a second entry. The default (win-x64) keeps the established name so anything already
# pointed at it (an existing app, an assignment) is undisturbed; every other architecture gets an
# explicit, distinct suffix.
$AppDisplayName = 'Mina Endpoint Agent'
if ($Runtime -ne 'win-x64') { $AppDisplayName = 'Mina Endpoint Agent ({0})' -f $ArchitectureLabel.ToUpperInvariant() }

function Write-Step  { param([string] $M) Write-Host ''; Write-Host ('==> ' + $M) -ForegroundColor Cyan }
function Write-Info  { param([string] $M) Write-Host ('    ' + $M) }
function Write-Warn2 { param([string] $M) Write-Host ('    WARNING: ' + $M) -ForegroundColor Yellow }
function Write-Ok    { param([string] $M) Write-Host ('    OK: ' + $M) -ForegroundColor Green }

function Write-JsonFile {
    # No BOM: the .NET configuration provider copes with one, but a BOM in a file that also gets
    # diffed and hashed is noise, and Set-Content -Encoding UTF8 emits one on PowerShell 5.1.
    #
    # Depth 8 rather than something generously large. Everything written here is at most five
    # levels deep, and a high depth is not free on PowerShell 5.1: see Read-TextFile below for the
    # trap a large depth turns into a hang.
    param([string] $Path, $Object)
    $json = $Object | ConvertTo-Json -Depth 8
    [IO.File]::WriteAllText($Path, $json, (New-Object Text.UTF8Encoding($false)))
}

function Read-TextFile {
    <#
        Get-Content decorates every string it returns with ETS note properties -- PSPath,
        PSParentPath, PSChildName, PSDrive, PSProvider, ReadCount. PSDrive and PSProvider are rich
        objects with their own nested graphs, and ConvertTo-Json walks them: a decorated string
        embedded in an object being serialised grows the output roughly tenfold per level of
        -Depth, which at any generous depth stops looking like slow output and starts looking like
        a hung build.

        Measured here on 2026-09-05 with the CA PEM, at the depths either side of where it turns:
        depth 4 gave 3,725 characters, depth 5 gave 39,788, depth 6 gave 462,582, and depth 12 did
        not finish. The same content read with ReadAllText, and an identical string built inline,
        both stay flat at every depth -- so it is the decoration, not the length and not the
        newlines. [IO.File]::ReadAllText returns a bare string carrying only Length.

        Use this for any file content that will end up inside a ConvertTo-Json call.
    #>
    param([string] $Path)
    return [IO.File]::ReadAllText($Path)
}

# --- 1. Inputs ---------------------------------------------------------------------------------

Write-Step 'Reading inputs'

if (-not (Test-Path -LiteralPath $ConfigPath)) { throw "Configuration not found at $ConfigPath." }
$config = Get-Content -LiteralPath $ConfigPath -Raw -Encoding UTF8 | ConvertFrom-Json

foreach ($required in @('packageVersion', 'publisher', 'region', 'egressCaCertificatePemPath', 'researchProfileDirectory')) {
    if ($config.PSObject.Properties.Name -notcontains $required) { throw "Configuration is missing '$required'." }
    if ([string]::IsNullOrWhiteSpace($config.$required)) { throw "Configuration value '$required' is empty." }
}
if ($config.PSObject.Properties.Name -notcontains 'controlPlane') { throw "Configuration is missing 'controlPlane'." }
if ($config.PSObject.Properties.Name -notcontains 'entra') { throw "Configuration is missing 'entra'." }

$controlPlaneAddress = $config.controlPlane.baseAddress
$clientId = $config.entra.clientId
$tenantId = $config.entra.tenantId
$profileDirectory = $config.researchProfileDirectory
$packageVersion = $config.packageVersion

# Catch a template that was copied but never filled in, rather than shipping REPLACE_ literals into
# a service's configuration and finding out at first launch on a managed endpoint.
foreach ($pair in @(
        @{ Name = 'controlPlane.baseAddress'; Value = $controlPlaneAddress },
        @{ Name = 'entra.clientId';           Value = $clientId },
        @{ Name = 'entra.tenantId';           Value = $tenantId },
        @{ Name = 'researchProfileDirectory'; Value = $profileDirectory })) {
    if ([string]::IsNullOrWhiteSpace($pair.Value)) { throw ("Configuration value '{0}' is empty." -f $pair.Name) }
    if ($pair.Value -match 'REPLACE') { throw ("Configuration value '{0}' still carries a template placeholder: {1}" -f $pair.Name, $pair.Value) }
}
foreach ($pair in @(@{ Name = 'entra.clientId'; Value = $clientId }, @{ Name = 'entra.tenantId'; Value = $tenantId })) {
    $parsed = [Guid]::Empty
    if (-not [Guid]::TryParse($pair.Value, [ref]$parsed)) {
        throw ("Configuration value '{0}' is not a GUID: {1}. The tray silently falls back to 'no sign-in configured' on an unparseable id, so this must be caught here." -f $pair.Name, $pair.Value)
    }
}
$parsedUri = $null
if (-not [Uri]::TryCreate($controlPlaneAddress, [UriKind]::Absolute, [ref]$parsedUri)) {
    throw "controlPlane.baseAddress is not an absolute URI: $controlPlaneAddress"
}
if ($parsedUri.Scheme -ne 'https') {
    throw "controlPlane.baseAddress must be https, got '$($parsedUri.Scheme)'. The agent's session material is not carried over cleartext."
}

# The image path comes from the flags file, never from the config -- see the notes above.
if (-not (Test-Path -LiteralPath $FlagsFile)) { throw "Research-browser flags not found at $FlagsFile." }
$flags = Get-Content -LiteralPath $FlagsFile -Raw -Encoding UTF8 | ConvertFrom-Json
$browserImagePath = $flags.researchBrowser.imagePath
if ([string]::IsNullOrWhiteSpace($browserImagePath)) { throw "research-browser-flags.json carries no researchBrowser.imagePath." }

$caPemPath = $config.egressCaCertificatePemPath
if (-not [IO.Path]::IsPathRooted($caPemPath)) { $caPemPath = Join-Path (Split-Path -Parent (Resolve-Path -LiteralPath $ConfigPath)) $caPemPath }
if (-not (Test-Path -LiteralPath $caPemPath)) { throw "Egress CA PEM not found at $caPemPath." }
$caPem = Read-TextFile -Path $caPemPath   # NOT Get-Content -- see Read-TextFile
if ($caPem -notmatch '-----BEGIN CERTIFICATE-----') { throw "File at $caPemPath does not look like a PEM certificate." }
if ($caPem -match 'PRIVATE KEY') {
    # D-18: the signing key lives in Key Vault and never leaves it. A private key reaching an
    # endpoint package would be a serious, silent regression, so this refuses rather than warns.
    throw "The file at $caPemPath contains a PRIVATE KEY. Only the CA certificate belongs in an endpoint package."
}

Write-Info ('Configured version : {0}   (a payload hash is appended once the payload exists)' -f $packageVersion)
Write-Info ('Control plane      : {0}' -f $controlPlaneAddress)
Write-Info ('Region             : {0}' -f $config.region)
Write-Info ('Research browser   : {0}   (from research-browser-flags.json)' -f $browserImagePath)
Write-Info ('Research profile   : {0}' -f $profileDirectory)
Write-Info ('Egress CA PEM      : {0}' -f $caPemPath)

$cert = $null
if (-not $SkipSigning) {
    $cert = Get-ChildItem -Path Cert:\CurrentUser\My, Cert:\LocalMachine\My -ErrorAction SilentlyContinue |
        Where-Object { $_.Thumbprint -eq $SigningCertificateThumbprint }
    if (-not $cert) { throw "No certificate with thumbprint $SigningCertificateThumbprint in CurrentUser\My or LocalMachine\My." }
    $cert = @($cert)[0]
    if (-not $cert.HasPrivateKey) { throw "Certificate $SigningCertificateThumbprint has no private key available; it cannot sign." }
    if ($cert.NotAfter -lt (Get-Date)) { throw ("Certificate {0} expired on {1:yyyy-MM-dd}." -f $SigningCertificateThumbprint, $cert.NotAfter) }
    Write-Info ('Signing certificate: {0}' -f $cert.Subject)
    Write-Info ('  expires {0:yyyy-MM-dd}, thumbprint {1}' -f $cert.NotAfter, $cert.Thumbprint)
} else {
    Write-Warn2 'Building UNSIGNED. This contradicts CLAUDE.md''s endpoint-signing requirement and the emitted install command will use -ExecutionPolicy Bypass rather than AllSigned.'
}

# --- 2. Publish --------------------------------------------------------------------------------

$payloadOut = Join-Path $OutputRoot 'payload'
$agentOut   = Join-Path $payloadOut 'Agent'
$trayOut    = Join-Path $payloadOut 'Tray'

Write-Step 'Publishing'

# Cleared, not merged: a publish over a previous one leaves assemblies from the older build in
# place, which is how a package ends up carrying a binary nobody built for it.
if (Test-Path -LiteralPath $payloadOut) { Remove-Item -LiteralPath $payloadOut -Recurse -Force }
New-Item -ItemType Directory -Path $payloadOut -Force | Out-Null

# Publishing for a runtime identifier makes NuGet add a RID target to every lock file it touches,
# and those targets must not be committed: no project here declares a RuntimeIdentifier, so
# `dotnet restore --locked-mode` -- CI's first step -- fails NU1004 on any lock file carrying one.
# That is not hypothetical; it is what commit 08c42b0 had to undo after this script's own first run
# left them behind, and it took every downstream CI job with it.
#
# RestorePackagesWithLockFile=false does not help (NU1005 refuses it outright while a lock file
# exists), and --no-restore cannot work because a RID publish genuinely needs a RID restore. So the
# transient change is allowed to happen and then reverted: snapshot the bytes, publish, put them
# back. Byte comparison rather than git, so this is correct in a dirty tree, in a worktree shared
# with another session, and on a machine with no git at all.
$lockFiles = @{}
foreach ($lock in (Get-ChildItem -Path $RepoRoot -Filter 'packages.lock.json' -Recurse -File -ErrorAction SilentlyContinue)) {
    $lockFiles[$lock.FullName] = [IO.File]::ReadAllBytes($lock.FullName)
}
Write-Info ('Snapshotted {0} lock files; any RID targets the publish adds will be reverted.' -f $lockFiles.Count)

try {
    # Self-contained: the endpoint gains no .NET runtime prerequisite, and -- more to the point for a
    # security component -- it runs on exactly the runtime this build was tested against, rather than
    # whatever the machine happens to have when a shared runtime is serviced underneath it.
    foreach ($job in @(
            @{ Proj = $AgentProj; Out = $agentOut; Name = 'agent' },
            @{ Proj = $TrayProj;  Out = $trayOut;  Name = 'tray'  })) {
        Write-Info ('Publishing {0}...' -f $job.Name)
        & dotnet publish $job.Proj -c Release -r $Runtime --self-contained true -o $job.Out --nologo -v quiet
        if ($LASTEXITCODE -ne 0) { throw ("dotnet publish failed for the {0} ({1})." -f $job.Name, $job.Proj) }
    }
} finally {
    # In a finally block: a publish that fails partway still leaves the lock files rewritten, and
    # leaving the repository dirty on the way out of a failure is how the CI break happened.
    $reverted = 0
    foreach ($path in @($lockFiles.Keys)) {
        if (-not (Test-Path -LiteralPath $path)) { continue }
        $now = [IO.File]::ReadAllBytes($path)
        $original = $lockFiles[$path]
        $same = $now.Length -eq $original.Length
        if ($same) {
            for ($i = 0; $i -lt $now.Length; $i++) { if ($now[$i] -ne $original[$i]) { $same = $false; break } }
        }
        if (-not $same) {
            [IO.File]::WriteAllBytes($path, $original)
            $reverted++
        }
    }
    if ($reverted -gt 0) { Write-Info ('Reverted {0} lock file(s) the publish had rewritten.' -f $reverted) }
}
Write-Ok ('Published to {0}' -f $payloadOut)

# Publish output carries more than the endpoint should receive. Each of these is removed for its own
# reason, and the first is not cosmetic:
#
#   packages.lock.json          The publish copies it into the output, and because a RID publish
#                               rewrites it in place first, the copy carries the RID target even
#                               though the source file is restored afterwards. Whether it does
#                               depends on the restore's cache state, so it made the payload hash
#                               flap between otherwise identical builds -- found 2026-09-06 by
#                               diffing payload-inventory.txt, which is what that file is for. It
#                               is also a listing of every package and hash the build used, which
#                               is build metadata and not something to distribute to endpoints.
#   appsettings.Development.json  A development configuration has no business on a managed device.
#                               The host defaults to Production so it would not be read, but that
#                               is a reason it is harmless, not a reason to ship it.
#   *.pdb                       Debug symbols make a security component markedly easier to reverse,
#                               and nothing on the endpoint consumes them.
$pruned = 0
foreach ($stray in @(
        (Get-ChildItem -LiteralPath $payloadOut -Recurse -File -Filter 'packages.lock.json'),
        (Get-ChildItem -LiteralPath $payloadOut -Recurse -File -Filter 'appsettings.Development.json'),
        (Get-ChildItem -LiteralPath $payloadOut -Recurse -File -Filter '*.pdb'))) {
    foreach ($f in @($stray)) {
        Remove-Item -LiteralPath $f.FullName -Force
        $pruned++
    }
}
if ($pruned -gt 0) { Write-Info ('Pruned {0} file(s) that should not reach an endpoint.' -f $pruned) }

# --- 3. Configuration --------------------------------------------------------------------------

Write-Step 'Writing configuration'

$agentSettingsPath = Join-Path $agentOut 'appsettings.json'
$agentSettings = if (Test-Path -LiteralPath $agentSettingsPath) {
    Get-Content -LiteralPath $agentSettingsPath -Raw -Encoding UTF8 | ConvertFrom-Json
} else {
    [PSCustomObject]@{}
}
$agentMina = [ordered]@{
    Agent = [ordered]@{
        ControlPlaneBaseAddress = $controlPlaneAddress
        Region                  = $config.region
        EgressCaCertificatePem  = $caPem
        ResearchBrowser         = [ordered]@{
            ImagePath        = $browserImagePath
            ProfileDirectory = $profileDirectory
        }
    }
}
$agentSettings | Add-Member -NotePropertyName 'Mina' -NotePropertyValue $agentMina -Force
Write-JsonFile -Path $agentSettingsPath -Object $agentSettings
Write-Info ('agent appsettings.json written ({0})' -f $agentSettingsPath)

$traySettingsPath = Join-Path $trayOut 'appsettings.json'
$traySettings = [PSCustomObject]@{}
$trayMina = [ordered]@{
    Tray = [ordered]@{
        ClientId                 = $clientId
        TenantId                 = $tenantId
        ResearchProfileDirectory = $profileDirectory
    }
}
$traySettings | Add-Member -NotePropertyName 'Mina' -NotePropertyValue $trayMina -Force
Write-JsonFile -Path $traySettingsPath -Object $traySettings
Write-Info ('tray appsettings.json written ({0})' -f $traySettingsPath)

# --- 4. Assert the invariants on what was actually produced -------------------------------------

Write-Step 'Verifying the produced artifacts'

$agentCheck = Get-Content -LiteralPath $agentSettingsPath -Raw -Encoding UTF8 | ConvertFrom-Json
$trayCheck  = Get-Content -LiteralPath $traySettingsPath  -Raw -Encoding UTF8 | ConvertFrom-Json

$agentProfile = $agentCheck.Mina.Agent.ResearchBrowser.ProfileDirectory
$trayProfile  = $trayCheck.Mina.Tray.ResearchProfileDirectory
if ($agentProfile -cne $trayProfile) {
    throw ("Research profile directory differs between agent ('{0}') and tray ('{1}'). WindowsPeerAuthorizer compares this as an exact literal string, so the proxy would refuse every browser connection." -f $agentProfile, $trayProfile)
}
Write-Ok ('research profile directory identical in both configurations: {0}' -f $agentProfile)

$agentImage = $agentCheck.Mina.Agent.ResearchBrowser.ImagePath
if ($agentImage -cne $browserImagePath) {
    throw ("Agent image path ('{0}') does not match research-browser-flags.json ('{1}')." -f $agentImage, $browserImagePath)
}
Write-Ok ('agent image path matches research-browser-flags.json')

# The tray parses this file at runtime to build the launch command line. The csproj copies it from
# edge-integration/ at build time, but "the build copies it" is a claim about the build, and this
# is the artifact -- so compare the bytes that actually shipped.
$trayFlagsPath = Join-Path $trayOut 'research-browser-flags.json'
if (-not (Test-Path -LiteralPath $trayFlagsPath)) {
    throw "The tray payload is missing research-browser-flags.json; it cannot launch the research browser without it."
}
$repoFlagsHash = (Get-FileHash -LiteralPath $FlagsFile -Algorithm SHA256).Hash
$trayFlagsHash = (Get-FileHash -LiteralPath $trayFlagsPath -Algorithm SHA256).Hash
if ($repoFlagsHash -ne $trayFlagsHash) {
    throw "The research-browser-flags.json in the tray payload differs from edge-integration/research-browser-flags.json."
}
Write-Ok ('tray payload carries research-browser-flags.json byte-identical to edge-integration/ (SHA256 {0})' -f $repoFlagsHash.Substring(0, 16))

# --- 5. Stage the scripts and the manifest ------------------------------------------------------

Write-Step 'Deriving the package version from the payload'

# The version is what decides whether an endpoint already carrying this package updates. Detect.ps1
# reports "installed" when the marker's version matches its own, so a rebuild that kept the
# configured version -- a new tray build, say -- would upload, be reported healthy by Intune, and
# never reach a device that already has the old one. The stale binary would keep running with
# nothing anywhere reporting a problem.
#
# So the configured semver is a prefix, not the whole answer: a hash of the payload is appended, and
# the version therefore changes if and only if the shipped bytes change.
#
# Hashed BEFORE signing, deliberately. Authenticode embeds a trusted timestamp, so signing makes
# every build differ from every other; hashing signed output would churn the version on rebuilds of
# identical source and force a pointless reinstall each time. Both publishes were measured
# byte-for-byte reproducible on 2026-09-06 (agent 353 files, tray 493, two runs each, zero
# differences), so the unsigned payload is a stable identity for the source it came from.
# Configuration is included because a package aimed at a different control plane is a different
# package, whatever its binaries say.
#
# The full path is NOT used as the hash input: $payloadOut can arrive as an 8.3 short path on this
# platform, and mixing that with FileInfo.FullName (always long form) silently truncates the wrong
# number of characters. Relative paths are computed from the FileInfo's own root instead.
$payloadRoot = (Get-Item -LiteralPath $payloadOut).FullName
$payloadEntries =
    Get-ChildItem -LiteralPath $payloadRoot -Recurse -File |
    ForEach-Object {
        [PSCustomObject]@{
            Rel  = $_.FullName.Substring($payloadRoot.Length).TrimStart('\').Replace('\', '/').ToLowerInvariant()
            Full = $_.FullName
        }
    } |
    Sort-Object -Property Rel -CaseSensitive

$hasher = [Security.Cryptography.SHA256]::Create()
try {
    foreach ($entry in $payloadEntries) {
        # Path as well as content: a renamed or moved file changes what ships even when no byte of
        # any file changed.
        $relBytes = [Text.Encoding]::UTF8.GetBytes($entry.Rel)
        [void]$hasher.TransformBlock($relBytes, 0, $relBytes.Length, $null, 0)
        $bytes = [IO.File]::ReadAllBytes($entry.Full)
        [void]$hasher.TransformBlock($bytes, 0, $bytes.Length, $null, 0)
    }
    [void]$hasher.TransformFinalBlock([byte[]]::new(0), 0, 0)
    $payloadHash = [BitConverter]::ToString($hasher.Hash).Replace('-', '').ToLowerInvariant()
} finally {
    $hasher.Dispose()
}

$resolvedVersion = '{0}+{1}' -f $packageVersion, $payloadHash.Substring(0, 12)
Write-Info ('Payload files      : {0}' -f @($payloadEntries).Count)
Write-Info ('Payload SHA-256    : {0}' -f $payloadHash)
Write-Ok   ('Package version    : {0}' -f $resolvedVersion)

# A per-file manifest beside the package, so that when two builds of the same source disagree the
# answer is a diff rather than an investigation.
$inventory = $payloadEntries | ForEach-Object {
    '{0}  {1}' -f (Get-FileHash -LiteralPath $_.Full -Algorithm SHA256).Hash.ToLowerInvariant(), $_.Rel
}
[IO.File]::WriteAllLines((Join-Path $OutputRoot 'payload-inventory.txt'), $inventory)

Write-Step 'Staging install scripts and manifest'

Copy-Item -LiteralPath (Join-Path $PayloadSrc 'Install.ps1')   -Destination $payloadOut -Force
Copy-Item -LiteralPath (Join-Path $PayloadSrc 'Uninstall.ps1') -Destination $payloadOut -Force

# The expected version goes into the detection script itself, so it lives in signed code rather
# than being read back from the unsigned manifest the same package carries.
$detect = Read-TextFile -Path (Join-Path $PayloadSrc 'Detect.ps1')
if ($detect -notmatch '@@PACKAGE_VERSION@@') { throw "Detect.ps1 no longer contains the @@PACKAGE_VERSION@@ token." }
$detect = $detect.Replace('@@PACKAGE_VERSION@@', $resolvedVersion)
[IO.File]::WriteAllText((Join-Path $payloadOut 'Detect.ps1'), $detect, (New-Object Text.UTF8Encoding($false)))
Write-Info ('Detect.ps1 pinned to version {0}' -f $resolvedVersion)

$manifest = [ordered]@{
    packageVersion           = $resolvedVersion
    configuredVersion        = $packageVersion
    payloadSha256            = $payloadHash
    builtUtc                 = (Get-Date).ToUniversalTime().ToString('o')
    researchBrowserImagePath = $browserImagePath
    researchProfileDirectory = $profileDirectory
    signed                   = (-not $SkipSigning)
}
Write-JsonFile -Path (Join-Path $payloadOut 'package.json') -Object $manifest
Write-Info 'package.json manifest written'

# --- 6. Sign ------------------------------------------------------------------------------------

if (-not $SkipSigning) {
    Write-Step 'Signing'

    # Mina's own binaries and the three scripts. Third-party assemblies keep their vendors'
    # signatures: re-signing them would replace a publisher's attestation with ours, which is a
    # weaker claim, not a stronger one.
    $toSign = @()
    $toSign += Get-ChildItem -Path $agentOut, $trayOut -Recurse -File -Include 'Mina.*.exe', 'Mina.*.dll'
    $toSign += Get-ChildItem -Path $payloadOut -File -Filter '*.ps1'

    $signParams = @{ Certificate = $cert; HashAlgorithm = 'SHA256' }
    if (-not [string]::IsNullOrWhiteSpace($TimestampUrl)) { $signParams['TimestampServer'] = $TimestampUrl }

    $signed = 0
    foreach ($file in $toSign) {
        $result = Set-AuthenticodeSignature -FilePath $file.FullName @signParams
        if ($result.Status -ne 'Valid') {
            # UnknownError with a self-signed certificate normally means the chain does not
            # terminate in a trusted root on THIS machine. The file is still signed; it is the
            # local verification that cannot complete.
            if ($result.Status -eq 'UnknownError' -and $result.SignerCertificate) {
                Write-Warn2 ('{0}: signed, but not verifiable here ({1}). Expected for a self-signed lab certificate not in this machine''s trusted roots.' -f $file.Name, $result.StatusMessage)
            } else {
                throw ('Signing failed for {0}: {1} ({2})' -f $file.FullName, $result.Status, $result.StatusMessage)
            }
        }
        $signed++
    }
    Write-Ok ('{0} files signed with {1}' -f $signed, $cert.Thumbprint)
    if ([string]::IsNullOrWhiteSpace($TimestampUrl)) {
        Write-Warn2 'No timestamp applied: these signatures stop validating when the certificate expires.'
    }
}

# --- 7. Wrap ------------------------------------------------------------------------------------

Write-Step 'Wrapping for Intune'

$intuneWin = $null
if ($IntuneWinAppUtilPath -and (Test-Path -LiteralPath $IntuneWinAppUtilPath)) {
    & $IntuneWinAppUtilPath -c $payloadOut -s 'Install.ps1' -o $OutputRoot -q
    if ($LASTEXITCODE -ne 0) { throw "IntuneWinAppUtil.exe failed with exit code $LASTEXITCODE." }

    # The tool names its output after the setup file, so every build of every version would land as
    # Install.intunewin. Renamed to carry the version, because the one thing an operator needs to be
    # sure of when uploading is which build they are holding.
    $produced = Join-Path $OutputRoot 'Install.intunewin'
    if (Test-Path -LiteralPath $produced) {
        # '+' is legal in a Windows filename but is percent-encoded by half the things that will
        # later carry this name around, so the build-metadata separator becomes a dash on disk.
        $intuneWin = Join-Path $OutputRoot ('Mina-EndpointAgent-{0}.intunewin' -f $resolvedVersion.Replace('+', '-'))
        if (Test-Path -LiteralPath $intuneWin) { Remove-Item -LiteralPath $intuneWin -Force }
        Move-Item -LiteralPath $produced -Destination $intuneWin
        Write-Ok ('Wrapped: {0}' -f $intuneWin)
    } else {
        Write-Warn2 'IntuneWinAppUtil reported success but no .intunewin was found.'
        $intuneWin = $null
    }
} else {
    Write-Warn2 'IntuneWinAppUtil.exe not supplied -- payload staged but not wrapped.'
    Write-Info  'The .intunewin container is the tool''s own encrypted format and cannot be produced without it.'
    Write-Info  'Get it from https://github.com/microsoft/Microsoft-Win32-Content-Prep-Tool and re-run with -IntuneWinAppUtilPath.'
}

# --- 8. Intune app settings ---------------------------------------------------------------------

# AllSigned when signed, so the signature is enforced rather than merely present: under AllSigned
# Windows refuses to run a script whose publisher is not trusted on that machine. That makes the
# signing certificate a real deployment prerequisite (it must reach the endpoint's TrustedPublisher
# store), which is the point.
$policy = 'AllSigned'
if ($SkipSigning) { $policy = 'Bypass' }

# The Company Portal tile: the tunnel from branding/, generated by New-MinaIcons.ps1. Placed beside
# the settings rather than inside the payload -- it is tenant metadata with no business on the
# device, and keeping it out leaves the signed package unchanged.
$iconSrc = Join-Path $RepoRoot 'branding\mina-256.png'
if (-not (Test-Path -LiteralPath $iconSrc)) { throw "No application icon at $iconSrc. Run branding\New-MinaIcons.ps1 first." }
$iconFileName = 'intune-app-icon.png'
$iconPath = Join-Path $OutputRoot $iconFileName
Copy-Item -LiteralPath $iconSrc -Destination $iconPath -Force

$appSettings = [ordered]@{
    name                   = $AppDisplayName
    description            = 'Mina protected research-egress endpoint agent, tray and research-browser integration.'
    # A deployment fact, not source: the organisation's name in production, the lab's own name in a lab tenant.
    publisher              = [string]$config.publisher
    largeIconFile          = $iconFileName
    appVersion             = $resolvedVersion
    payloadSha256          = $payloadHash
    installCommandLine     = ('powershell.exe -NoProfile -ExecutionPolicy {0} -File .\Install.ps1' -f $policy)
    uninstallCommandLine   = ('powershell.exe -NoProfile -ExecutionPolicy {0} -File .\Uninstall.ps1' -f $policy)
    installExperience      = [ordered]@{
        runAsAccount           = 'system'
        deviceRestartBehavior  = 'basedOnReturnCode'
    }
    runAs32Bit             = $false
    detectionRule          = [ordered]@{
        type                  = 'script'
        scriptFile            = 'Detect.ps1'
        runAs32Bit            = $false
        enforceSignatureCheck = (-not $SkipSigning)
    }
    requirements           = [ordered]@{
        applicableArchitectures = $TargetArchitecture.ApplicableArchitectures
        allowedArchitectures    = $TargetArchitecture.AllowedArchitectures
        minimumSupportedWindowsRelease = 'Windows11_22H2'
    }
    returnCodes            = @(
        [ordered]@{ code = 0;  type = 'success' },
        [ordered]@{ code = 10; type = 'failed'; meaning = 'Not running as LocalSystem' },
        [ordered]@{ code = 11; type = 'failed'; meaning = 'Not a 64-bit host -- set "Run as 32-bit process" to No' },
        [ordered]@{ code = 12; type = 'failed'; meaning = 'Research browser absent -- deploy the Edge Beta dependency first' },
        [ordered]@{ code = 13; type = 'failed'; meaning = 'Payload malformed' },
        [ordered]@{ code = 14; type = 'failed'; meaning = 'Agent service failed to start, or started without its containment rule' },
        [ordered]@{ code = 15; type = 'failed'; meaning = 'Payload copy failed' },
        [ordered]@{ code = 20; type = 'failed'; meaning = 'Uninstall could not remove the containment firewall rule' }
    )
    dependencies           = @(
        [ordered]@{
            name   = 'Microsoft Edge (Beta channel)'
            reason = 'The research browser must exist at ' + $browserImagePath + ' before the agent applies a containment rule scoped to it. Deploy via Intune''s first-party "Microsoft Edge version 77 and later" app type with Channel = Beta, and mark it a required dependency of this app.'
        }
    )
    prerequisites          = @(
        'The signing certificate must be present in the endpoint''s LocalMachine\TrustedPublisher store (and, for a self-signed lab certificate, LocalMachine\Root) -- otherwise AllSigned refuses to run the install script.'
    )
}
$settingsPath = Join-Path $OutputRoot 'intune-app-settings.json'
Write-JsonFile -Path $settingsPath -Object $appSettings

Write-Step 'Done'
Write-Info ('Payload        : {0}' -f $payloadOut)
if ($intuneWin) { Write-Info ('Package        : {0}' -f $intuneWin) }
Write-Info ('Intune settings: {0}' -f $settingsPath)
Write-Info ('Icon           : {0}' -f $iconPath)
Write-Info ('Install command: {0}' -f $appSettings.installCommandLine)
Write-Host ''
