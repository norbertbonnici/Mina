#Requires -RunAsAdministrator
<#
.SYNOPSIS
    ADR-0001 M1-5 verification register, item 2: policy scope across channels and profiles, and
    whether flag-based hardening holds for a spawned instance.

.DESCRIPTION
    ADR-0001 constraint 2 asserts that Chromium enterprise policies are instance-global: Edge
    reads policy from a single machine location, a second --user-data-dir instance receives the
    same policies, and channels are believed to share that location. The consequence drives the
    design -- policy set for the research context would also land on the analyst's ordinary Edge,
    which is why variant C2 relies on per-launch command-line flags for browser-level hardening
    and on WFP for enforcement, rather than on policy to separate the two contexts.

    Proven behaviourally rather than by reading edge://policy, because a misspelled or
    non-existent policy name is silently ignored: it appears in the registry, changes nothing,
    and a name-only check would call that a pass. Forcing traffic through a proxy that is not
    listening turns "the policy applied" into "no packet reached the target", which is
    unambiguous at the NIC.

      1 Stable, no policy               expect Tx > 0   baseline
      2 Beta,   no policy               expect Tx > 0   baseline
      -- machine-wide fixed-proxy policy set, pointing at a dead local port --
      3 Stable                          expect Tx = 0   the policy applied
      4 Beta                            expect Tx = 0   channels share the policy location
      5 Stable, a second profile        expect Tx = 0   policy is not per-profile
      -- policy removed --
      6 Stable                          expect Tx > 0   control: the effect was the policy, and
                                                        the machine is back as it was found
      -- no policy; hardening passed as a launch flag instead --
      7 Stable --proxy-server=dead      expect Tx = 0   flag-based hardening holds on a spawned
                                                        instance

    Case 6 is the one that makes the rest trustworthy. Without it, a permanently broken network
    path would produce the same zeros as a working policy.

.NOTES
    While cases 3-5 run, EVERY Edge instance on this machine is pointed at a proxy that is not
    listening -- including any the operator has open. That is the constraint under test, not a
    side effect that could be scoped away. The window is short and the policy key is removed in
    a finally block; the script refuses to start if a policy key already exists, rather than
    clobbering real configuration.

    Only the proxy policy pair is pinned here. QUIC, DoH and WebRTC hardening cannot be settled
    by this method -- each needs its own observation (an HTTP/3 origin, DNS capture, an ICE
    harness) and lands with register items 4 and 5.
#>
[CmdletBinding()]
param(
    [Parameter()] [string] $TargetIp     = '10.20.40.21',
    [Parameter()] [int]    $TargetPort   = 18099,
    [Parameter()] [string] $StablePath   = 'C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe',
    [Parameter()] [string] $BetaPath     = 'C:\Program Files (x86)\Microsoft\Edge Beta\Application\msedge.exe',
    # A port on loopback with nothing listening: a browser that obeys the fixed proxy reaches
    # nothing, and one that ignores it reaches the target and shows up in the counters.
    [Parameter()] [int]    $DeadProxyPort = 19999,
    [Parameter()] [int]    $DwellSeconds  = 8
)

$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'MinaEnforcementProbe.psm1') -Force

$policyKey = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
$deadProxy = "127.0.0.1:$DeadProxyPort"

foreach ($exe in @($StablePath, $BetaPath)) {
    if (-not (Test-Path -LiteralPath $exe)) {
        throw "Edge installation not found at '$exe'. This test needs two channels installed."
    }
}
if (Test-Path -LiteralPath $policyKey) {
    throw "$policyKey already exists. Refusing to overwrite real Edge policy configuration; " +
          'inspect and clear it by hand if this machine is genuinely meant to have none.'
}
if (Get-NetTCPConnection -State Listen -LocalPort $DeadProxyPort -ErrorAction SilentlyContinue) {
    throw "Something is listening on port $DeadProxyPort. The proxy target must be dead for this test to mean anything."
}

function Measure-Case {
    param([string]$Exe, [string]$Tag, [string[]]$ExtraArgs = @())
    Measure-BrowserEgress -Exe $Exe -Tag $Tag -TargetIp $TargetIp -TargetPort $TargetPort `
                          -DwellSeconds $DwellSeconds -ExtraArgs $ExtraArgs
}

$cases = [ordered]@{}
try {
    $cases['1 Stable  no policy']                 = Measure-Case $StablePath 'base-stable'
    $cases['2 Beta    no policy']                 = Measure-Case $BetaPath   'base-beta'

    New-Item -Path $policyKey -Force | Out-Null
    New-ItemProperty -Path $policyKey -Name 'ProxyMode'   -Value 'fixed_servers' -PropertyType String -Force | Out-Null
    New-ItemProperty -Path $policyKey -Name 'ProxyServer' -Value $deadProxy      -PropertyType String -Force | Out-Null

    $cases['3 Stable  policy set']                = Measure-Case $StablePath 'pol-stable'
    $cases['4 Beta    policy set']                = Measure-Case $BetaPath   'pol-beta'
    $cases['5 Stable  policy set, 2nd profile']   = Measure-Case $StablePath 'pol-stable-2'
}
finally {
    Remove-Item -LiteralPath $policyKey -Recurse -Force -ErrorAction SilentlyContinue
}

$policyGone = -not (Test-Path -LiteralPath $policyKey)
try {
    $cases['6 Stable  policy removed (control)']  = Measure-Case $StablePath 'ctl-stable'
    $cases['7 Stable  --proxy-server flag']       = Measure-Case $StablePath 'flag-stable' @("--proxy-server=$deadProxy")

    # Microsoft documents ProxyMode/ProxyServer (used above) as deprecated in favour of a single
    # ProxySettings JSON value. Shipping configuration should not rest on a deprecated name, and
    # the replacement should not be trusted on the strength of a docs page either -- a policy
    # name Edge does not recognise sits in the registry looking correct and changes nothing.
    $proxySettingsJson = (@{ ProxyMode = 'fixed_servers'; ProxyServer = $deadProxy } | ConvertTo-Json -Compress)
    New-Item -Path $policyKey -Force | Out-Null
    New-ItemProperty -Path $policyKey -Name 'ProxySettings' -Value $proxySettingsJson -PropertyType String -Force | Out-Null

    $cases['8 Stable  ProxySettings (current form)'] = Measure-Case $StablePath 'pset-stable'
}
finally {
    Remove-Item -LiteralPath $policyKey -Recurse -Force -ErrorAction SilentlyContinue
    $filtersCleared = Clear-ProbeCapture
}
$policyGone = $policyGone -and -not (Test-Path -LiteralPath $policyKey)

$baseStable = $cases['1 Stable  no policy']
$baseBeta   = $cases['2 Beta    no policy']
$polStable  = $cases['3 Stable  policy set']
$polBeta    = $cases['4 Beta    policy set']
$polProfile = $cases['5 Stable  policy set, 2nd profile']
$control    = $cases['6 Stable  policy removed (control)']
$flag       = $cases['7 Stable  --proxy-server flag']
$proxySet   = $cases['8 Stable  ProxySettings (current form)']

# Fail closed: without live baselines and a recovering control, zeros prove nothing.
$verdict =
    if ($baseStable -le 0 -or $baseBeta -le 0) {
        'INCONCLUSIVE - a baseline produced no egress; the measurement is broken, not the claim'
    }
    elseif ($control -le 0) {
        'INCONCLUSIVE - egress did not recover after the policy was removed; the zeros above are not attributable to the policy'
    }
    elseif ($polStable -eq 0 -and $polBeta -eq 0 -and $polProfile -eq 0 -and $flag -eq 0 -and $proxySet -eq 0) {
        'CONSTRAINT 2 CONFIRMED - one machine-wide policy location governs both channels and every profile; launch flags hold on a spawned instance; both the deprecated and current proxy policy forms are honoured'
    }
    elseif ($proxySet -gt 0) {
        'ProxySettings NOT HONOURED - the current documented form had no effect while the deprecated pair did; ship ProxyMode/ProxyServer and re-check on the next Edge major'
    }
    elseif ($polBeta -gt 0) {
        'CONSTRAINT 2 REFUTED - Beta ignored a policy that bound Stable; channels do NOT share the policy location'
    }
    elseif ($polProfile -gt 0) {
        'CONSTRAINT 2 REFUTED - a second profile escaped the policy; policy is per-profile after all'
    }
    elseif ($flag -gt 0) {
        'FLAG HARDENING REFUTED - --proxy-server did not bind the spawned instance'
    }
    else { 'UNEXPECTED - review the per-case counts' }

[pscustomobject]@{
    Target            = "${TargetIp}:${TargetPort}"
    DeadProxy         = $deadProxy
    StableVersion     = (Get-Item -LiteralPath $StablePath).VersionInfo.ProductVersion
    BetaVersion       = (Get-Item -LiteralPath $BetaPath).VersionInfo.ProductVersion
    PolicyKey         = $policyKey
    PinnedPolicyDeprecated = 'ProxyMode=fixed_servers + ProxyServer=<host:port>  (REG_SZ each)'
    PinnedPolicyCurrent    = 'ProxySettings={"ProxyMode":"fixed_servers","ProxyServer":"<host:port>"}  (REG_SZ)'
    PinnedFlag             = '--proxy-server=<host:port>'
    Cases             = $cases
    PolicyKeyRemoved  = $policyGone
    FiltersCleared    = $filtersCleared
    Verdict           = $verdict
}
