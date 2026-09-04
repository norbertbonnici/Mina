#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Pins the QUIC and DNS-over-HTTPS policy names behaviourally, closing the last gap left open
    by ADR-0001 M1-5 register item 2.

.DESCRIPTION
    Item 2 pinned the proxy flag and policy by observation but could only list the QUIC and DoH
    names as documented candidates. A policy name Edge does not recognise sits in the registry
    looking entirely correct and changes nothing, so a name is not pinned until behaviour moves.

    Both halves are made deterministic and pointed at one off-box address that nothing else on
    this network talks to, so the counters cannot be polluted by the operator's own browsing --
    which matters here because ordinary Edge does plenty of QUIC and DNS of its own.

    QUIC. The browser is pointed at https://<target>/ with --origin-to-force-quic-on for that
    origin, which makes a QUIC attempt happen on demand rather than waiting for an Alt-Svc hint
    from a real HTTP/3 site. QUIC is UDP, so the filter isolates UDP/443.

      Q1 no policy                     expect UDP > 0   a QUIC attempt really is being made
      Q2 QuicAllowed = 0               expect UDP = 0   the name is honoured
      Q3 policy removed (control)      expect UDP > 0   the zero was the policy, not a dead path

    DoH. DnsOverHttpsTemplates is pointed at https://<target>/dns-query, so a resolution attempt
    becomes a connection to an address we are watching. The browser is sent to a hostname that
    must be resolved, so it has something to resolve. DoH is HTTPS, so the filter isolates
    TCP/443.

      D1 mode secure + our template    expect TCP > 0   DnsOverHttpsMode and
                                                        DnsOverHttpsTemplates are both honoured
      D2 mode off, template still set  expect TCP = 0   the mode value is what stops it
      D3 mode secure, built-in DNS off expect TCP = 0   BuiltInDnsClientEnabled gates DoH

.NOTES
    Q2 interpretation. QuicAllowed = 0 suppressing a *forced* QUIC origin is a strong result: the
    policy beat an explicit command-line instruction to use QUIC. The converse would be weaker
    than it looks -- if the force flag won, that would not by itself prove the policy is ignored
    in ordinary use, so a non-zero Q2 is reported as ambiguous rather than as a refutation.

    D3 interpretation. A zero confirms the combination suppresses DoH, which is what the
    enforcement design needs. It does not isolate *why*: Chromium's DoH depends on the built-in
    asynchronous resolver, so this name gating DoH is expected, but a non-zero result could mean
    either that the name is not honoured or that it is honoured and does not gate DoH in this
    build. Recorded as observed rather than resolved.

    None of these run through a proxy. Under C2 the research browser resolves nothing locally
    because the fixed proxy resolves at the egress; QUIC and DoH hardening is defence in depth
    for the case where the proxy is not in force, which is exactly the case this measures.
#>
[CmdletBinding()]
param(
    [Parameter()] [string] $TargetIp = '10.20.40.21',
    [Parameter()] [string] $ResearchBrowserPath = 'C:\Program Files (x86)\Microsoft\Edge Beta\Application\msedge.exe',
    # A hostname that must be resolved and resolves to nothing real, so a DoH attempt is
    # guaranteed and no traffic reaches a third party.
    [Parameter()] [string] $ProbeHostname = 'mina-doh-probe.example',
    # The DoH resolver is nominated on a deliberately non-standard port. TCP/443 toward this host
    # is NOT a clean measurement channel -- an idle control with no browser running at all
    # transmitted ~20 packets in 10 s, enough to make every DoH case read as a leak. Measured
    # 2026-09-04; the same control on 18443 is a flat zero. QUIC below stays on 443 because it is
    # observed over UDP, which is clean.
    [Parameter()] [int]    $DohPort = 18443,
    [Parameter()] [int]    $DwellSeconds = 12
)

$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'MinaEnforcementProbe.psm1') -Force

if (-not (Test-Path -LiteralPath $ResearchBrowserPath)) { throw "Browser not found at $ResearchBrowserPath" }

$policyKey = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
if (Test-Path -LiteralPath $policyKey) {
    throw "$policyKey already exists. Refusing to overwrite real Edge policy configuration."
}

$runId = [guid]::NewGuid().ToString('N').Substring(0, 8)

function Set-Policy {
    param([hashtable]$Values)
    New-Item -Path $policyKey -Force | Out-Null
    foreach ($k in $Values.Keys) {
        $v = $Values[$k]
        $type = if ($v -is [int]) { 'DWord' } else { 'String' }
        New-ItemProperty -Path $policyKey -Name $k -Value $v -PropertyType $type -Force | Out-Null
    }
}
function Clear-Policy { Remove-Item -LiteralPath $policyKey -Recurse -Force -ErrorAction SilentlyContinue }

function Measure-IdleChannel {
    <#
        Watches the channel with nothing launched at all. Any traffic here is somebody else's,
        and every later count on this channel is noise by exactly that much.
    #>
    param([string]$Transport, [int]$Port)
    Invoke-Quietly { & pktmon.exe stop | Out-Null }
    Invoke-Quietly { & pktmon.exe filter remove | Out-Null }
    Invoke-Quietly { & pktmon.exe filter add MinaProbe -i $TargetIp -p $Port -t $Transport | Out-Null }
    Invoke-Quietly { & pktmon.exe start --capture --counters-only | Out-Null }
    Start-Sleep -Seconds $DwellSeconds
    Invoke-Quietly { & pktmon.exe stop | Out-Null }
    $c = Get-PktmonTxCounters
    return [pscustomobject]@{ Sent = $c.Transmitted; Dropped = $c.Dropped }
}

function Measure-Case {
    param([string]$Tag, [string]$Transport, [string]$Url, [int]$Port, [string[]]$ExtraArgs = @())

    Invoke-Quietly { & pktmon.exe stop | Out-Null }
    Invoke-Quietly { & pktmon.exe filter remove | Out-Null }
    Invoke-Quietly { & pktmon.exe filter add MinaProbe -i $TargetIp -p $Port -t $Transport | Out-Null }
    Invoke-Quietly { & pktmon.exe start --capture --counters-only | Out-Null }

    $dir  = Join-Path $env:TEMP "mina-qd-$runId-$Tag"
    $argv = @(
        '--headless=new'
        "--user-data-dir=$dir"
        '--no-first-run'
        '--no-default-browser-check'
        '--disable-gpu'
        '--ignore-certificate-errors'
    ) + $ExtraArgs + @($Url)

    $proc = Start-Process -FilePath $ResearchBrowserPath -WindowStyle Hidden -PassThru -ArgumentList $argv
    try { Start-Sleep -Seconds $DwellSeconds }
    finally {
        Stop-ProcessTree $proc.Id
        Invoke-Quietly { & pktmon.exe stop | Out-Null }
        Remove-Item -LiteralPath $dir -Recurse -Force -ErrorAction SilentlyContinue
    }
    $c = Get-PktmonTxCounters
    return [pscustomobject]@{ Sent = $c.Transmitted; Dropped = $c.Dropped }
}

$quicUrl  = "https://${TargetIp}/"
$quicArgs = @("--origin-to-force-quic-on=${TargetIp}:443")
$dohUrl   = "http://$ProbeHostname/"
$template = "https://${TargetIp}:${DohPort}/dns-query"

$cases = [ordered]@{}
try {
    # ---- QUIC (UDP/443) ----
    $cases['Q1 no policy']                    = Measure-Case 'q1' 'UDP' $quicUrl 443 $quicArgs
    Set-Policy @{ QuicAllowed = 0 }
    $cases['Q2 QuicAllowed=0']                = Measure-Case 'q2' 'UDP' $quicUrl 443 $quicArgs
    Clear-Policy
    $cases['Q3 policy removed (control)']     = Measure-Case 'q3' 'UDP' $quicUrl 443 $quicArgs

    # ---- DoH (TCP on the quiet port) ----
    # An idle control with no browser at all, proving the channel is silent before anything is
    # attributed to a policy. Without this the DoH cases are unreadable -- see $DohPort.
    $cases['D0 idle control (no browser)']    = Measure-IdleChannel 'TCP' $DohPort

    Set-Policy @{ DnsOverHttpsMode = 'secure'; DnsOverHttpsTemplates = $template }
    $cases['D1 mode=secure + template']       = Measure-Case 'd1' 'TCP' $dohUrl $DohPort
    Set-Policy @{ DnsOverHttpsMode = 'off';    DnsOverHttpsTemplates = $template }
    $cases['D2 mode=off']                     = Measure-Case 'd2' 'TCP' $dohUrl $DohPort
    Set-Policy @{ DnsOverHttpsMode = 'secure'; DnsOverHttpsTemplates = $template; BuiltInDnsClientEnabled = 0 }
    $cases['D3 secure + BuiltInDnsClient=0']  = Measure-Case 'd3' 'TCP' $dohUrl $DohPort
}
finally {
    Clear-Policy
    $filtersCleared = Clear-ProbeCapture
}

$policyGone = -not (Test-Path -LiteralPath $policyKey)
$q1 = $cases['Q1 no policy'].Sent
$q2 = $cases['Q2 QuicAllowed=0'].Sent
$q3 = $cases['Q3 policy removed (control)'].Sent
$d0 = $cases['D0 idle control (no browser)'].Sent
$d1 = $cases['D1 mode=secure + template'].Sent
$d2 = $cases['D2 mode=off'].Sent
$d3 = $cases['D3 secure + BuiltInDnsClient=0'].Sent

$quicVerdict =
    if ($q1 -le 0)      { 'INCONCLUSIVE - no QUIC attempt was made even unrestricted; --origin-to-force-quic-on may not be doing what this test assumes' }
    elseif ($q3 -le 0)  { 'INCONCLUSIVE - QUIC did not resume after the policy was removed, so the zero is not attributable to the policy' }
    elseif ($q2 -eq 0)  { 'QuicAllowed PINNED - the policy suppressed QUIC even against an explicit force-QUIC switch' }
    else                { 'AMBIGUOUS - QUIC persisted under QuicAllowed=0, but against a forced origin; this does not by itself show the policy is ignored in ordinary use' }

$dohVerdict =
    if ($d0 -gt 0)      { "INVALID - the channel is not silent when idle ($d0 packets with no browser running); every DoH count below is noise by at least that much. Move DohPort" }
    elseif ($d1 -le 0)  { 'INCONCLUSIVE - no DoH attempt reached the nominated resolver, so the mode/template pair cannot be judged' }
    elseif ($d2 -gt 0)  { 'DnsOverHttpsMode NOT HONOURED - traffic still went to the DoH template with mode=off' }
    else                { 'DnsOverHttpsMode + DnsOverHttpsTemplates PINNED - the resolver was contacted on secure and not on off' }

$builtInVerdict =
    if ($d0 -gt 0)      { 'not assessed - channel not silent when idle' }
    elseif ($d1 -le 0)  { 'not assessed - no DoH baseline' }
    elseif ($d3 -eq 0)  { 'BuiltInDnsClientEnabled=0 SUPPRESSES DoH - sufficient for enforcement; does not isolate whether the name gates DoH or is simply honoured' }
    else                { 'BuiltInDnsClientEnabled=0 did NOT suppress DoH - either the name is not honoured or it does not gate DoH on this build; do not rely on it alone' }

[pscustomobject]@{
    RunId            = $runId
    Target           = "${TargetIp}:443"
    BrowserVersion   = (Get-Item -LiteralPath $ResearchBrowserPath).VersionInfo.ProductVersion
    Cases            = $cases
    QuicVerdict      = $quicVerdict
    DohVerdict       = $dohVerdict
    BuiltInDnsResult = $builtInVerdict
    PolicyKeyRemoved = $policyGone
    FiltersCleared   = $filtersCleared
}
