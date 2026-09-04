#Requires -RunAsAdministrator
<#
.SYNOPSIS
    ADR-0001 M1-5 verification register, item 5: WebRTC leak harness against the chosen flag and
    policy set.

.DESCRIPTION
    ADR-0001 constraint 5 asserts that WebRTC bypasses proxies by default and needs explicit
    browser-level controls or network-level blocking. That is the claim with teeth: if it holds,
    a fixed proxy -- the control the whole fail-closed design leans on -- does nothing whatsoever
    to stop WebRTC putting UDP on the wire from the research browser (AC-007, THREAT_MODEL).

    ICE is offered a STUN server on an off-box address that nothing listens on. The measurement
    is the UDP that LEAVES this machine toward it, not a completed round trip: against a real
    STUN server those same packets would have come back carrying the public egress address,
    which is the leak. Not needing the answer to prove the send keeps the test free of any
    external dependency.

      1 no proxy, no hardening              expect UDP > 0   ICE really does emit UDP
      2 fixed proxy, no hardening           expect UDP > 0   WebRTC bypasses the proxy --
                                                             constraint 5, and the reason the
                                                             proxy alone is not sufficient
      3 fixed proxy + --webrtc-ip-handling  expect UDP = 0   the browser-level control works
      4 fixed proxy + WebRtcLocalhostIpHandling policy
                                            expect UDP = 0   pins the POLICY name, which item 2
                                                             left as a documented candidate
      5 C2 image-path block, no flags       expect UDP = 0   network-level enforcement catches it
                                                             regardless of what the browser was
                                                             told

    Case 2 is the point of the exercise. Cases 3-5 are only interesting because case 2 shows
    there is something real to stop.

.NOTES
    The harness page (tests/security/canaries/webrtc-harness.html, TEST_STRATEGY §2) is served
    over loopback by this script, which also receives the candidate report the page POSTs back.
    Loopback is deliberate: Windows does not filter it and Chromium does not proxy it, so the
    page and its report survive every case including the one where the browser is comprehensively
    blocked. That keeps "the browser emitted nothing" distinguishable from "the page never ran".

    Reported candidates are secondary evidence. Chromium obfuscates host candidates behind mDNS
    .local names by default, so the candidate list is not where the leak shows up on a modern
    build -- the UDP counter is. The candidates are recorded anyway because AC-007 asks what an
    adversary site would learn, and "obfuscated" is a different answer from "nothing".

    Only the research browser (Edge Beta) is blocked, and only in case 5. The proxy policy in
    cases 2-4 is machine-wide for the moments it is set -- that is constraint 2, established in
    item 2, not something that can be scoped away.
#>
[CmdletBinding()]
param(
    [Parameter()] [string] $StunIp   = '10.20.40.21',
    [Parameter()] [int]    $StunPort = 19302,
    [Parameter()] [string] $ResearchBrowserPath = 'C:\Program Files (x86)\Microsoft\Edge Beta\Application\msedge.exe',
    [Parameter()] [int]    $HarnessPort  = 18098,
    [Parameter()] [int]    $DeadProxyPort = 19999,
    [Parameter()] [int]    $DwellSeconds = 14
)

$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'MinaEnforcementProbe.psm1') -Force

$harnessFile = Join-Path $PSScriptRoot '..\canaries\webrtc-harness.html'
if (-not (Test-Path -LiteralPath $harnessFile)) { throw "Harness page not found at $harnessFile" }
if (-not (Test-Path -LiteralPath $ResearchBrowserPath)) { throw "Research browser not found at $ResearchBrowserPath" }

$policyKey = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
if (Test-Path -LiteralPath $policyKey) {
    throw "$policyKey already exists. Refusing to overwrite real Edge policy configuration."
}

$runId     = [guid]::NewGuid().ToString('N').Substring(0, 8)
$ruleName  = "MINA-C2-WEBRTC-$runId"
$deadProxy = "127.0.0.1:$DeadProxyPort"
$pageHtml  = Get-Content -LiteralPath $harnessFile -Raw

$reports  = @{}
$listener = [System.Net.HttpListener]::new()
$listener.Prefixes.Add("http://127.0.0.1:$HarnessPort/")
$listener.Start()
$ctxTask = $listener.GetContextAsync()

function Invoke-Pump {
    param([int]$Ms = 300)
    $deadline = (Get-Date).AddMilliseconds($Ms)
    while ((Get-Date) -lt $deadline) {
        if ($script:ctxTask.IsCompleted) {
            try {
                $ctx = $script:ctxTask.Result
                if ($ctx.Request.HttpMethod -eq 'POST') {
                    $body = (New-Object IO.StreamReader($ctx.Request.InputStream)).ReadToEnd()
                    $parsed = $body | ConvertFrom-Json
                    $script:reports[$parsed.tag] = $parsed
                    $bytes = [Text.Encoding]::UTF8.GetBytes('ok')
                } else {
                    $bytes = [Text.Encoding]::UTF8.GetBytes($script:pageHtml)
                    $ctx.Response.ContentType = 'text/html'
                }
                $ctx.Response.OutputStream.Write($bytes, 0, $bytes.Length)
                $ctx.Response.Close()
            } catch { }
            $script:ctxTask = $script:listener.GetContextAsync()
        }
        Start-Sleep -Milliseconds 100
    }
}

function Invoke-WebRtcCase {
    param([string]$Tag, [string[]]$ExtraArgs = @())

    Invoke-Quietly { & pktmon.exe stop | Out-Null }
    Invoke-Quietly { & pktmon.exe filter remove | Out-Null }
    Invoke-Quietly { & pktmon.exe filter add MinaProbe -i $StunIp -p $StunPort | Out-Null }
    Invoke-Quietly { & pktmon.exe start --capture --counters-only | Out-Null }

    $dir = Join-Path $env:TEMP "mina-webrtc-$runId-$Tag"
    $url = "http://127.0.0.1:$HarnessPort/?tag=$Tag&stun=${StunIp}:${StunPort}"
    $argv = @(
        '--headless=new'
        "--user-data-dir=$dir"
        '--no-first-run'
        '--no-default-browser-check'
        '--disable-gpu'
    ) + $ExtraArgs + @($url)

    $proc = Start-Process -FilePath $ResearchBrowserPath -WindowStyle Hidden -PassThru -ArgumentList $argv
    try {
        $deadline = (Get-Date).AddSeconds($DwellSeconds)
        while ((Get-Date) -lt $deadline -and -not $reports.ContainsKey($Tag)) {
            Invoke-Pump -Ms 300
        }
        Invoke-Pump -Ms 500
    }
    finally {
        Stop-ProcessTree $proc.Id
        Invoke-Quietly { & pktmon.exe stop | Out-Null }
        Remove-Item -LiteralPath $dir -Recurse -Force -ErrorAction SilentlyContinue
    }

    $rpt      = if ($reports.ContainsKey($Tag)) { $reports[$Tag] } else { $null }
    $counters = Get-PktmonTxCounters
    return [pscustomobject]@{
        # Transmitted is egress. Dropped is the browser having tried and enforcement having
        # caught it -- reported separately because it is the stronger result: silence alone
        # cannot distinguish "blocked" from "WebRTC never ran".
        Udp        = $counters.Transmitted
        UdpDropped = $counters.Dropped
        Reported   = [bool]$rpt
        Reason     = if ($rpt) { $rpt.reason } else { 'no report received' }
        Candidates = if ($rpt) { @($rpt.candidates) } else { @() }
        Literals   = if ($rpt) { @($rpt.literalAddresses) } else { @() }
    }
}

function Set-ProxyPolicy {
    New-Item -Path $policyKey -Force | Out-Null
    $json = (@{ ProxyMode = 'fixed_servers'; ProxyServer = $deadProxy } | ConvertTo-Json -Compress)
    New-ItemProperty -Path $policyKey -Name 'ProxySettings' -Value $json -PropertyType String -Force | Out-Null
}

$cases = [ordered]@{}
try {
    $cases['1 no proxy, no hardening']            = Invoke-WebRtcCase 'plain'

    Set-ProxyPolicy
    $cases['2 fixed proxy, no hardening']         = Invoke-WebRtcCase 'proxied'
    $cases['3 proxy + --webrtc-ip-handling flag'] = Invoke-WebRtcCase 'flag' @('--webrtc-ip-handling-policy=disable_non_proxied_udp')

    New-ItemProperty -Path $policyKey -Name 'WebRtcLocalhostIpHandling' `
        -Value 'disable_non_proxied_udp' -PropertyType String -Force | Out-Null
    $cases['4 proxy + WebRtc policy']             = Invoke-WebRtcCase 'policy'

    Remove-Item -LiteralPath $policyKey -Recurse -Force -ErrorAction SilentlyContinue

    New-NetFirewallRule -DisplayName $ruleName -Name $ruleName -Direction Outbound `
        -Action Block -Program $ResearchBrowserPath -Profile Any -Enabled True | Out-Null
    $cases['5 C2 image-path block, no flags']     = Invoke-WebRtcCase 'wfp'
}
finally {
    Remove-Item -LiteralPath $policyKey -Recurse -Force -ErrorAction SilentlyContinue
    Invoke-Quietly { Remove-NetFirewallRule -Name $ruleName | Out-Null }
    $filtersCleared = Clear-ProbeCapture
    try { $listener.Stop(); $listener.Close() } catch { }
}

$policyGone = -not (Test-Path -LiteralPath $policyKey)
$ruleGone   = -not [bool](Get-NetFirewallRule -Name $ruleName -ErrorAction SilentlyContinue)

$plain   = $cases['1 no proxy, no hardening']
$proxied = $cases['2 fixed proxy, no hardening']
$flag    = $cases['3 proxy + --webrtc-ip-handling flag']
$policy  = $cases['4 proxy + WebRtc policy']
$wfp     = $cases['5 C2 image-path block, no flags']

$verdict =
    if ($plain.Udp -le 0) {
        'INCONCLUSIVE - ICE emitted no UDP even unhardened; the harness is not exercising WebRTC, so nothing below means anything'
    }
    elseif ($proxied.Udp -le 0) {
        'UNEXPECTED - the fixed proxy alone suppressed WebRTC UDP on this build. Constraint 5 may not hold as written; re-check before relying on the proxy as a WebRTC control'
    }
    elseif ($flag.Udp -eq 0 -and $policy.Udp -eq 0 -and $wfp.Udp -eq 0) {
        'ITEM 5 CONFIRMED - WebRTC bypasses the proxy, and the flag, the policy and the image-path block each stop it'
    }
    elseif ($flag.Udp -gt 0) {
        'FLAG INEFFECTIVE - --webrtc-ip-handling-policy did not stop non-proxied UDP'
    }
    elseif ($policy.Udp -gt 0) {
        'POLICY NAME NOT HONOURED - WebRtcLocalhostIpHandling had no effect; do not ship that name'
    }
    elseif ($wfp.Udp -gt 0) {
        'ENFORCEMENT GAP - UDP was TRANSMITTED despite the image-path block; C2 does not cover WebRTC at the network layer. Check the Drops column before believing this: dropped packets are enforcement working, not egress'
    }
    else { 'UNEXPECTED - review the per-case counts' }

[pscustomobject]@{
    RunId            = $runId
    StunTarget       = "${StunIp}:${StunPort}"
    ResearchBrowser  = (Get-Item -LiteralPath $ResearchBrowserPath).VersionInfo.ProductVersion
    Cases            = $cases
    PolicyKeyRemoved = $policyGone
    RuleRemoved      = $ruleGone
    FiltersCleared   = $filtersCleared
    Verdict          = $verdict
}
