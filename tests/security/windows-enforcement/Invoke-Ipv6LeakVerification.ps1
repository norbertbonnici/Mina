#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Measures whether the research browser ever reaches an IPv6-only destination directly, instead
    of through the proxy, once one is configured.

.DESCRIPTION
    M1-6 (AC-006) and THREAT_MODEL §7 residual risk #4 frame this platform's actual commitment
    precisely: MVP egress is IPv4-only, by accepted design, not an oversight to be fixed here.
    That reframes what "IPv6 leak" has to mean for AC-006 to be answerable at all -- it cannot be
    "dual-stack egress works," because this platform never promised that. It has to be: does a
    dual-stack endpoint ever take a *direct* route to an IPv6-only destination once proxied,
    rather than failing the way an IPv4-only egress path should for a destination it cannot reach?
    A silent direct fallback would be worse than the request simply failing -- it would mean the
    one case this platform is explicit about not serving is exactly the case most likely to leak.

    Measured categorically, not by counting: this script resolves the target's own AAAA address
    once up front and scopes pktmon's capture to that specific address (`-i <address>`), then
    decodes the capture (`pktmon etl2txt`) and checks whether any packet toward it appears at all
    -- the same method, and the same reason, as Invoke-DnsLeakVerification.ps1's rewrite. An
    earlier version of this script filtered by data-link protocol alone (`-d IPv6`, any
    destination) and counted packets against a fixed threshold; an adversarial review of this
    repo's own work found that filter cannot distinguish this platform's target from ordinary
    Windows IPv6 housekeeping (link-local ND/RA/mDNS traffic exists on any dual-stack host,
    proxied or not), and -- because this admin workstation has no real IPv6 route at all -- the
    counting logic had literally never executed against a host where it could produce a real
    verdict, so it shipped untested. Scoping to the resolved address removes the ambiguity
    entirely: a packet toward that one address is unambiguous, regardless of what else is on the
    wire.

      1 no proxy, direct navigation          expect REACHED       this machine can reach the target's IPv6 address
                                                                     directly and the method can see it -- confirms
                                                                     the test means something before trusting a
                                                                     proxied "not reached"
      2 proxied, live proxy                  expect NOT REACHED   no direct v6 fallback once a proxy is configured
      3 proxied, dead proxy                  expect NOT REACHED   even a failed CONNECT should not fall back to
                                                                     a direct route
      4 proxied, production flags            expect NOT REACHED   the actual shipped flag set
                                                                     (edge-integration/research-browser-flags.json)

.NOTES
    Cases 2 and 4 also record whether the stand-in proxy actually received a CONNECT for the
    target hostname during the dwell window, for the same reason Invoke-DnsLeakVerification.ps1
    does: "the direct route stayed silent" is only reassuring if the browser did something at all,
    not if it simply failed to navigate.

    This host has no global unicast IPv6 address at all (confirmed live, `Get-NetIPAddress`) --
    only link-local/ULA, so it cannot originate a routed connection to *any* internet destination
    regardless of proxying. That precondition is checked and reported explicitly
    (`NOT TESTABLE HERE`) rather than left to read as an unearned pass; the case ladder below has
    not been exercised end-to-end against a capable host and its correctness rests on the same
    method as the DNS script, not on having been proven here.

    Scoped deliberately to what Windows/Chromium-side testing can honestly answer: whether the
    *browser* takes a direct v6 route. Whether the real egress path (Envoy on the live stamp)
    then correctly refuses or cannot reach an AAAA-only destination is a node-side question this
    script does not and cannot answer -- IPv4-only egress at MVP is the accepted framing
    (THREAT_MODEL §7 residual risk #4), not something under test here. Also does not run against
    a real analyst session on the live stamp, for the same reason every other script in this
    directory says so: that whole chain is still blocked on M2-1 and the remaining part of M2-4.
#>
[CmdletBinding()]
param(
    [Parameter()] [string] $ResearchBrowserPath = 'C:\Program Files (x86)\Microsoft\Edge Beta\Application\msedge.exe',
    [Parameter()] [string] $TargetHostname       = 'ipv6.google.com',
    [Parameter()] [int]    $LiveProxyPort        = 18098,
    [Parameter()] [int]    $DeadProxyPort        = 19997,
    [Parameter()] [int]    $DwellSeconds         = 12
)

$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'MinaEnforcementProbe.psm1') -Force

if (-not (Test-Path -LiteralPath $ResearchBrowserPath)) { throw "Browser not found at $ResearchBrowserPath" }
if (Get-NetTCPConnection -State Listen -LocalPort $DeadProxyPort -ErrorAction SilentlyContinue) {
    throw "Something is listening on $DeadProxyPort. The dead-proxy case must be dead to discriminate."
}

# Confirmed live, not assumed -- and fails LOUD, not quiet, on anything but a clean "no A record"
# answer. A transient resolver hiccup here must not be readable as "confirmed AAAA-only, proceed":
# that would make a DNS outage look identical to the very property this script is supposed to
# verify, which is the unsafe direction for a security test to fail in.
$aLookup = Resolve-DnsName -Name $TargetHostname -Type A -ErrorAction SilentlyContinue
if ($null -eq $aLookup -and $Error.Count -gt 0 -and $Error[0].Exception -notmatch 'no records') {
    throw "Could not confirm $TargetHostname has no A record (resolution itself may have failed) -- not proceeding on an unconfirmed precondition. $($Error[0].Exception.Message)"
}
$aRecords = @($aLookup | Where-Object { $_.Type -eq 'A' })
if ($aRecords.Count -gt 0) {
    throw "$TargetHostname resolved $($aRecords.Count) A record(s) ($(($aRecords.IPAddress) -join ', ')) -- not AAAA-only, pick a different target."
}
$aaaaRecords = @(Resolve-DnsName -Name $TargetHostname -Type AAAA -ErrorAction Stop | Where-Object { $_.Type -eq 'AAAA' })
if ($aaaaRecords.Count -eq 0) {
    throw "$TargetHostname resolved no AAAA record either -- not a usable AAAA-only target."
}
$targetAddress = $aaaaRecords[0].IPAddress

# A global unicast address is what this test actually needs -- a link-local or ULA-only host
# (RFC 4193 fd00::/8, common on networks with no real IPv6 transit) cannot originate a routed
# connection to a real internet destination at all. Checked once, up front, so the verdict below
# can say which situation this actually is instead of guessing.
$hasGlobalIpv6 = [bool](Get-NetIPAddress -AddressFamily IPv6 -ErrorAction SilentlyContinue |
    Where-Object { $_.IPAddress -match '^[2-3]' -and $_.AddressState -eq 'Preferred' })

$runId = [guid]::NewGuid().ToString('N').Substring(0, 8)

# A minimal CONNECT-capable stand-in, identical in shape to Invoke-DnsLeakVerification.ps1's --
# accepts the tunnel, records the request line, answers 200, then closes without forwarding
# anywhere.
$proxyListener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, $LiveProxyPort)
$proxyListener.Start()
$proxyAcceptTask = $proxyListener.AcceptTcpClientAsync()
$script:proxyRequests = New-Object System.Collections.Generic.List[string]

function Invoke-ProxyPump {
    param([int] $Ms = 300)
    $deadline = (Get-Date).AddMilliseconds($Ms)
    while ((Get-Date) -lt $deadline) {
        if ($script:proxyAcceptTask.IsCompleted) {
            try {
                $client = $script:proxyAcceptTask.Result
                $stream = $client.GetStream()
                Start-Sleep -Milliseconds 50
                if ($stream.DataAvailable) {
                    $buf = New-Object byte[] 4096
                    $read = $stream.Read($buf, 0, $buf.Length)
                    if ($read -gt 0) {
                        $firstLine = ([Text.Encoding]::ASCII.GetString($buf, 0, $read) -split "`r`n")[0]
                        [void]$script:proxyRequests.Add($firstLine)
                    }
                }
                $resp = [Text.Encoding]::ASCII.GetBytes("HTTP/1.1 200 Connection Established`r`n`r`n")
                $stream.Write($resp, 0, $resp.Length)
                $stream.Close(); $client.Close()
            } catch { }
            $script:proxyAcceptTask = $script:proxyListener.AcceptTcpClientAsync()
        }
        Start-Sleep -Milliseconds 100
    }
}

function Get-ProductionFlags {
    param([int] $ProxyPort)
    $configPath = Join-Path $PSScriptRoot '..\..\..\edge-integration\research-browser-flags.json'
    $config = Get-Content -LiteralPath $configPath -Raw | ConvertFrom-Json
    $flags = $config.launchFlags | Where-Object {
        $_ -notmatch '^--user-data-dir=' -and $_ -notmatch '^--proxy-server='
    }
    return @("--proxy-server=http://127.0.0.1:$ProxyPort") + $flags
}

function Remove-DirectoryWithRetry {
    param([string] $Path, [int] $Attempts = 5)
    for ($i = 0; $i -lt $Attempts; $i++) {
        try { Remove-Item -LiteralPath $Path -Recurse -Force -ErrorAction Stop; return }
        catch { Start-Sleep -Milliseconds 300 }
    }
    Invoke-Quietly { Remove-Item -LiteralPath $Path -Recurse -Force }
}

function Test-TargetReachedDirectly {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $Exe,
        [Parameter(Mandatory)] [string] $Tag,
        [string[]] $ExtraArgs = @(),
        [switch]   $PumpProxy
    )

    Invoke-Quietly { & pktmon.exe stop | Out-Null }
    Invoke-Quietly { & pktmon.exe filter remove | Out-Null }
    Invoke-Quietly { & pktmon.exe filter add MinaIpv6Target -i $targetAddress | Out-Null }
    $etlPath = Join-Path $env:TEMP "mina-v6-$runId-$Tag.etl"
    Invoke-Quietly { & pktmon.exe start --capture -f $etlPath | Out-Null }

    $script:proxyRequests.Clear()
    $dir = Join-Path $env:TEMP "mina-v6-$runId-$Tag"
    $argv = @(
        '--headless=new'
        "--user-data-dir=$dir"
        '--no-first-run'
        '--no-default-browser-check'
        '--disable-gpu'
    ) + $ExtraArgs + @("https://$TargetHostname/")

    $proc = Start-Process -FilePath $Exe -WindowStyle Hidden -PassThru -ArgumentList $argv
    try {
        if ($PumpProxy) {
            $deadline = (Get-Date).AddSeconds($DwellSeconds)
            while ((Get-Date) -lt $deadline) { Invoke-ProxyPump -Ms 300 }
        }
        else {
            Start-Sleep -Seconds $DwellSeconds
        }
    }
    finally {
        Stop-ProcessTree $proc.Id
        Invoke-Quietly { & pktmon.exe stop | Out-Null }
        Remove-DirectoryWithRetry -Path $dir
    }

    $reached = $false
    if (Test-Path -LiteralPath $etlPath) {
        $txtPath = Join-Path $env:TEMP "mina-v6-$runId-$Tag.txt"
        Invoke-Quietly { & pktmon.exe etl2txt $etlPath --out $txtPath | Out-Null }
        if (Test-Path -LiteralPath $txtPath) {
            # pktmon etl2txt always emits a "Packet Filter" metadata line echoing the filter's own
            # configured IP, whether or not anything matched it -- found live, the hard way, on a
            # capture with zero real packets that still "matched" every time. Excluded explicitly
            # rather than trusted; only an actual decoded packet line counts.
            $reached = [bool](Select-String -LiteralPath $txtPath -Pattern ([regex]::Escape($targetAddress)) |
                Where-Object { $_.Line -notmatch 'Packet Filter' })
            Remove-Item -LiteralPath $txtPath -ErrorAction SilentlyContinue
        }
        Remove-Item -LiteralPath $etlPath -ErrorAction SilentlyContinue
    }

    [pscustomobject]@{
        ReachedDirectly = $reached
        ProxyReachedIt  = if ($PumpProxy) { [bool]($script:proxyRequests -match [regex]::Escape($TargetHostname)) } else { $null }
    }
}

$cases = [ordered]@{}
try {
    $cases['1 no proxy']                 = Test-TargetReachedDirectly $ResearchBrowserPath 'noproxy'
    $cases['2 proxied, live proxy']       = Test-TargetReachedDirectly $ResearchBrowserPath 'liveproxy' @("--proxy-server=http://127.0.0.1:$LiveProxyPort") -PumpProxy
    $cases['3 proxied, dead proxy']       = Test-TargetReachedDirectly $ResearchBrowserPath 'deadproxy' @("--proxy-server=http://127.0.0.1:$DeadProxyPort")
    $cases['4 proxied, production flags'] = Test-TargetReachedDirectly $ResearchBrowserPath 'prodflags' (Get-ProductionFlags -ProxyPort $LiveProxyPort) -PumpProxy
}
finally {
    Invoke-Quietly { $proxyListener.Stop() }
    Clear-ProbeCapture | Out-Null
}

$c1 = $cases['1 no proxy'].ReachedDirectly
$c2 = $cases['2 proxied, live proxy'].ReachedDirectly
$c3 = $cases['3 proxied, dead proxy'].ReachedDirectly
$c4 = $cases['4 proxied, production flags'].ReachedDirectly
$proxySawIt2 = $cases['2 proxied, live proxy'].ProxyReachedIt
$proxySawIt4 = $cases['4 proxied, production flags'].ProxyReachedIt

$verdict =
    if (-not $hasGlobalIpv6) {
        "NOT TESTABLE HERE - this host has no global unicast IPv6 address (only link-local/ULA), so it cannot originate a routed connection to $targetAddress regardless of proxying; the browser-side no-direct-fallback claim needs a host with real IPv6 transit to verify (raw: unproxied=$c1, live=$c2, dead=$c3, prodflags=$c4)"
    }
    elseif (-not $c1) {
        "INCONCLUSIVE - the target address was not reached even unproxied; the measurement did not detect a real connection attempt"
    }
    elseif ($c2 -or $c3 -or $c4) {
        "GAP - the browser reached $targetAddress directly while proxied (live=$c2, dead=$c3, prodflags=$c4)"
    }
    elseif (-not ($proxySawIt2 -or $proxySawIt4)) {
        "INCONCLUSIVE - the direct route stayed silent while proxied, but the stand-in proxy never saw a CONNECT for '$TargetHostname' either (live=$proxySawIt2, prodflags=$proxySawIt4) -- cannot tell 'used the proxy correctly' apart from 'did nothing'"
    }
    else {
        "NO DIRECT FALLBACK - $targetAddress is reached unproxied and not reached directly once proxied (live=$c2, dead=$c3, prodflags=$c4), and the proxy itself did receive the CONNECT for the hostname (live=$proxySawIt2, prodflags=$proxySawIt4)"
    }

[pscustomobject]@{
    RunId          = $runId
    TargetHostname = $TargetHostname
    TargetAddress  = $targetAddress
    HasGlobalIpv6  = $hasGlobalIpv6
    BrowserVersion = (Get-Item -LiteralPath $ResearchBrowserPath).VersionInfo.ProductVersion
    Cases          = $cases
    Verdict        = $verdict
}
