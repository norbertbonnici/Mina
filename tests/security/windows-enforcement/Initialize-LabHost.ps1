#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Prepares a Windows client lab host for the ADR-0001 M1-5 verification register, and records
    what SKU the evidence taken there actually came from.

.DESCRIPTION
    Every M1-5 result so far was measured on the administration workstation: Windows Server 2025,
    build 26100. That shares a kernel and WFP stack with Windows 11 24H2, which is why those
    results were accepted as evidence for a client SKU -- but that is an argument, not a
    measurement. Re-running the register on a real Windows 11 client turns it into one, and this
    script is what makes a fresh client host fit to do that.

    Four things, in an order that matters:

      1  Records host identity -- SKU, build, virtualisation platform. This is the provenance
         line that belongs beside any result the register scripts produce on this host, because
         the entire reason for running them here is that the SKU is the variable under test.

      2  Asserts the preconditions that would otherwise make a result vacuous rather than wrong:
         both Edge channels present at distinct image paths (variant C2 is two image paths -- with
         one, there is nothing to separate), and the Windows Firewall enabled on every profile.
         A block-rule test on a host with the firewall switched off passes every case and proves
         nothing; a fresh VM is exactly where that is worth checking rather than assuming.

      3  Measures the chosen target channel with nothing running -- case D0. A channel that is
         not silent when idle cannot have a packet count attributed to it. This check exists
         because it has already produced one false result in this project: unrelated traffic on
         TCP/443 toward the lab target read as "DnsOverHttpsMode NOT HONOURED", the exact
         opposite of the truth.

      4  Self-tests the instrument: generates a known SYN and confirms pktmon counts it. Without
         this, a "0 packets" result is unfalsifiable -- it cannot tell enforcement apart from a
         probe that never worked on this host at all.

    Steps 3 and 4 are in that order deliberately: step 4 puts traffic on the channel step 3 has
    to find silent.

.PARAMETER TargetIp
    Off-box address the probes are aimed at. Two properties matter and are easy to get wrong:
    it must be OFF this machine, because Windows exempts traffic to the host's own address from
    outbound filtering (a canary listening here is reached even by a fully blocked process), and
    nothing may listen on the port, so the only thing that can move the counter is the process
    under test. The default is the lab address every register script defaults to, so the readiness
    measured here is the readiness of the channel they will actually use; override it on both sides
    together if this host has no line of sight to it. Do not point it at a public resolver to work
    around a routing problem: 1.1.1.1 and its kind answer on 443, which breaks the "nothing may
    listen" precondition above, turns Invoke-QuicDohVerification's forced-QUIC cases into a real
    handshake with a stranger, and sends unsolicited probe traffic to a third party.

.NOTES
    Nothing here is destructive and nothing is left running: pktmon capture is stopped and probe
    filters removed on the way out. -InstallMissing is the only switch that changes the host, and
    it only installs Edge Beta machine-wide via winget.
#>
[CmdletBinding()]
param(
    [Parameter()] [string] $TargetIp   = '10.20.40.21',
    [Parameter()] [int]    $TargetPort = 18099,
    [Parameter()] [string] $StablePath = 'C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe',
    [Parameter()] [string] $BetaPath   = 'C:\Program Files (x86)\Microsoft\Edge Beta\Application\msedge.exe',
    [Parameter()] [int]    $IdleSeconds = 10,
    # Installs Edge Beta machine-wide if it is absent. Off by default: this script's job is to
    # report what the host is, and silently installing software is not that.
    [Parameter()] [switch] $InstallMissing
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
Import-Module (Join-Path $PSScriptRoot 'MinaEnforcementProbe.psm1') -Force

$failures = [System.Collections.Generic.List[string]]::new()

function Start-ProbeCapture {
    param([string] $Ip, [int] $Port)
    Invoke-Quietly { & pktmon.exe stop | Out-Null }
    Invoke-Quietly { & pktmon.exe filter remove | Out-Null }
    Invoke-Quietly { & pktmon.exe filter add MinaProbe -i $Ip -p $Port | Out-Null }
    Invoke-Quietly { & pktmon.exe start --capture --counters-only | Out-Null }
}

# ---------------------------------------------------------------------------------------------
# 1. Host identity
# ---------------------------------------------------------------------------------------------
Write-Host '==> Host identity' -ForegroundColor Cyan

$os = Get-CimInstance -ClassName Win32_OperatingSystem
$cs = Get-CimInstance -ClassName Win32_ComputerSystem

# ProductType 1 is a workstation (client SKU); 2 a domain controller; 3 any other server. The
# whole point of running the register here is that this reads 1 where the earlier evidence read 3.
$skuKind = switch ($os.ProductType) {
    1       { 'Client workstation' }
    2       { 'Domain controller' }
    3       { 'Server' }
    default { "Unknown ($($os.ProductType))" }
}

$joinState = if ($cs.PartOfDomain) { "Domain-joined ($($cs.Domain))" } else { 'Workgroup / not domain-joined' }

$identity = [pscustomobject]@{
    ComputerName = $env:COMPUTERNAME
    Caption      = $os.Caption
    Version      = $os.Version
    Build        = $os.BuildNumber
    ProductType  = $skuKind
    Platform     = "$($cs.Manufacturer) / $($cs.Model)"
    PsVersion    = $PSVersionTable.PSVersion.ToString()
    JoinState    = $joinState
}
$identity | Format-List | Out-String | Write-Host

if ($os.ProductType -ne 1) {
    Write-Host '    NOTE: this is not a client SKU, so running the register here does not answer' -ForegroundColor Yellow
    Write-Host '          the question the client-SKU re-run exists to answer.' -ForegroundColor Yellow
}

# ---------------------------------------------------------------------------------------------
# 2a. Windows Firewall must be on, or every block-rule case passes vacuously
# ---------------------------------------------------------------------------------------------
Write-Host '==> Windows Firewall profiles' -ForegroundColor Cyan

# ActiveStore, not the default PersistentStore: the default reads this host's own local
# configuration, which a domain or Intune policy can override without changing. On a managed client
# -- which is exactly what this re-run exists to measure -- a firewall switched off by GPO reports
# Enabled=True from the local store while netsh reports OFF, and the host would be declared READY
# with no enforcement behind any block rule. ActiveStore is the effective state, whatever set it.
$fwProfiles = Get-NetFirewallProfile -PolicyStore ActiveStore | Select-Object Name, Enabled, DefaultOutboundAction
$fwProfiles | Format-Table -AutoSize | Out-String | Write-Host

# Enabled is GpoBoolean, which is three-state: False=0, True=1, NotConfigured=2. `-not $_.Enabled`
# coerces via the underlying value, so it is true only for False and reads NotConfigured -- a
# profile whose state was never actually determined -- as an enabled firewall. Anything that is not
# positively True is unfit to measure against.
$disabled = @($fwProfiles | Where-Object { $_.Enabled -ne 'True' })
if ($disabled.Count -gt 0) {
    $failures.Add("Firewall not enabled on profile(s): $($disabled.Name -join ', ') (effective state: " +
                  "$(($disabled | ForEach-Object { "$($_.Name)=$($_.Enabled)" }) -join ', ')). A block " +
                  'rule on a profile that is not enabled enforces nothing, so every blocked case ' +
                  'would pass without the rule doing any work.')
}

# A leftover rule from an aborted run would silently bias a later case, so name any that exist.
$stale = @(Get-NetFirewallRule -ErrorAction SilentlyContinue |
           Where-Object { $_.Name -like 'MINA-C2-VERIFY-*' -or $_.Name -eq 'Mina-ResearchBrowser-C2-Block' })
if ($stale.Count -gt 0) {
    Write-Host '    Pre-existing Mina rules on this host (not removed by this script):' -ForegroundColor Yellow
    foreach ($rule in $stale) {
        Write-Host "      $($rule.Name)  enabled=$($rule.Enabled)  action=$($rule.Action)" -ForegroundColor Yellow
    }
}
else {
    Write-Host '    No pre-existing Mina firewall rules.'
}

# ---------------------------------------------------------------------------------------------
# 2b. Two Edge channels at distinct image paths -- variant C2 has nothing to separate without them
# ---------------------------------------------------------------------------------------------
Write-Host '==> Edge channels' -ForegroundColor Cyan

if ($InstallMissing -and -not (Test-Path -LiteralPath $BetaPath)) {
    Write-Host '    Edge Beta absent; installing machine-wide via winget...'

    # Deliberately not Invoke-Quietly. That helper exists so a benign stderr line from a *cleanup*
    # call (taskkill on a dead pid, pktmon stop with nothing capturing) cannot abort the run, and it
    # restores $LASTEXITCODE on the way out -- which is precisely the signal that matters here. Run
    # through it, a failed install is invisible and the only symptom is the Test-Path miss below
    # telling the operator to pass the switch they just passed. The stderr demotion is still wanted,
    # though: winget writes progress there, and $ErrorActionPreference is 'Stop' in this script.
    $wingetExit = $null
    $prevPreference = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        & winget.exe install --id Microsoft.Edge.Beta --scope machine --silent `
            --accept-package-agreements --accept-source-agreements | Out-Null
        $wingetExit = $LASTEXITCODE
    }
    finally {
        $ErrorActionPreference = $prevPreference
    }

    if ($wingetExit -ne 0) {
        Write-Host "    winget exited $wingetExit" -ForegroundColor Red
        $failures.Add("winget install of Edge Beta failed (exit code $wingetExit). Install it by " +
                      'hand and re-run, or pass -BetaPath if it is already installed somewhere ' +
                      'other than the default location. Re-running with -InstallMissing will not ' +
                      'help: this is the install itself failing, not the switch being absent.')
    }
}

foreach ($channel in @(
        [pscustomobject]@{ Name = 'Stable'; Path = $StablePath },
        [pscustomobject]@{ Name = 'Beta';   Path = $BetaPath })) {

    if (Test-Path -LiteralPath $channel.Path) {
        $ver = (Get-Item -LiteralPath $channel.Path).VersionInfo.ProductVersion
        Write-Host "    $($channel.Name.PadRight(6)) $ver  $($channel.Path)"
    }
    else {
        Write-Host "    $($channel.Name.PadRight(6)) MISSING  $($channel.Path)" -ForegroundColor Red
        $failures.Add("Edge $($channel.Name) not found at '$($channel.Path)'. Variant C2 needs two " +
                      'channels installed at distinct image paths; re-run with -InstallMissing, or ' +
                      'install it by hand.')
    }
}

if ((Test-Path -LiteralPath $StablePath) -and (Test-Path -LiteralPath $BetaPath) -and
    (Get-Item -LiteralPath $StablePath).FullName -eq (Get-Item -LiteralPath $BetaPath).FullName) {
    $failures.Add('StablePath and BetaPath resolve to the same image. The register tests two paths apart.')
}

# ---------------------------------------------------------------------------------------------
# 2c. pktmon
# ---------------------------------------------------------------------------------------------
Write-Host '==> Measurement tooling' -ForegroundColor Cyan

$pktmon = Get-Command pktmon.exe -ErrorAction SilentlyContinue
if ($pktmon) {
    Write-Host "    pktmon  $($pktmon.Source)"
}
else {
    Write-Host '    pktmon  MISSING' -ForegroundColor Red
    $failures.Add('pktmon.exe not found. Every register script measures egress with it; there is no fallback.')
}

# ---------------------------------------------------------------------------------------------
# 3. Idle-channel control (D0) -- before anything is asked to generate traffic
# ---------------------------------------------------------------------------------------------
$idle     = $null
$selfTest = $null

if ($pktmon) {
    Write-Host "==> Idle-channel control: ${TargetIp}:${TargetPort} for ${IdleSeconds}s, nothing running" -ForegroundColor Cyan

    Start-ProbeCapture -Ip $TargetIp -Port $TargetPort
    try     { Start-Sleep -Seconds $IdleSeconds }
    finally { Invoke-Quietly { & pktmon.exe stop | Out-Null } }

    $idle = Get-PktmonTxCounters
    Write-Host "    transmitted=$($idle.Transmitted)  dropped=$($idle.Dropped)"

    if ($idle.Transmitted -gt 0) {
        $failures.Add("The target channel is not silent when idle ($($idle.Transmitted) packets in " +
                      "${IdleSeconds}s toward ${TargetIp}:${TargetPort}). Any count attributed to a " +
                      'browser or a policy on this channel would include that noise -- pick a port ' +
                      'nothing else on this host talks to and re-run.')
    }

    # -----------------------------------------------------------------------------------------
    # 4. Instrument self-test -- prove the probe can see egress that definitely happened
    # -----------------------------------------------------------------------------------------
    Write-Host '==> Instrument self-test: emitting SYNs toward the same target' -ForegroundColor Cyan

    Start-ProbeCapture -Ip $TargetIp -Port $TargetPort
    try {
        for ($i = 0; $i -lt 3; $i++) {
            $client = [System.Net.Sockets.TcpClient]::new()
            try {
                $async = $client.BeginConnect($TargetIp, $TargetPort, $null, $null)
                [void] $async.AsyncWaitHandle.WaitOne(1500)
            }
            catch { }
            finally { $client.Dispose() }
        }
        Start-Sleep -Seconds 2
    }
    finally { Invoke-Quietly { & pktmon.exe stop | Out-Null } }

    $selfTest = Get-PktmonTxCounters
    Write-Host "    transmitted=$($selfTest.Transmitted)  dropped=$($selfTest.Dropped)"

    if ($selfTest.Transmitted -le 0) {
        $failures.Add('The instrument saw nothing for traffic this script generated itself toward ' +
                      "${TargetIp}:${TargetPort}. Until that reads non-zero, a '0 packets' result " +
                      'from any register script on this host means nothing -- it cannot be told ' +
                      'apart from a probe that does not work here. Try a different target address ' +
                      "(this host's network may be dropping it) and check the vNIC is the adapter " +
                      'pktmon is counting.')
    }

    [void] (Clear-ProbeCapture)
}

# ---------------------------------------------------------------------------------------------
# Verdict
# ---------------------------------------------------------------------------------------------
Write-Host ''
Write-Host '==================== LAB HOST READINESS ====================' -ForegroundColor Cyan

$idleReport = if ($null -ne $idle)     { $idle.Transmitted }     else { 'not measured' }
$probeReport = if ($null -ne $selfTest) { $selfTest.Transmitted } else { 'not measured' }

$result = [pscustomobject]@{
    Host             = $identity.ComputerName
    Caption          = $identity.Caption
    Build            = $identity.Build
    ProductType      = $identity.ProductType
    Platform         = $identity.Platform
    Target           = "${TargetIp}:${TargetPort}"
    IdleTransmitted  = $idleReport
    ProbeTransmitted = $probeReport
    Ready            = ($failures.Count -eq 0)
}
$result | Format-List | Out-String | Write-Host

if ($failures.Count -eq 0) {
    Write-Host 'READY -- the register scripts will produce meaningful results on this host.' -ForegroundColor Green

    # Only the scripts that actually declare these parameters. Printing one blanket invocation for
    # all eight sent the operator into a binding error on five of them: four take no target
    # parameters at all, and Invoke-QuicDohVerification takes -TargetIp but has no -TargetPort.
    Write-Host '  -TargetIp and -TargetPort:' -ForegroundColor Green
    Write-Host "      Invoke-C2Verification.ps1 -TargetIp $TargetIp -TargetPort $TargetPort" -ForegroundColor Green
    Write-Host "      Invoke-PolicyScopeVerification.ps1 -TargetIp $TargetIp -TargetPort $TargetPort" -ForegroundColor Green
    Write-Host "      Invoke-StartupLeakVerification.ps1 -TargetIp $TargetIp -TargetPort $TargetPort" -ForegroundColor Green
    Write-Host '  -TargetIp only:' -ForegroundColor Green
    Write-Host "      Invoke-QuicDohVerification.ps1 -TargetIp $TargetIp" -ForegroundColor Green
    Write-Host '  No target parameters -- run as-is:' -ForegroundColor Green
    Write-Host '      Invoke-DnsLeakVerification.ps1, Invoke-Ipv6LeakVerification.ps1,' -ForegroundColor Green
    Write-Host '      Invoke-LoopbackBypassVerification.ps1, Invoke-WebRtcLeakVerification.ps1' -ForegroundColor Green
}
else {
    Write-Host 'NOT READY:' -ForegroundColor Red
    foreach ($failure in $failures) { Write-Host "  - $failure" -ForegroundColor Red }
}

return $result
