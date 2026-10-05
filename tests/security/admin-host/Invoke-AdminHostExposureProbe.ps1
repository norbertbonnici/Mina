#Requires -Version 5.1
#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Enforces D-21 on an administration host: no third-party CI, and no principal outside
    owner/SYSTEM/Administrators able to read the platform's credential stores.

.DESCRIPTION
    THREAT_MODEL B10 records that an administration host sits inside every Mina plane at once.
    D-21 decides that such a host does not run third-party CI. Backlog M4-30(b) asks for a check
    that enforces that rather than trusting it, because the original exposure was found only by
    accident — OpenSSH refuses a key with loose permissions and says so, while nothing at all
    checks the Azure token store.

    Read-only. It does not modify ACLs, services, the registry or any credential store. The only
    files it writes are its own JSON report and nothing else.

    WHY A NAIVE VERSION OF THIS CHECK WOULD HAVE PASSED THE INCIDENT. The dangerous ACE named a
    local GROUP (GITHUB_ActionsRunner_*) whose member was NETWORK SERVICE. A check comparing ACL
    identity strings sees an unfamiliar group, has no rule for it, and reports clean. So the ACL
    predicate closes group membership to leaf principals, compares SIDs rather than names, and
    treats a closure it cannot complete as a failure — never as a skip.

    THE FIRST RUN ON ADMIN-WS01 IS EXPECTED TO REPORT VIOLATION, because the unrelated CI runner is
    still installed here (M4-30 remaining item (a)). A green first run would mean the check is
    broken, not that the host is clean.

.PARAMETER SkipSelfTest
    Skips the falsifiability harness. The report is then marked TrustLevel=untrusted, because a
    predicate that has not demonstrated it can fail is not evidence.

.NOTES
    Verdict ladder, highest precedence first:
      SELF-TEST-FAILED (4)  the instrument is broken; findings are withheld from the verdict
      VIOLATION (1)         a credential store is reachable, or a CI agent is present
      INCONCLUSIVE (2)      something could not be enumerated; never report clean instead
      NOT-AN-ADMINISTRATION-HOST (3)  D-21 does not apply here; a scope statement, not a pass
      COMPLIANT (0)
#>
[CmdletBinding()]
param(
    [Parameter()] [string]   $ProfilePath = $env:USERPROFILE,
    [Parameter()] [string]   $RepoPath    = (Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSScriptRoot))),
    [Parameter()] [string[]] $MinaSubscriptionIds = @('04d3d150-1b4c-4cec-b73e-9030c0c0c27c'),
    [Parameter()] [string[]] $ControlPlaneAddresses = @('10.20.40.21', '10.20.40.90', '10.20.40.91'),
    [Parameter()] [string]   $ReportPath,
    [Parameter()] [switch]   $SkipSelfTest
)

$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'MinaAdminHostProbe.psm1') -Force

$machineSid = ((Get-LocalUser -Name 'Administrator').SID.Value -replace '-500$','') -replace '^S-1-5-21-',''
# The identity this host belongs to. Its own access to its own credentials is not the question
# D-21 asks; who else can reach them is.
#
# NOT the profile directory's owner: on this host that is SYSTEM, which is already accepted, so
# using it silently accepts nothing and every store then reports the legitimate user as a
# violation — 38 findings all naming the account whose credentials these are. A check that
# reports the owner of the data as the threat is worse than no check, because it gets muted.
# ProfileList maps SID to profile path authoritatively, and works when auditing another profile.
$script:profileOwnerSid = $null
foreach ($k in (Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList' -ErrorAction SilentlyContinue)) {
    $pip = (Get-ItemProperty $k.PSPath -ErrorAction SilentlyContinue).ProfileImagePath
    if ($pip -and ($pip.TrimEnd('\') -ieq $ProfilePath.TrimEnd('\'))) { $script:profileOwnerSid = $k.PSChildName; break }
}
if (-not $script:profileOwnerSid -and $ProfilePath -ieq $env:USERPROFILE) {
    $script:profileOwnerSid = ([Security.Principal.WindowsIdentity]::GetCurrent()).User.Value
}
if (-not $script:profileOwnerSid) { throw "Could not determine the owning identity for profile '$ProfilePath'. Refusing to evaluate: without it every ACE for the legitimate user reads as a violation." }
$counters = @{ ObjectsWalked = 0; DaclsEvaluated = 0; ServicesEnumerated = 0; GroupsEnumerated = 0 }
$gaps = New-Object System.Collections.ArrayList
$violations = New-Object System.Collections.ArrayList

function Add-Gap { param([string]$Kind, [string]$Name, [string]$Reason)
    [void]$gaps.Add([pscustomobject]@{ Kind = $Kind; Name = $Name; Reason = $Reason }) }

# ---- H1: administration-host gate (positive control) ---------------------------------------
# Never report COMPLIANT from a host that produced no evidence it is in scope. A clean result
# from a machine holding none of these credentials says nothing about D-21.
$evidence = [ordered]@{}
$az = Invoke-Quietly { & az account show -o json }
$azJson = if ($az) { try { ($az | Out-String | ConvertFrom-Json) } catch { $null } } else { $null }
$evidence['AzureSession'] = [bool]($azJson -and ($MinaSubscriptionIds -contains $azJson.id))
$sshDir = Join-Path $ProfilePath '.ssh'
$evidence['SshPrivateKey'] = [bool]((Test-Path $sshDir) -and (Get-ChildItem $sshDir -File -Force -ErrorAction SilentlyContinue |
    Where-Object { (Get-Content $_.FullName -TotalCount 1 -ErrorAction SilentlyContinue) -match '^-----BEGIN .*PRIVATE KEY-----' }))
$kh = Join-Path $sshDir 'known_hosts'
$evidence['KnownHostsMatch'] = [bool]((Test-Path $kh) -and ((Get-Content $kh -Raw -ErrorAction SilentlyContinue) -match ($ControlPlaneAddresses -join '|')))
$evidence['TerraformBackend'] = [bool](Get-ChildItem (Join-Path $RepoPath 'infra\terraform\environments') -Recurse -Filter 'backend.hcl' -Force -ErrorAction SilentlyContinue)
$evidenceScore = @($evidence.Values | Where-Object { $_ }).Count

# ---- credential stores ---------------------------------------------------------------------
$storePaths = @(
    (Join-Path $ProfilePath '.ssh'),
    (Join-Path $ProfilePath '.azure'),
    (Join-Path $ProfilePath 'AppData\Roaming\Microsoft\Protect'),
    (Join-Path $ProfilePath 'AppData\Roaming\Microsoft\Credentials'),
    (Join-Path $ProfilePath 'AppData\Local\Microsoft\Credentials'),
    (Join-Path $ProfilePath 'AppData\Roaming\Microsoft\UserSecrets'),
    (Join-Path $ProfilePath 'AppData\Local\.IdentityService'),
    (Join-Path $ProfilePath '.claude\.credentials.json'),
    (Join-Path $RepoPath 'infra\terraform\environments\dev-onprem\set-proxmox-env.ps1')
)

function Test-StoreExposure {
    param([string]$Path)
    $findings = New-Object System.Collections.ArrayList
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction SilentlyContinue
    if (-not $item) { return [pscustomobject]@{ Present = $false; Status = 'ABSENT'; Findings = @(); Protected = $null; OwnerSid = $null } }

    $targets = New-Object System.Collections.ArrayList
    [void]$targets.Add($Path)

    # Ancestors, climbing only while inheritance is unbroken. Without the protection check the
    # default C:\Users inherit-only ACE fails every profile store; with it, the walk still finds
    # an ACE placed on the profile root itself, which is exactly where the incident's was.
    $cur = $Path
    while ($true) {
        $curAcl = Get-Acl -LiteralPath $cur -ErrorAction SilentlyContinue
        # If this object's rules are protected, inheritance is severed here and no ancestor
        # grants anything on it. That check is what stops the default C:\Users inherit-only ACE
        # failing every profile store; without it the check cries wolf and gets muted.
        if (-not $curAcl -or $curAcl.AreAccessRulesProtected) { break }
        $parent = Split-Path -Parent $cur
        if (-not $parent -or $parent -eq $cur -or -not (Test-Path -LiteralPath $parent)) { break }
        [void]$targets.Add($parent)
        $cur = $parent
    }

    # Descendants that break inheritance or carry a non-inherited ACE. Purely-inherited children
    # are covered by the parent's verdict; inheritance can be broken at any child, so they cannot
    # simply be skipped. Junctions are not traversed (loops, and the real ACL is at the target).
    if ($item.PSIsContainer) {
        $kids = Get-ChildItem -LiteralPath $Path -Recurse -Force -Depth 2 -ErrorAction SilentlyContinue |
                Where-Object { -not ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) }
        foreach ($k in $kids) {
            $script:counters.ObjectsWalked++
            $kacl = Get-Acl -LiteralPath $k.FullName -ErrorAction SilentlyContinue
            if (-not $kacl) { continue }
            if ($kacl.AreAccessRulesProtected -or ($kacl.Access | Where-Object { -not $_.IsInherited })) {
                [void]$targets.Add($k.FullName)
            }
        }
    }

    foreach ($t in ($targets | Select-Object -Unique)) {
        $acl = Get-Acl -LiteralPath $t -ErrorAction SilentlyContinue
        if (-not $acl) { continue }
        $script:counters.DaclsEvaluated++
        $res = Test-AclExposure -Sddl $acl.Sddl -OwnerSid $acl.GetOwner([System.Security.Principal.SecurityIdentifier]).Value `
                                -MachineSid $machineSid -Path $t -AlsoAccepted $script:profileOwnerSid
        foreach ($f in $res.Findings) { [void]$findings.Add($f) }
    }

    $rootAcl = Get-Acl -LiteralPath $Path
    return [pscustomobject]@{
        Present   = $true
        Status    = if ($findings.Count) { 'VIOLATION' } else { 'CLEAN' }
        Findings  = @($findings)
        Protected = $rootAcl.AreAccessRulesProtected
        OwnerSid  = $rootAcl.GetOwner([System.Security.Principal.SecurityIdentifier]).Value
    }
}

$stores = New-Object System.Collections.ArrayList
foreach ($p in $storePaths) {
    $r = Test-StoreExposure -Path $p
    [void]$stores.Add([pscustomobject]@{ Path = $p; Present = $r.Present; Status = $r.Status
                                         Protected = $r.Protected; OwnerSid = $r.OwnerSid; Findings = $r.Findings })
    if ($r.Status -eq 'VIOLATION') { [void]$violations.Add("credential store reachable: $p") }
}

# ---- CI agents -------------------------------------------------------------------------------
$services = @(Get-CimInstance Win32_Service -ErrorAction SilentlyContinue)
$counters.ServicesEnumerated = $services.Count
$groups = @(Get-LocalGroup -ErrorAction SilentlyContinue)
$counters.GroupsEnumerated = $groups.Count

$agents = New-Object System.Collections.ArrayList

# Vendor service-name patterns, plus the vendor-independent signal: a service whose image sits
# outside the standard program directories.
$vendorSvc = '^(actions\.runner\.|vstsagent\.|gitlab-runner|jenkins|TCBuildAgent|buildkite-agent|OctopusDeploy|codedeployagent)'
foreach ($s in $services) {
    $img = if ($s.PathName) { ($s.PathName -replace '^"([^"]+)".*$', '$1') -replace '^([^\s]+)\s.*$', '$1' } else { '' }
    $foreign = $img -and ($img -notmatch '^[A-Za-z]:\\Windows\\') -and ($img -notmatch '^[A-Za-z]:\\Program Files') `
               -and ($img -notmatch 'Windows Defender')
    # The generic "foreign image path" signal is deliberately NOT enough on its own. Six innocent
    # services here match /agent/ (spice-agent, ssh-agent, QEMU guest agent, nvagent...), and a
    # check that cries wolf six times gets muted, then ignored. A vendor service name stands
    # alone; a foreign image path must be corroborated by CI registration markers on disk.
    $vendorMatch = $s.Name -match $vendorSvc
    if (-not $vendorMatch -and -not $foreign) { continue }

    $root = if ($img) { Split-Path -Parent (Split-Path -Parent $img) } else { $null }
    # Marker files are Hidden: Get-ChildItem -Filter '.runner' returns nothing without -Force,
    # and that single mistake flips a live, running runner to a clean result. Test-Path sees them.
    $markers = @()
    if ($root -and (Test-Path $root)) {
        $markers = @(@('.runner','.credentials','.agent','.service','config.toml','buildAgent.properties') |
                     Where-Object { Test-Path (Join-Path $root $_) })
    }
    if (-not $vendorMatch -and -not $markers.Count) { continue }   # foreign path alone is not evidence

    $state = Get-CiAgentState -ServiceRunning ($s.State -eq 'Running') -ProcessRunning $false `
                              -MarkersPresent ([bool]$markers.Count) -BinariesPresent ([bool]$root)
    if ($state -eq 'CLEAN') { continue }

    [void]$agents.Add([pscustomobject]@{
        State = $state; Name = $s.Name; InstallRoot = $root; ImagePath = $img
        ServiceAccount = $s.StartName; ServiceState = $s.State; Markers = $markers; DetectedBy = 'service' })
    [void]$violations.Add("CI agent $state`: $($s.Name)")
}

# Install roots with no service: residue still carries re-arm assets and, as found here, stale ACEs.
foreach ($dir in @(Get-ChildItem 'C:\' -Directory -Force -ErrorAction SilentlyContinue |
                   Where-Object { $_.Name -match 'runner|agent|buildkite|jenkins|octopus' })) {
    if ($agents | Where-Object { $_.InstallRoot -and $_.InstallRoot -like "$($dir.FullName)*" }) { continue }
    $markers = @(@('.runner','.credentials','.agent','config.toml') | Where-Object { Test-Path (Join-Path $dir.FullName $_) })
    $bins = [bool](Get-ChildItem $dir.FullName -Filter '*.exe' -Recurse -Force -Depth 2 -ErrorAction SilentlyContinue | Select-Object -First 1)
    $state = Get-CiAgentState -ServiceRunning $false -ProcessRunning $false -MarkersPresent ([bool]$markers.Count) -BinariesPresent $bins
    if ($state -ne 'CLEAN') {
        [void]$agents.Add([pscustomobject]@{
            State = $state; Name = $dir.Name; InstallRoot = $dir.FullName; ImagePath = $null
            ServiceAccount = $null; ServiceState = $null; Markers = $markers; DetectedBy = 'install root' })
        [void]$violations.Add("CI agent $state`: $($dir.FullName)")
    }
}

# Orphaned SIDs: an ACE whose trustee no longer resolves. A future principal issued the same RID
# inherits the access. This is agent-removal residue by construction.
$orphans = New-Object System.Collections.ArrayList
foreach ($p in @('C:\actions-runner', 'C:\actions-runner-other', $ProfilePath)) {
    if (-not (Test-Path $p)) { continue }
    $acl = Get-Acl -LiteralPath $p -ErrorAction SilentlyContinue
    if (-not $acl) { continue }
    $sd = New-Object System.Security.AccessControl.RawSecurityDescriptor($acl.Sddl)
    if ($null -eq $sd.DiscretionaryAcl) { continue }
    foreach ($ace in $sd.DiscretionaryAcl) {
        $sid = $ace.SecurityIdentifier.Value
        if ($sid -notlike "S-1-5-21-$machineSid-*") { continue }
        if (Resolve-SidName -Sid $sid) { continue }
        $mask = ConvertTo-UInt32Mask -Mask $ace.AccessMask
        [void]$orphans.Add([pscustomobject]@{ Sid = $sid; Path = $p; Mask = ('0x{0:X8}' -f $mask)
                                              ReadEquivalent = (Test-ReadEquivalent -Mask $mask) })
        if (Test-ReadEquivalent -Mask $mask) { [void]$violations.Add("orphaned SID with read access: $sid on $p") }
    }
}

# Installer-created groups: the mechanism B10 records.
$installerGroups = New-Object System.Collections.ArrayList
foreach ($g in $groups) {
    $members = @(Invoke-Quietly { Get-LocalGroupMember -SID $g.SID.Value -ErrorAction Stop })
    $svcOnly = $members.Count -gt 0 -and -not (@($members | Where-Object { $_.SID.Value -notin @('S-1-5-19','S-1-5-20') }).Count)
    if (($g.Name -match '^(GITHUB_ActionsRunner|VSTS_AgentService)_') -or $svcOnly) {
        [void]$installerGroups.Add([pscustomobject]@{ Name = $g.Name; Sid = $g.SID.Value
                                                      Members = @($members | ForEach-Object { $_.Name }) })
    }
}

# ---- host principals --------------------------------------------------------------------------
$admins = @(Invoke-Quietly { Get-LocalGroupMember -SID 'S-1-5-32-544' -ErrorAction Stop } | ForEach-Object { $_.Name })
$backupOps = @(Invoke-Quietly { Get-LocalGroupMember -SID 'S-1-5-32-551' -ErrorAction Stop } | ForEach-Object { $_.Name })
if ($backupOps.Count) { [void]$violations.Add("Backup Operators is not empty: SeBackupPrivilege bypasses every DACL") }

# ---- declared gaps ------------------------------------------------------------------------------
# A Linux CI agent inside WSL can read /mnt/c/Users/<profile>/.ssh and .azure directly and matches
# no Windows signature. Enumerating a stopped distro would start it, which is a host state change
# this probe is not permitted to make, so it is declared rather than silently ignored.
$lxss = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Lxss'
if (Test-Path $lxss) {
    foreach ($d in (Get-ChildItem $lxss -ErrorAction SilentlyContinue)) {
        $n = (Get-ItemProperty $d.PSPath -ErrorAction SilentlyContinue).DistributionName
        if ($n) { Add-Gap 'wsl' $n 'distro not enumerated; a Linux CI agent inside it is invisible to Windows signatures' }
    }
}
if (Get-Command docker -ErrorAction SilentlyContinue) {
    $ps = Invoke-Quietly { & docker ps -a --format '{{.Image}}' }
    if (-not $ps) { Add-Gap 'container' 'docker' 'engine not responding; an agent container with restart:always becomes operational when it starts' }
}

# ---- self-test -----------------------------------------------------------------------------------
$selfTest = if ($SkipSelfTest) { [pscustomobject]@{ Result = 'Skipped'; Legs = @(); FailedCount = 0 } }
            else { & (Join-Path $PSScriptRoot 'Test-AdminHostProbeSelfTest.ps1') }

# ---- enumeration integrity ------------------------------------------------------------------------
# Fail closed: a COMPLIANT verdict with zero DACLs evaluated is the failure this check exists to
# prevent. Silence must never render as clean.
if ($counters.ServicesEnumerated -lt 50) { Add-Gap 'enumeration' 'services' "only $($counters.ServicesEnumerated) services enumerated" }
if ($counters.GroupsEnumerated -lt 5)    { Add-Gap 'enumeration' 'groups'   "only $($counters.GroupsEnumerated) groups enumerated" }
if ($counters.DaclsEvaluated -lt 1)      { Add-Gap 'enumeration' 'dacls'    'no DACL was evaluated' }

# ---- verdict --------------------------------------------------------------------------------------
$verdict = if ($selfTest.Result -eq 'Failed') { 'SELF-TEST-FAILED' }
           elseif ($violations.Count)          { 'VIOLATION' }
           elseif ($gaps.Count)                { 'INCONCLUSIVE' }
           elseif ($evidenceScore -eq 0)       { 'NOT-AN-ADMINISTRATION-HOST' }
           else                                { 'COMPLIANT' }
$exit = switch ($verdict) { 'SELF-TEST-FAILED' {4} 'VIOLATION' {1} 'INCONCLUSIVE' {2} 'NOT-AN-ADMINISTRATION-HOST' {3} default {0} }

$report = [pscustomobject]@{
    Verdict        = $verdict
    TrustLevel     = if ($selfTest.Result -eq 'Passed') { 'trusted' } else { 'untrusted' }
    Host           = [pscustomobject]@{ ComputerName = $env:COMPUTERNAME; ProfilePath = $ProfilePath; MachineSid = $machineSid }
    AdminHostEvidence = [pscustomobject]$evidence
    EvidenceScore  = $evidenceScore
    Stores         = @($stores)
    CiAgents       = @($agents)
    OrphanedSids   = @($orphans)
    InstallerGroups= @($installerGroups)
    Administrators = $admins
    BackupOperators= $backupOps
    Gaps           = @($gaps)
    Counters       = [pscustomobject]$counters
    SelfTest       = [pscustomobject]@{ Result = $selfTest.Result; FailedCount = $selfTest.FailedCount }
    Violations     = @($violations)
    ExitCode       = $exit
}

if ($ReportPath) {
    $dir = Split-Path -Parent $ReportPath
    if ($dir -and -not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir | Out-Null }
    $report | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $ReportPath -Encoding UTF8
}

return $report
