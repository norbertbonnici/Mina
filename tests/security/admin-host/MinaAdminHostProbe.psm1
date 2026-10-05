<#
    Predicates for the D-21 administration-host probe (THREAT_MODEL B10, backlog M4-30).

    These live in a module so the probe and every self-test leg call the SAME functions. A
    self-test that exercises a reimplementation proves nothing about the thing that runs.

    The design rule throughout: an assertion that cannot fail is not an assertion. Every
    predicate here either returns a finding or explicitly records why it could not decide —
    it never returns "clean" because it was unable to look.
#>

Set-StrictMode -Version Latest

# Read-equivalent access bits. WRITE_DAC and WRITE_OWNER are included because each is read in
# one further step: rewrite the DACL, then read. FILE_READ_ATTRIBUTES (0x80) and traverse
# (0x20) are deliberately excluded -- that exclusion, and nothing else, is what lets the AppX
# capability ACE present on this profile root pass without a name-based exemption.
$script:READ_EQUIVALENT =
    0x1        -bor `  # FILE_READ_DATA
    0x8        -bor `  # FILE_READ_EA
    0x20000    -bor `  # READ_CONTROL
    0x40000    -bor `  # WRITE_DAC
    0x80000    -bor `  # WRITE_OWNER
    0x2000000          # MAXIMUM_ALLOWED
# GENERIC_READ / GENERIC_ALL added separately: 0x80000000 is a negative Int32 in PS 5.1.
$script:GENERIC_READ = [uint32]'0x80000000'
$script:GENERIC_ALL  = [uint32]'0x10000000'

# Principals whose access is accepted, and why accepting them is honest rather than lax:
# SYSTEM already owns the machine; Administrators holds SeTakeOwnership/SeBackup/SeDebug so it
# can read any file whatever the DACL says, making a denial unenforceable; the owner implicitly
# holds READ_CONTROL|WRITE_DAC and can re-grant itself read at will. The price of each is a
# separate assertion: Administrators membership, and the owner check.
$script:ACCEPTED_SIDS = @('S-1-5-18', 'S-1-5-32-544')

# Principals whose membership is decided at logon rather than stored, so the recursion can never
# close. Treated as leaves that FAIL if they hold read -- never expanded.
$script:UNBOUNDED_SIDS = @(
    'S-1-1-0',       # Everyone
    'S-1-5-11',      # Authenticated Users
    'S-1-5-2',       # NETWORK
    'S-1-5-3',       # BATCH
    'S-1-5-4',       # INTERACTIVE
    'S-1-5-6',       # SERVICE
    'S-1-5-7',       # ANONYMOUS
    'S-1-5-19',      # LOCAL SERVICE
    'S-1-5-20',      # NETWORK SERVICE
    'S-1-5-113',     # Local account
    'S-1-5-114',     # Local account and member of Administrators group
    'S-1-5-32-545',  # BUILTIN\Users
    'S-1-5-32-546',  # Guests
    'S-1-5-32-547',  # Power Users
    'S-1-5-32-551',  # Backup Operators
    'S-1-5-32-555',  # Remote Desktop Users
    'S-1-5-32-568',  # IIS_IUSRS
    'S-1-5-32-580'   # Remote Management Users
)

function Invoke-Quietly {
    <#
    .SYNOPSIS
        Runs a block with native stderr demoted and $LASTEXITCODE preserved.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)] [scriptblock] $Block)

    $prev     = $ErrorActionPreference
    $hadExit  = Test-Path -Path 'variable:global:LASTEXITCODE'
    $prevExit = if ($hadExit) { $global:LASTEXITCODE } else { $null }
    $ErrorActionPreference = 'Continue'
    try { & $Block 2>$null } catch { }
    finally {
        $ErrorActionPreference = $prev
        if ($hadExit) { $global:LASTEXITCODE = $prevExit }
    }
}

function ConvertTo-UInt32Mask {
    <#
    .SYNOPSIS
        Access masks as unsigned. GENERIC_READ (0x80000000) is a negative Int32 and a direct
        [uint32] cast throws in PowerShell 5.1.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)] [int] $Mask)
    return [BitConverter]::ToUInt32([BitConverter]::GetBytes($Mask), 0)
}

function Test-ReadEquivalent {
    [CmdletBinding()]
    param([Parameter(Mandatory)] [uint32] $Mask)
    $bits = ([uint32]$script:READ_EQUIVALENT) -bor $script:GENERIC_READ -bor $script:GENERIC_ALL
    return (($Mask -band $bits) -ne 0)
}

function Resolve-SidName {
    [CmdletBinding()]
    param([Parameter(Mandatory)] [string] $Sid)
    try { return (New-Object System.Security.Principal.SecurityIdentifier($Sid)).Translate([System.Security.Principal.NTAccount]).Value }
    catch { return $null }
}

function Expand-PrincipalSid {
    <#
    .SYNOPSIS
        Closes a trustee SID to the set of leaf principals that actually obtain its access.
    .DESCRIPTION
        This is the function whose absence caused the incident. The dangerous ACE named a local
        GROUP (GITHUB_ActionsRunner_*) whose member was NETWORK SERVICE; a check comparing ACL
        identity strings sees an unfamiliar name, has no rule for it, and reports clean.

        Rules that are not negotiable:
          - Never expand an ACCEPTED principal. Administrators contains Domain Admins, and
            expanding it manufactures "closure incomplete" on every clean path -- after which
            the natural fix is to suppress the error, which suppresses the real ones too.
          - Never expand an UNBOUNDED principal; it is a leaf that fails if it holds read.
          - ANY incomplete closure is a failure, never a skip. Not enumerable, orphaned member,
            enumerator disagreement -- all fail. The incident's group is precisely the thing you
            must be able to close, so "could not close" must never read as "nothing there".
    .OUTPUTS
        [pscustomobject] Leaves (string[]), Complete (bool), Reason (string|null)
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $Sid,
        [hashtable] $Seen = $null,
        [string] $MachineSid = $null
    )

    if ($null -eq $Seen) { $Seen = @{} }

    if ($script:ACCEPTED_SIDS -contains $Sid) {
        return [pscustomobject]@{ Leaves = @($Sid); Complete = $true; Reason = $null }
    }
    if ($script:UNBOUNDED_SIDS -contains $Sid) {
        return [pscustomobject]@{ Leaves = @($Sid); Complete = $true; Reason = 'unbounded well-known principal' }
    }
    if ($Seen.ContainsKey($Sid)) {
        return [pscustomobject]@{ Leaves = @(); Complete = $true; Reason = 'cycle' }
    }
    $Seen[$Sid] = $true

    $name = Resolve-SidName -Sid $Sid
    if (-not $name) {
        # Orphaned SID: the account or group is gone but its ACE remains. A future principal
        # issued the same RID inherits this access.
        return [pscustomobject]@{ Leaves = @($Sid); Complete = $false; Reason = 'unresolvable SID (orphaned ACE)' }
    }

    # A USER is already a leaf and needs no closure. Only groups can hide a principal behind
    # them, and conflating the two makes every domain user an "incomplete closure" — which
    # floods the report with the account that legitimately owns the credentials, and a report
    # that is mostly noise gets muted, taking the real findings with it.
    $acct = Invoke-Quietly { Get-CimInstance Win32_Account -Filter "SID='$Sid'" -ErrorAction Stop }
    if ($acct -and $acct.PSObject.Properties['SIDType'] -and $acct.SIDType -eq 1) {
        return [pscustomobject]@{ Leaves = @($Sid); Complete = $true; Reason = $null }   # SidTypeUser
    }

    $isLocalGroup = ($Sid -like 'S-1-5-32-*') -or ($MachineSid -and $Sid -like "S-1-5-21-$MachineSid-*")
    if (-not $isLocalGroup) {
        # A domain GROUP genuinely cannot be closed without AD, and that is a real limitation
        # rather than a nuisance: we cannot prove it does not contain a foreign principal.
        return [pscustomobject]@{ Leaves = @($Sid); Complete = $false; Reason = 'domain group - cannot close without AD' }
    }

    $members = $null
    try { $members = @(Get-LocalGroupMember -SID $Sid -ErrorAction Stop) }
    catch {
        # Get-LocalGroupMember throws on groups holding orphaned member SIDs, and cannot take
        # some well-known SIDs. Catching and continuing here would turn the group into an empty
        # set and PASS the exact incident, so this is a hard incomplete instead.
        return [pscustomobject]@{ Leaves = @($Sid); Complete = $false; Reason = "membership not enumerable: $($_.Exception.GetType().Name)" }
    }

    $leaves = New-Object System.Collections.ArrayList
    $complete = $true
    $reasons = New-Object System.Collections.ArrayList
    foreach ($m in $members) {
        $msid = $null
        try { $msid = $m.SID.Value } catch { }
        if (-not $msid) {
            $complete = $false
            [void]$reasons.Add('member without resolvable SID')
            continue
        }
        $sub = Expand-PrincipalSid -Sid $msid -Seen $Seen -MachineSid $MachineSid
        foreach ($l in $sub.Leaves) { if (-not $leaves.Contains($l)) { [void]$leaves.Add($l) } }
        if (-not $sub.Complete) { $complete = $false; if ($sub.Reason) { [void]$reasons.Add($sub.Reason) } }
    }

    return [pscustomobject]@{
        Leaves   = @($leaves)
        Complete = $complete
        Reason   = if ($reasons.Count) { ($reasons | Select-Object -Unique) -join '; ' } else { $null }
    }
}

function Test-AclExposure {
    <#
    .SYNOPSIS
        Decides whether any principal outside the accepted set obtains read-equivalent access,
        given a security descriptor in SDDL form.
    .DESCRIPTION
        Takes SDDL rather than a path so the self-test can exercise the real evaluator against
        literal descriptors with no filesystem at all.

        Evaluation mirrors the kernel: ACEs in STORED order, deny-aware, per candidate leaf.
        "Is there an Allow ACE?" is wrong in both directions -- it fails a safe canonical
        (D;;FA)(A;;FA) and, far worse, passes an unsafe non-canonical (A;;FA)(D;;FA).
    .OUTPUTS
        [pscustomobject] Status (CLEAN|VIOLATION), Findings[], NullDacl (bool)
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $Sddl,
        [string] $OwnerSid = $null,
        [string] $MachineSid = $null,
        [string] $Path = '(sddl)',
        # The identity the host belongs to. Accepted everywhere, because these credentials are
        # its own — the question D-21 asks is who ELSE can reach them. Objects inside a profile
        # are not all owned by the profile's user (anything created elevated is owned by
        # Administrators), so per-object owner alone flags the legitimate user on its own data.
        [string[]] $AlsoAccepted = @()
    )

    $sd = New-Object System.Security.AccessControl.RawSecurityDescriptor($Sddl)
    $findings = New-Object System.Collections.ArrayList

    # A null DACL grants everyone everything. Get-Acl's .Access collection is EMPTY here, so any
    # loop that only inspects ACEs reports clean on the most open object possible.
    if ($null -eq $sd.DiscretionaryAcl) {
        [void]$findings.Add([pscustomobject]@{
            Path = $Path; AceTrustee = '(null DACL)'; ReachingPrincipal = 'Everyone'
            EffectiveMask = '0xFFFFFFFF'; Via = 'null DACL - unrestricted access'; ClosureComplete = $true
        })
        return [pscustomobject]@{ Status = 'VIOLATION'; Findings = @($findings); NullDacl = $true }
    }

    $owner = $OwnerSid
    if (-not $owner -and $sd.Owner) { $owner = $sd.Owner.Value }
    $accepted = @($script:ACCEPTED_SIDS)
    if ($owner) { $accepted += $owner }
    foreach ($a in $AlsoAccepted) { if ($a) { $accepted += $a } }

    # Rights first, principal second: only trustees whose mask actually intersects read get their
    # membership closed. Closing every trustee false-positives on benign unresolvable SIDs and
    # then invites an exemption list that will eventually exempt something real.
    # AceFlags is a byte-backed enum: -band against it throws "Specified cast is not valid" in
    # PowerShell 5.1 unless both sides are cast to int first. Left uncast, the inherit-only guard
    # below silently never runs and inherit-only ACEs are scored as if they granted access.
    $INHERIT_ONLY = [int][System.Security.AccessControl.AceFlags]::InheritOnly

    $candidates = @{}
    foreach ($ace in $sd.DiscretionaryAcl) {
        if ($ace.AceType -ne 'AccessAllowed') { continue }
        if (([int]$ace.AceFlags -band $INHERIT_ONLY) -ne 0) { continue }
        $mask = ConvertTo-UInt32Mask -Mask $ace.AccessMask
        if (-not (Test-ReadEquivalent -Mask $mask)) { continue }
        $t = $ace.SecurityIdentifier.Value
        # OWNER RIGHTS / CREATOR OWNER are not principals; substitute the owner before closure.
        if ($t -eq 'S-1-3-4' -or $t -eq 'S-1-3-0') { if ($owner) { $t = $owner } else { continue } }
        $candidates[$t] = $true
    }

    foreach ($trustee in $candidates.Keys) {
        if ($accepted -contains $trustee) { continue }

        $closure = Expand-PrincipalSid -Sid $trustee -MachineSid $MachineSid
        foreach ($leaf in $closure.Leaves) {
            if ($accepted -contains $leaf) { continue }

            # Ordered, deny-aware effective-rights computation for this leaf.
            $allowed = [uint32]0; $denied = [uint32]0
            foreach ($ace in $sd.DiscretionaryAcl) {
                if (([int]$ace.AceFlags -band $INHERIT_ONLY) -ne 0) { continue }
                $aceSid = $ace.SecurityIdentifier.Value
                if ($aceSid -eq 'S-1-3-4' -or $aceSid -eq 'S-1-3-0') { if ($owner) { $aceSid = $owner } }
                $applies = ($aceSid -eq $leaf) -or ($aceSid -eq $trustee)
                if (-not $applies) { continue }
                $m = ConvertTo-UInt32Mask -Mask $ace.AccessMask
                if ($ace.AceType -eq 'AccessDenied') { $denied = $denied -bor ($m -band (-bnot $allowed)) }
                else { $allowed = $allowed -bor ($m -band (-bnot $denied)) }
            }
            $effective = $allowed -band (-bnot $denied)
            if (Test-ReadEquivalent -Mask $effective) {
                [void]$findings.Add([pscustomobject]@{
                    Path = $Path
                    AceTrustee = "$trustee$(if ($n = Resolve-SidName $trustee) { " ($n)" })"
                    ReachingPrincipal = "$leaf$(if ($ln = Resolve-SidName $leaf) { " ($ln)" })"
                    EffectiveMask = ('0x{0:X8}' -f $effective)
                    Via = if ($leaf -eq $trustee) { 'direct ACE' } else { 'group membership' }
                    ClosureComplete = $closure.Complete
                })
            }
        }

        # An incomplete closure is a failure in its own right: we cannot prove the trustee does
        # not reach a foreign principal, and the incident's group is exactly this shape.
        if (-not $closure.Complete) {
            [void]$findings.Add([pscustomobject]@{
                Path = $Path
                AceTrustee = "$trustee$(if ($n2 = Resolve-SidName $trustee) { " ($n2)" })"
                ReachingPrincipal = '(unknown - closure incomplete)'
                EffectiveMask = '(not computed)'
                Via = "closure incomplete: $($closure.Reason)"
                ClosureComplete = $false
            })
        }
    }

    return [pscustomobject]@{
        Status   = if ($findings.Count) { 'VIOLATION' } else { 'CLEAN' }
        Findings = @($findings)
        NullDacl = $false
    }
}

function Get-CiAgentState {
    <#
    .SYNOPSIS
        Pure predicate: inventory record -> state. Kept free of collection so the self-test can
        drive it with synthetic records and prove the state model is implemented, not asserted.
    .DESCRIPTION
        M4-30 says "assert no CI agent is installed", and installed is not the same as running.
        A stopped agent still holds credentials on disk that authorise this host to a foreign
        control plane; one `sc start` restores it. Residue still carries re-arm assets and, as
        found here, stale ACEs.
    .OUTPUTS
        'OPERATIONAL' | 'REGISTERED-STOPPED' | 'RESIDUE' | 'CLEAN'
    #>
    [CmdletBinding()]
    param(
        [bool] $ServiceRunning = $false,
        [bool] $ProcessRunning = $false,
        [bool] $MarkersPresent = $false,
        [bool] $BinariesPresent = $false
    )

    if (($ServiceRunning -or $ProcessRunning) -and $MarkersPresent) { return 'OPERATIONAL' }
    if ($ServiceRunning -or $ProcessRunning) { return 'OPERATIONAL' }
    if ($MarkersPresent) { return 'REGISTERED-STOPPED' }
    if ($BinariesPresent) { return 'RESIDUE' }
    return 'CLEAN'
}

Export-ModuleMember -Function Invoke-Quietly, ConvertTo-UInt32Mask, Test-ReadEquivalent,
                              Resolve-SidName, Expand-PrincipalSid, Test-AclExposure, Get-CiAgentState
