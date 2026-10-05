<#
.SYNOPSIS
    Backs up the Mina control-plane database on the on-premises SQL Server host (RUNBOOKS.md 7).
.DESCRIPTION
    Runs ON the SQL host, as a scheduled task under a Windows identity holding db_backupoperator
    (or sysadmin) on the instance -- the instance is Windows-authentication-only (M4-18), so there
    is no SQL login to configure and nothing here stores a credential. Two schedules are expected:
    -Type Full nightly and -Type Log every 15 minutes (the recovery point objective; see
    OPERATIONS.md SLOs). Every backup is taken WITH CHECKSUM and COMPRESSION, then RESTORE
    VERIFYONLY'd before it counts, and one JSON line per backup is appended to a manifest the
    restore script reads. Files older than -RetainDays are pruned after a successful backup, never
    before. The backup directory is the organisation's to place on storage with its own off-host copy; this
    script does not copy anything off the host.
.PARAMETER Type
    Full, Diff or Log. Log requires the database to be in FULL recovery; the script refuses otherwise
    rather than silently taking a full backup under a Log schedule.
.PARAMETER BackupRoot
    Directory the backups and manifest.jsonl live in. Created if missing.
.PARAMETER Database
    Database name. Default Mina (what the deploy scripts' connection strings name).
.PARAMETER ServerInstance
    Instance to connect to. Default "." (local default instance).
.PARAMETER RetainDays
    Delete backup files older than this many days after a successful run. Default 35, which keeps
    one monthly restore drill's worth of history plus margin.
.EXAMPLE
    .\sql-backup-onprem.ps1 -Type Full -BackupRoot D:\MinaBackup
.EXAMPLE
    .\sql-backup-onprem.ps1 -Type Log -BackupRoot D:\MinaBackup
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidateSet('Full', 'Diff', 'Log')][string]$Type,
    [Parameter(Mandatory)][string]$BackupRoot,
    [ValidatePattern('^[A-Za-z0-9_]+$')][string]$Database = 'Mina',
    [string]$ServerInstance = '.',
    [ValidateRange(1, 3650)][int]$RetainDays = 35
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Invoke-Sql {
    param([Parameter(Mandatory)][string]$Sql, [switch]$Scalar)
    $connection = New-Object System.Data.SqlClient.SqlConnection(
        "Server=$ServerInstance;Database=master;Integrated Security=True;Encrypt=True;TrustServerCertificate=True")
    $connection.Open()
    try {
        $command = $connection.CreateCommand()
        $command.CommandText = $Sql
        $command.CommandTimeout = 0  # a backup runs as long as it runs
        if ($Scalar) { return $command.ExecuteScalar() }
        [void]$command.ExecuteNonQuery()
    }
    finally { $connection.Dispose() }
}

New-Item -ItemType Directory -Force -Path $BackupRoot | Out-Null
$manifest = Join-Path $BackupRoot 'manifest.jsonl'

$recovery = Invoke-Sql -Scalar -Sql "SELECT recovery_model_desc FROM sys.databases WHERE name = N'$Database'"
if (-not $recovery) { throw "Database '$Database' does not exist on $ServerInstance." }
if ($Type -eq 'Log' -and $recovery -ne 'FULL') {
    throw "Database '$Database' is in $recovery recovery; log backups need FULL. Set it (ALTER DATABASE ... SET RECOVERY FULL) and take a full backup first."
}

$stamp = (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ')
$extension = @{ Full = 'bak'; Diff = 'dif'; Log = 'trn' }[$Type]
$file = Join-Path $BackupRoot "$Database-$Type-$stamp.$extension"

$statement = switch ($Type) {
    'Full' { "BACKUP DATABASE [$Database] TO DISK = N'$file' WITH CHECKSUM, COMPRESSION, INIT, NAME = N'$Database full $stamp'" }
    'Diff' { "BACKUP DATABASE [$Database] TO DISK = N'$file' WITH DIFFERENTIAL, CHECKSUM, COMPRESSION, INIT, NAME = N'$Database diff $stamp'" }
    'Log'  { "BACKUP LOG [$Database] TO DISK = N'$file' WITH CHECKSUM, COMPRESSION, INIT, NAME = N'$Database log $stamp'" }
}

Write-Host "==> $Type backup of [$Database] to $file"
Invoke-Sql -Sql $statement

Write-Host "==> RESTORE VERIFYONLY"
Invoke-Sql -Sql "RESTORE VERIFYONLY FROM DISK = N'$file' WITH CHECKSUM"

# What the chain looked like at backup time, so a restore can be compared against the anchors
# (RUNBOOKS.md 7 step 3) without opening the file.
$maxSequence = Invoke-Sql -Scalar -Sql "SELECT ISNULL(MAX([Sequence]), 0) FROM [$Database].dbo.AuditEvents"
$auditRows = Invoke-Sql -Scalar -Sql "SELECT COUNT_BIG(*) FROM [$Database].dbo.AuditEvents"

$entry = [ordered]@{
    takenAtUtc       = $stamp
    type             = $Type
    database         = $Database
    file             = $file
    sizeBytes        = (Get-Item $file).Length
    auditMaxSequence = [long]$maxSequence
    auditRows        = [long]$auditRows
    verified         = $true
}
($entry | ConvertTo-Json -Compress) | Add-Content -Path $manifest -Encoding utf8
Write-Host "==> Recorded in $manifest (AuditEvents rows=$auditRows, max sequence=$maxSequence)"

$cutoff = (Get-Date).AddDays(-$RetainDays)
Get-ChildItem -Path $BackupRoot -File | Where-Object { $_.Extension -in '.bak', '.dif', '.trn' -and $_.LastWriteTime -lt $cutoff } |
    ForEach-Object { Write-Host "==> Pruning $($_.Name)"; Remove-Item $_.FullName -Force }
