<#
.SYNOPSIS
    Restores the Mina control-plane database from the backups sql-backup-onprem.ps1 wrote, as a
    drill by default and as the real thing with -Replace (RUNBOOKS.md 7).
.DESCRIPTION
    Runs ON the SQL host under a Windows identity holding dbcreator/sysadmin. Reads the manifest,
    picks the latest full backup, then every differential and log backup taken after it in order,
    and restores the chain WITH CHECKSUM into -TargetDatabase (default Mina_RestoreDrill, data files
    relocated so the drill never touches production's files). Runs DBCC CHECKDB, prints the row
    count and maximum Sequence of AuditEvents -- the figure RUNBOOKS.md 7 says to compare with the
    anchors in immutable storage -- and drops the drill database unless -Keep.

    With -Replace and -TargetDatabase Mina this is the production restore. It refuses to run unless
    the application is stopped: a connection from the app host's identity means the API is still
    writing, and restoring under it would fork the chain.
.PARAMETER BackupRoot
    Directory holding the backups and manifest.jsonl.
.PARAMETER SourceDatabase
    Database name as it appears in the manifest. Default Mina.
.PARAMETER TargetDatabase
    Name to restore into. Default Mina_RestoreDrill.
.PARAMETER Replace
    Allow restoring over an existing database (WITH REPLACE). Required for a production restore.
.PARAMETER Keep
    Leave the restored drill database in place for inspection instead of dropping it.
.PARAMETER ServerInstance
    Instance to connect to. Default ".".
.EXAMPLE
    .\sql-restore-drill-onprem.ps1 -BackupRoot D:\MinaBackup
.EXAMPLE
    .\sql-restore-drill-onprem.ps1 -BackupRoot D:\MinaBackup -TargetDatabase Mina -Replace
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$BackupRoot,
    [ValidatePattern('^[A-Za-z0-9_]+$')][string]$SourceDatabase = 'Mina',
    [ValidatePattern('^[A-Za-z0-9_]+$')][string]$TargetDatabase = 'Mina_RestoreDrill',
    [switch]$Replace,
    [switch]$Keep,
    [string]$ServerInstance = '.'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Invoke-Sql {
    param([Parameter(Mandatory)][string]$Sql, [switch]$Scalar, [switch]$Table)
    $connection = New-Object System.Data.SqlClient.SqlConnection(
        "Server=$ServerInstance;Database=master;Integrated Security=True;Encrypt=True;TrustServerCertificate=True")
    $connection.Open()
    try {
        $command = $connection.CreateCommand()
        $command.CommandText = $Sql
        $command.CommandTimeout = 0
        if ($Scalar) { return $command.ExecuteScalar() }
        if ($Table) {
            $data = New-Object System.Data.DataTable
            (New-Object System.Data.SqlClient.SqlDataAdapter($command)).Fill($data) | Out-Null
            return $data
        }
        [void]$command.ExecuteNonQuery()
    }
    finally { $connection.Dispose() }
}

$manifestPath = Join-Path $BackupRoot 'manifest.jsonl'
if (-not (Test-Path $manifestPath)) { throw "No manifest at $manifestPath." }
$entries = Get-Content $manifestPath | Where-Object { $_.Trim() } | ForEach-Object { $_ | ConvertFrom-Json } |
    Where-Object { $_.database -eq $SourceDatabase -and $_.verified } | Sort-Object takenAtUtc

$full = $entries | Where-Object type -eq 'Full' | Select-Object -Last 1
if (-not $full) { throw "No verified full backup of '$SourceDatabase' in the manifest." }
$later = $entries | Where-Object { $_.takenAtUtc -gt $full.takenAtUtc }
$diff = $later | Where-Object type -eq 'Diff' | Select-Object -Last 1
$logs = $later | Where-Object { $_.type -eq 'Log' -and (-not $diff -or $_.takenAtUtc -gt $diff.takenAtUtc) }

foreach ($entry in @($full) + @($diff) + @($logs)) {
    if ($entry -and -not (Test-Path $entry.file)) { throw "Backup file missing: $($entry.file)" }
}

$exists = Invoke-Sql -Scalar -Sql "SELECT COUNT(*) FROM sys.databases WHERE name = N'$TargetDatabase'"
if ($exists -gt 0 -and -not $Replace) {
    throw "Database '$TargetDatabase' already exists. Pass -Replace to restore over it (production restore), or drop the stale drill database first."
}
if ($Replace -and $exists -gt 0) {
    $connections = Invoke-Sql -Scalar -Sql "SELECT COUNT(*) FROM sys.dm_exec_sessions WHERE database_id = DB_ID(N'$TargetDatabase') AND is_user_process = 1"
    if ($connections -gt 0) {
        throw "'$TargetDatabase' has $connections open user connection(s). Stop the application (both IIS app pools on the app host) before restoring, or the chain forks (RUNBOOKS.md 7)."
    }
}

# Relocate data files for a drill so they cannot collide with production's.
$files = Invoke-Sql -Table -Sql "RESTORE FILELISTONLY FROM DISK = N'$($full.file)'"
$dataRoot = Invoke-Sql -Scalar -Sql "SELECT CAST(SERVERPROPERTY('InstanceDefaultDataPath') AS nvarchar(512))"
$logRoot = Invoke-Sql -Scalar -Sql "SELECT CAST(SERVERPROPERTY('InstanceDefaultLogPath') AS nvarchar(512))"
$moves = ($files | ForEach-Object {
    $root = if ($_.Type -eq 'L') { $logRoot } else { $dataRoot }
    $ext = [System.IO.Path]::GetExtension($_.PhysicalName)
    "MOVE N'$($_.LogicalName)' TO N'$(Join-Path $root "$TargetDatabase-$($_.LogicalName)$ext")'"
}) -join ', '
$replaceClause = if ($Replace) { ', REPLACE' } else { '' }

Write-Host "==> Restoring full $($full.file) -> [$TargetDatabase] (NORECOVERY)"
Invoke-Sql -Sql "RESTORE DATABASE [$TargetDatabase] FROM DISK = N'$($full.file)' WITH $moves, CHECKSUM, NORECOVERY$replaceClause"
if ($diff) {
    Write-Host "==> Restoring differential $($diff.file)"
    Invoke-Sql -Sql "RESTORE DATABASE [$TargetDatabase] FROM DISK = N'$($diff.file)' WITH CHECKSUM, NORECOVERY"
}
foreach ($log in $logs) {
    Write-Host "==> Restoring log $($log.file)"
    Invoke-Sql -Sql "RESTORE LOG [$TargetDatabase] FROM DISK = N'$($log.file)' WITH CHECKSUM, NORECOVERY"
}
Invoke-Sql -Sql "RESTORE DATABASE [$TargetDatabase] WITH RECOVERY"

Write-Host "==> DBCC CHECKDB"
Invoke-Sql -Sql "DBCC CHECKDB (N'$TargetDatabase') WITH NO_INFOMSGS, ALL_ERRORMSGS"

$rows = Invoke-Sql -Scalar -Sql "SELECT COUNT_BIG(*) FROM [$TargetDatabase].dbo.AuditEvents"
$maxSequence = Invoke-Sql -Scalar -Sql "SELECT ISNULL(MAX([Sequence]), 0) FROM [$TargetDatabase].dbo.AuditEvents"
$lastEntry = @($full) + @($diff) + @($logs) | Select-Object -Last 1
Write-Host ""
Write-Host "Restored [$TargetDatabase]: AuditEvents rows=$rows, max sequence=$maxSequence (backup chain ends $($lastEntry.takenAtUtc), manifest said max sequence $($lastEntry.auditMaxSequence))."
Write-Host "Compare max sequence with the anchors in the immutable container (RUNBOOKS.md 7 step 3) -- GET /api/audit/verify after the application starts reports any range the anchors have that this chain does not."

if (-not $Keep -and $TargetDatabase -ne $SourceDatabase) {
    Write-Host "==> Dropping drill database [$TargetDatabase] (pass -Keep to retain)"
    Invoke-Sql -Sql "ALTER DATABASE [$TargetDatabase] SET SINGLE_USER WITH ROLLBACK IMMEDIATE; DROP DATABASE [$TargetDatabase]"
}
