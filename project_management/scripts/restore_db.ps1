param(
    [Parameter(Mandatory = $true)]
    [string]$BackupFile,
    [string]$LogDir = ".\logs"
)

if (-not (Test-Path $BackupFile)) {
    throw "Backup file not found: $BackupFile"
}
New-Item -ItemType Directory -Force -Path $LogDir | Out-Null
$drillLog = Join-Path $LogDir "backup_restore_drill.log"

$dbEngine = $env:DJANGO_DB_ENGINE
if ($dbEngine -eq "postgres") {
    if (-not $env:POSTGRES_DB) { throw "POSTGRES_DB is required." }
    if (-not $env:POSTGRES_USER) { throw "POSTGRES_USER is required." }
    if (-not $env:POSTGRES_HOST) { $env:POSTGRES_HOST = "127.0.0.1" }
    if (-not $env:POSTGRES_PORT) { $env:POSTGRES_PORT = "5432" }

    pg_restore `
      --clean `
      --if-exists `
      --no-owner `
      --host=$env:POSTGRES_HOST `
      --port=$env:POSTGRES_PORT `
      --username=$env:POSTGRES_USER `
      --dbname=$env:POSTGRES_DB `
      $BackupFile
    if ($LASTEXITCODE -ne 0) { throw "pg_restore failed." }
    Write-Host "Restore completed to database: $($env:POSTGRES_DB)"
    Add-Content -Path $drillLog -Value "$(Get-Date -Format s) RESTORE OK postgres $BackupFile"
}
else {
    $sqliteFile = ".\db.sqlite3"
    Copy-Item $BackupFile $sqliteFile -Force
    Write-Host "SQLite restore completed: $sqliteFile"
    Add-Content -Path $drillLog -Value "$(Get-Date -Format s) RESTORE OK sqlite $BackupFile"
}
