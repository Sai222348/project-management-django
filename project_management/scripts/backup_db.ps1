param(
    [string]$OutputDir = ".\backups",
    [string]$LogDir = ".\logs"
)

$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null
New-Item -ItemType Directory -Force -Path $LogDir | Out-Null
$drillLog = Join-Path $LogDir "backup_restore_drill.log"

$dbEngine = $env:DJANGO_DB_ENGINE
if ($dbEngine -eq "postgres") {
    if (-not $env:POSTGRES_DB) { throw "POSTGRES_DB is required." }
    if (-not $env:POSTGRES_USER) { throw "POSTGRES_USER is required." }
    if (-not $env:POSTGRES_HOST) { $env:POSTGRES_HOST = "127.0.0.1" }
    if (-not $env:POSTGRES_PORT) { $env:POSTGRES_PORT = "5432" }

    $backupFile = Join-Path $OutputDir ("pg_" + $env:POSTGRES_DB + "_" + $timestamp + ".dump")
    pg_dump `
      --format=custom `
      --host=$env:POSTGRES_HOST `
      --port=$env:POSTGRES_PORT `
      --username=$env:POSTGRES_USER `
      --file=$backupFile `
      $env:POSTGRES_DB
    if ($LASTEXITCODE -ne 0) { throw "pg_dump failed." }
    Write-Host "Backup created: $backupFile"
    Add-Content -Path $drillLog -Value "$(Get-Date -Format s) BACKUP OK postgres $backupFile"
}
else {
    $sqliteFile = ".\db.sqlite3"
    if (-not (Test-Path $sqliteFile)) { throw "SQLite database not found: $sqliteFile" }
    $backupFile = Join-Path $OutputDir ("sqlite_" + $timestamp + ".sqlite3")
    Copy-Item $sqliteFile $backupFile -Force
    Write-Host "Backup created: $backupFile"
    Add-Content -Path $drillLog -Value "$(Get-Date -Format s) BACKUP OK sqlite $backupFile"
}
