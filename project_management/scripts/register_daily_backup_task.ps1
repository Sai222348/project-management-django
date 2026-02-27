param(
    [string]$TaskName = "ProjectManagementDailyBackup",
    [string]$ProjectDir = ".",
    [string]$RunTime = "23:30"
)

$projectPath = (Resolve-Path $ProjectDir).Path
$scriptPath = Join-Path $projectPath "scripts\backup_db.ps1"
$logPath = Join-Path $projectPath "logs\scheduler_backup.log"
New-Item -ItemType Directory -Force -Path (Join-Path $projectPath "logs") | Out-Null

$taskCmd = "powershell.exe -NoProfile -ExecutionPolicy Bypass -File `"$scriptPath`" >> `"$logPath`" 2>&1"

schtasks /Create `
  /F `
  /SC DAILY `
  /TN $TaskName `
  /TR $taskCmd `
  /ST $RunTime | Out-Null

Write-Host "Scheduled task '$TaskName' created for daily run at $RunTime"
Write-Host "Command: $taskCmd"

