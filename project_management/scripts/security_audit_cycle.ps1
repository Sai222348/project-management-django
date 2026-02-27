param(
    [string]$LogDir = ".\logs"
)

New-Item -ItemType Directory -Force -Path $LogDir | Out-Null
$stamp = Get-Date -Format "yyyyMMdd_HHmmss"
$logFile = Join-Path $LogDir ("security_audit_" + $stamp + ".log")

function Write-Log {
    param([string]$Text)
    $line = "$(Get-Date -Format s) $Text"
    Add-Content -Path $logFile -Value $line
    Write-Host $line
}

Write-Log "Starting dependency/security audit cycle"
Write-Log "Python version: $(python --version 2>&1)"
Write-Log "Pip version: $(python -m pip --version 2>&1)"

Write-Log "Running pip check"
python -m pip check 2>&1 | Tee-Object -FilePath $logFile -Append

Write-Log "Running pip list --outdated"
python -m pip list --outdated 2>&1 | Tee-Object -FilePath $logFile -Append

Write-Log "Running pip-audit if installed"
python -m pip_audit --version *> $null
if ($LASTEXITCODE -eq 0) {
    python -m pip_audit 2>&1 | Tee-Object -FilePath $logFile -Append
}
else {
    Write-Log "pip-audit not installed. Install with: pip install pip-audit"
}

Write-Log "Security audit cycle completed"
Write-Host "Audit log: $logFile"

