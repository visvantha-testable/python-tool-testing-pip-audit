$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot
python scripts/verify_100_percent.py --metrics-json pip_audit_metrics.json --dashboard-json dashboard_metrics.json
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
Write-Host "SUCCESS: All metrics are 100/100 PASS" -ForegroundColor Green
