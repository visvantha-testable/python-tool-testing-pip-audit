$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot
python (Join-Path $PSScriptRoot "scripts\verify_pip_audit_json.py") --pip-audit-json (Join-Path $PSScriptRoot "pip_audit.json")
exit $LASTEXITCODE
