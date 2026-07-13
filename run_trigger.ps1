$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot
python pip_audit_trigger.py @args
exit $LASTEXITCODE
