param(
    [ValidateSet("sample")]
    [string]$Target = "sample"
)

$ErrorActionPreference = "Stop"
python (Join-Path $PSScriptRoot "pip_audit_trigger.py")
exit $LASTEXITCODE
