$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot
python -m pip install -r requirements.txt -q
python -m pytest tests/ -q
.\run_pip_audit_analysis.ps1
