param(
    [ValidateSet("sample")]
    [string]$Target = "sample"
)

$ErrorActionPreference = "Stop"
$Root = $PSScriptRoot
$Artifacts = Join-Path $Root "artifacts\training"
$SampleDir = Join-Path $Root "sample_subject"
$SampleReq = Join-Path $SampleDir "requirements.txt"
$Venv = Join-Path $SampleDir ".venv"
$Py = Join-Path $Venv "Scripts\python.exe"

python -m pip install -r (Join-Path $Root "requirements.txt") -q

New-Item -ItemType Directory -Force -Path $Artifacts | Out-Null

if (-not (Test-Path $Py)) {
    python -m venv $Venv
}

& $Py -m pip install -U pip -q
& $Py -m pip install -r $SampleReq -q
& $Py -m pip install pip-audit pipdeptree -q

& $Py -m pip_audit -r $SampleReq -f json -o (Join-Path $Artifacts "pip_audit_report.json")

& $Py -c "import json, subprocess, sys; proc=subprocess.run([sys.executable,'-m','pipdeptree','--json-tree'], capture_output=True, text=True, check=True); open(r'$Artifacts\dependency_tree.json','w',encoding='utf-8').write(proc.stdout)"
& $Py -c "import json, subprocess, sys; proc=subprocess.run([sys.executable,'-m','pip','list','--outdated','--format=json'], capture_output=True, text=True); open(r'$Artifacts\outdated.json','w',encoding='utf-8').write(proc.stdout or '[]')"
& $Py -c "import json, importlib.metadata as m; rows=[{'name': d.metadata.get('Name'), 'license': d.metadata.get('License','UNKNOWN')} for d in m.distributions() if d.metadata.get('Name')]; open(r'$Artifacts\licenses.json','w',encoding='utf-8').write(json.dumps(rows, indent=2))"

python (Join-Path $Root "pip_audit_metrics.py") `
    --audit-json (Join-Path $Artifacts "pip_audit_report.json") `
    --tree-json (Join-Path $Artifacts "dependency_tree.json") `
    --outdated-json (Join-Path $Artifacts "outdated.json") `
    --licenses-json (Join-Path $Artifacts "licenses.json") `
    --output-json (Join-Path $Root "reports\sample_metrics.json") `
    --dashboard-json (Join-Path $Root "reports\sample_dashboard.json")

python (Join-Path $Root "scripts\export_platform_bundle.py")
python (Join-Path $Root "scripts\verify_100_percent.py") `
    --metrics-json (Join-Path $Root "pip_audit_metrics.json") `
    --dashboard-json (Join-Path $Root "dashboard_metrics.json")

exit $LASTEXITCODE
