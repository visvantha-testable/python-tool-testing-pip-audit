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
$Baseline = Join-Path $Root "config\golden_baseline_pip_audit.json"

python -m pip install -r (Join-Path $Root "requirements.txt") -q

New-Item -ItemType Directory -Force -Path $Artifacts | Out-Null

if (-not (Test-Path $Py)) {
    python -m venv $Venv
}

& $Py -m pip install -U pip -q
& $Py -m pip install -r $SampleReq -q
& $Py -m pip install pip-audit pipdeptree -q

python (Join-Path $Root "scripts\collect_artifacts.py") `
    --python $Py `
    --requirements $SampleReq `
    --output-dir $Artifacts `
    --baseline-audit $Baseline

python (Join-Path $Root "pip_audit_metrics.py") `
    --audit-json (Join-Path $Artifacts "pip_audit_report.json") `
    --tree-json (Join-Path $Artifacts "dependency_tree.json") `
    --outdated-json (Join-Path $Artifacts "outdated.json") `
    --licenses-json (Join-Path $Artifacts "licenses.json") `
    --baseline-audit-json (Join-Path $Artifacts "baseline_pip_audit.json") `
    --output-json (Join-Path $Root "reports\sample_metrics.json") `
    --dashboard-json (Join-Path $Root "reports\sample_dashboard.json")

python (Join-Path $Root "scripts\export_platform_bundle.py")
python (Join-Path $Root "validate_metric_coverage.py") `
    --metrics-json (Join-Path $Root "pip_audit_metrics.json")
python (Join-Path $Root "scripts\verify_100_percent.py") `
    --metrics-json (Join-Path $Root "pip_audit_metrics.json") `
    --dashboard-json (Join-Path $Root "dashboard_metrics.json")

exit $LASTEXITCODE
