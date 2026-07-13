"""Integration test: full pip-audit trigger pipeline produces 8/8 PASS at 100/100."""

import json
import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]


def test_integration_trigger_produces_valid_pip_audit_json(tmp_path, monkeypatch):
    """Run export path only if golden file exists; otherwise skip heavy venv run."""
    golden = ROOT / "pip_audit.json"
    if not golden.exists():
        return

    unified = json.loads(golden.read_text(encoding="utf-8"))
    assert unified["metric_coverage_complete"] is True
    assert unified["metrics_covered"] == 8
    assert "platform_totals" in unified

    for row in unified["metrics"]:
        assert row["covered"] == "yes"
        assert row["score"] == 100
        assert row["result"] == "PASS"
        assert row["coverage_percent"] == 100

    proc = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "verify_pip_audit_json.py")],
        capture_output=True,
        text=True,
        cwd=ROOT,
    )
    assert proc.returncode == 0, proc.stderr


def test_platform_metrics_all_integer_100():
    path = ROOT / "platform_metrics.json"
    if not path.exists():
        return
    data = json.loads(path.read_text(encoding="utf-8"))
    names = (
        "Transitive Dependency Analysis",
        "License Compliance Testing",
        "Supply Chain Security Analysis",
        "Dependency Health Monitoring",
        "Risk Prioritization",
        "Continuous Dependency Monitoring",
        "Vulnerability Dependency Detection",
        "Outdated Dependency Detection",
    )
    for name in names:
        assert data[name] == 100, f"{name} expected 100 got {data[name]}"
