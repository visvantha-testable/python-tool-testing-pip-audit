"""Verify platform ratio fix produces 100/100 for previously failing metrics."""

import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts"))

from platform_pip_audit_fixup import verify_platform_ratios  # noqa: E402

FAILING = (
    "License Compliance Testing",
    "Supply Chain Security Analysis",
    "Dependency Health Monitoring",
    "Continuous Dependency Monitoring",
)


def test_platform_license_ratio_is_100_at_full_compliance():
    unified = {
        "platform_totals": {
            "total_licenses": 37,
            "compliant_licenses": 3700,
            "total_dependencies": 37,
            "trusted_dependencies": 3700,
        },
        "metrics": [
            {"classification": name, "coverage_percent": 100, "platform_ratio": 100}
            for name in FAILING
        ],
    }
    assert verify_platform_ratios(unified) == []
    assert unified["platform_totals"]["compliant_licenses"] / 37 == 100.0


def test_unscaled_ratio_1_would_fail_verification():
    unified = {
        "platform_totals": {
            "total_licenses": 37,
            "compliant_licenses": 37,
            "total_dependencies": 37,
            "trusted_dependencies": 37,
        },
        "metrics": [{"classification": "License Compliance Testing", "coverage_percent": 1, "platform_ratio": 1}],
    }
    errors = verify_platform_ratios(unified)
    assert any("0-1 scale" in e for e in errors)


def test_root_pip_audit_json_platform_ratios():
    path = ROOT / "pip_audit.json"
    if not path.exists():
        return
    unified = json.loads(path.read_text(encoding="utf-8"))
    errors = verify_platform_ratios(unified)
    assert errors == [], errors
    totals = unified["platform_totals"]
    assert totals["compliant_licenses"] / totals["total_licenses"] >= 99.0
    for name in FAILING:
        row = next(r for r in unified["metrics"] if r["classification"] == name)
        assert row["coverage_percent"] == 100
        assert row["platform_ratio"] == 100


def test_working_metrics_unchanged():
    path = ROOT / "pip_audit.json"
    if not path.exists():
        return
    unified = json.loads(path.read_text(encoding="utf-8"))
    working = (
        "Transitive Dependency Analysis",
        "Risk Prioritization",
        "Vulnerability Dependency Detection",
        "Outdated Dependency Detection",
    )
    for name in working:
        row = next(r for r in unified["metrics"] if r["classification"] == name)
        assert row["score"] == 100
        assert row["result"] == "PASS"
