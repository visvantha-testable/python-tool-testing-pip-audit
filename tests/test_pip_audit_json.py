"""Verify unified pip_audit.json output."""

import json
import pathlib

ROOT = pathlib.Path(__file__).resolve().parents[1]
PIP_AUDIT = ROOT / "pip_audit.json"


def test_pip_audit_json_exists_and_complete():
    assert PIP_AUDIT.exists(), "pip_audit.json missing at repo root"
    payload = json.loads(PIP_AUDIT.read_text(encoding="utf-8"))
    assert payload["output_complete"] is True
    assert payload["metric_coverage_complete"] is True
    assert payload["metrics_covered"] == 8
    assert len(payload["metrics"]) == 8
    assert all(row["covered"] == "yes" for row in payload["metrics"])
    assert all(row["score"] == 100 for row in payload["metrics"])
    supplemental = payload["supplemental_raw_data"]
    assert "dependency_tree" in supplemental
    assert "outdated_packages" in supplemental
    assert "licenses" in supplemental
    assert "baseline_audit" in supplemental
