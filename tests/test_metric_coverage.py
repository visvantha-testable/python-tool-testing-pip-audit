"""Validate metric coverage config maps all 8 SCA metrics."""

import json
import pathlib

from pip_audit_metrics import compute_metrics, compute_normalized_scores, export_metric_evidence

CONFIG = pathlib.Path(__file__).resolve().parents[1] / "config" / "metric_coverage.json"
ARTIFACTS = pathlib.Path(__file__).resolve().parents[1] / "artifacts" / "training"


def test_metric_coverage_config_has_eight_entries():
    data = json.loads(CONFIG.read_text(encoding="utf-8"))
    assert data["metrics_total"] == 8
    assert len(data["metrics"]) == 8


def test_metric_evidence_covers_all_eight():
    metrics = compute_metrics(
        ARTIFACTS / "pip_audit_report.json",
        tree_json=ARTIFACTS / "dependency_tree.json",
        outdated_json=ARTIFACTS / "outdated.json",
        licenses_json=ARTIFACTS / "licenses.json",
        baseline_audit_json=ARTIFACTS / "baseline_pip_audit.json",
    )
    evidence = export_metric_evidence(metrics)
    assert evidence["metrics_total"] == 8
    assert evidence["metrics_covered"] == 8
    assert evidence["metric_coverage_complete"] is True
    assert len(evidence["metric_evidence"]) == 8
    scores = compute_normalized_scores(metrics)
    assert all(score == 100.0 for score in scores.values())
