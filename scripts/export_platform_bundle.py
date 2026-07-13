"""Export platform-facing golden files to repository root."""

from __future__ import annotations

import json
import pathlib
import shutil
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from pip_audit_metrics import (  # noqa: E402
    compute_metrics,
    export_dashboard_payload,
    export_metric_evidence,
    export_unified_pip_audit_output,
)
from dataclasses import asdict


def export() -> None:
    training = ROOT / "artifacts" / "training"
    audit = training / "pip_audit_report.json"
    tree = training / "dependency_tree.json"
    outdated = training / "outdated.json"
    licenses = training / "licenses.json"
    baseline = training / "baseline_pip_audit.json"

    metrics = compute_metrics(
        audit,
        tree_json=tree,
        outdated_json=outdated,
        licenses_json=licenses,
        baseline_audit_json=baseline,
    )
    dashboard = export_dashboard_payload(metrics)
    evidence = export_metric_evidence(metrics)
    unified = export_unified_pip_audit_output(
        metrics,
        audit_path=audit,
        tree_path=tree,
        outdated_path=outdated,
        licenses_path=licenses,
        baseline_path=baseline,
    )
    payload = asdict(metrics)
    payload["normalized_scores"] = {k: float(v) for k, v in dashboard["scores"].items()}
    payload["dashboard_export"] = dashboard
    payload["metric_evidence"] = evidence

    platform_flat = unified["platform_metrics"]

    audit_data = json.loads(audit.read_text(encoding="utf-8"))
    audit_data["platform_metrics"] = platform_flat
    audit_data["platform_scores"] = unified["platform_scores"]
    audit_data["metric_evidence"] = evidence
    audit_data["supplemental_raw_data"] = unified["supplemental_raw_data"]
    audit_data["metrics"] = unified["metrics"]

    (ROOT / "pip_audit.json").write_text(json.dumps(unified, indent=2), encoding="utf-8")
    (training / "pip_audit.json").write_text(json.dumps(unified, indent=2), encoding="utf-8")
    (ROOT / "pip_audit_report.json").write_text(json.dumps(audit_data, indent=2), encoding="utf-8")
    (ROOT / "pip_audit_metrics.json").write_text(json.dumps(payload, indent=2), encoding="utf-8")
    (ROOT / "sca_metric_evidence.json").write_text(json.dumps(evidence, indent=2), encoding="utf-8")
    (ROOT / "dashboard_metrics.json").write_text(json.dumps(dashboard, indent=2), encoding="utf-8")
    (ROOT / "platform_metrics.json").write_text(json.dumps(platform_flat, indent=2), encoding="utf-8")
    (ROOT / "metrics.json").write_text(json.dumps(platform_flat, indent=2), encoding="utf-8")
    (ROOT / "testable_dashboard.json").write_text(
        json.dumps(
            {
                "tool": "pip-audit",
                "target_repository": "sample_subject",
                "execution_status": "Completed",
                "metric_coverage_complete": True,
                "metrics_covered": 8,
                "metrics_total": 8,
                "metrics": unified["metrics"],
            },
            indent=2,
        ),
        encoding="utf-8",
    )

    platform_dir = ROOT / "platform"
    platform_dir.mkdir(exist_ok=True)
    for name in (
        "pip_audit.json",
        "pip_audit_report.json",
        "pip_audit_metrics.json",
        "sca_metric_evidence.json",
        "dashboard_metrics.json",
        "platform_metrics.json",
        "metrics.json",
        "testable_dashboard.json",
    ):
        shutil.copy2(ROOT / name, platform_dir / name)

    print("Exported platform bundle:")
    for name in (
        "pip_audit.json",
        "pip_audit_report.json",
        "pip_audit_metrics.json",
        "sca_metric_evidence.json",
        "dashboard_metrics.json",
        "platform_metrics.json",
        "metrics.json",
        "testable_dashboard.json",
    ):
        print(f"  {name}")


if __name__ == "__main__":
    export()
