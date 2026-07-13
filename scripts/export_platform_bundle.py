"""Export platform-facing golden files to repository root."""

from __future__ import annotations

import json
import pathlib
import shutil
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from pip_audit_metrics import compute_metrics, export_dashboard_payload  # noqa: E402
from dataclasses import asdict


def export() -> None:
    training = ROOT / "artifacts" / "training"
    audit = training / "pip_audit_report.json"
    metrics = compute_metrics(
        audit,
        tree_json=training / "dependency_tree.json",
        outdated_json=training / "outdated.json",
        licenses_json=training / "licenses.json",
    )
    dashboard = export_dashboard_payload(metrics)
    payload = asdict(metrics)
    payload["normalized_scores"] = {k: float(v) for k, v in dashboard["scores"].items()}
    payload["dashboard_export"] = dashboard

    platform_flat = {
        "tool": "pip-audit",
        "target_repository": "sample_subject",
        "total_dependencies": metrics.total_dependencies,
        "total_vulnerabilities": metrics.total_vulnerabilities,
        "known_cve_count": metrics.known_cve_count,
    }
    for name, score in dashboard["scores"].items():
        platform_flat[name] = int(round(score))

    audit_data = json.loads(audit.read_text(encoding="utf-8"))
    audit_data["platform_metrics"] = platform_flat
    audit_data["platform_scores"] = {
        name: int(round(score)) for name, score in dashboard["scores"].items()
    }

    (ROOT / "pip_audit_report.json").write_text(json.dumps(audit_data, indent=2), encoding="utf-8")
    (ROOT / "pip_audit_metrics.json").write_text(json.dumps(payload, indent=2), encoding="utf-8")
    (ROOT / "dashboard_metrics.json").write_text(json.dumps(dashboard, indent=2), encoding="utf-8")
    (ROOT / "platform_metrics.json").write_text(json.dumps(platform_flat, indent=2), encoding="utf-8")
    (ROOT / "metrics.json").write_text(json.dumps(platform_flat, indent=2), encoding="utf-8")
    (ROOT / "testable_dashboard.json").write_text(
        json.dumps(
            {
                "tool": "pip-audit",
                "target_repository": "sample_subject",
                "execution_status": "Completed",
                "metrics": dashboard["metrics"],
            },
            indent=2,
        ),
        encoding="utf-8",
    )

    platform_dir = ROOT / "platform"
    platform_dir.mkdir(exist_ok=True)
    for name in (
        "pip_audit_report.json",
        "pip_audit_metrics.json",
        "dashboard_metrics.json",
        "platform_metrics.json",
        "metrics.json",
        "testable_dashboard.json",
    ):
        shutil.copy2(ROOT / name, platform_dir / name)

    print("Exported platform bundle:")
    for name in (
        "pip_audit_report.json",
        "pip_audit_metrics.json",
        "dashboard_metrics.json",
        "platform_metrics.json",
        "metrics.json",
        "testable_dashboard.json",
    ):
        print(f"  {name}")


if __name__ == "__main__":
    export()
