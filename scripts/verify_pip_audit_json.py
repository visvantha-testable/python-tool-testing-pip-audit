"""Verify unified pip_audit.json has all 8 metrics covered with yes + 100/100."""

from __future__ import annotations

import argparse
import json
import pathlib
import sys


REQUIRED_SUPPLEMENTAL_KEYS = (
    "dependency_tree",
    "outdated_packages",
    "licenses",
    "baseline_audit",
)


def verify(path: pathlib.Path) -> int:
    payload = json.loads(path.read_text(encoding="utf-8-sig"))
    errors: list[str] = []

    if not payload.get("output_complete"):
        errors.append("output_complete is not true")
    if not payload.get("metric_coverage_complete"):
        errors.append("metric_coverage_complete is not true")
    if payload.get("metrics_covered") != 8:
        errors.append(f"metrics_covered is {payload.get('metrics_covered')} not 8")

    supplemental = payload.get("supplemental_raw_data") or {}
    for key in REQUIRED_SUPPLEMENTAL_KEYS:
        if key not in supplemental:
            errors.append(f"missing supplemental_raw_data.{key}")

    metrics = payload.get("metrics") or []
    if len(metrics) != 8:
        errors.append(f"expected 8 metric rows, got {len(metrics)}")

    for row in metrics:
        name = row.get("classification", "?")
        if row.get("covered") != "yes":
            errors.append(f"{name}: covered is not 'yes'")
        if int(row.get("score", 0)) < 100:
            errors.append(f"{name}: score {row.get('score')} below 100")
        if row.get("result") != "PASS":
            errors.append(f"{name}: result is not PASS")
        if not row.get("raw_sources_present"):
            errors.append(f"{name}: raw_sources_present is false")
        if not row.get("raw_parameters"):
            errors.append(f"{name}: raw_parameters missing")

    if errors:
        print("FAIL: pip_audit.json incomplete:", file=sys.stderr)
        for err in errors:
            print(f"  - {err}", file=sys.stderr)
        return 1

    print("PASS: pip_audit.json has all 8 metrics covered=yes with 100/100 scores")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--pip-audit-json",
        type=pathlib.Path,
        default=pathlib.Path(__file__).resolve().parents[1] / "pip_audit.json",
    )
    args = parser.parse_args()
    return verify(args.pip_audit_json)


if __name__ == "__main__":
    raise SystemExit(main())
