"""Fail unless every pip-audit dashboard metric is 100/100 PASS."""

from __future__ import annotations

import argparse
import json
import pathlib
import sys


def verify(metrics_path: pathlib.Path, dashboard_path: pathlib.Path | None) -> int:
    payload = json.loads(metrics_path.read_text(encoding="utf-8"))
    scores = payload.get("normalized_scores") or payload.get("dashboard_export", {}).get("scores")
    if scores is None:
        print("ERROR: normalized_scores missing", file=sys.stderr)
        return 1

    failing = {name: score for name, score in scores.items() if float(score) < 100.0}
    if failing:
        print("FAIL: metrics below 100/100:", file=sys.stderr)
        for name, score in sorted(failing.items()):
            print(f"  {name}: {score}", file=sys.stderr)
        return 1

    evidence = payload.get("metric_evidence") or {}
    if evidence:
        if not evidence.get("metric_coverage_complete"):
            print("FAIL: metric_coverage_complete is false", file=sys.stderr)
            return 1
        if evidence.get("metrics_covered") != 8:
            print("FAIL: metrics_covered is not 8", file=sys.stderr)
            return 1

    if dashboard_path and dashboard_path.exists():
        dash = json.loads(dashboard_path.read_text(encoding="utf-8"))
        for row in dash.get("metrics", []):
            if row.get("result") != "PASS" or float(row.get("coverage_percent", 0)) < 100.0:
                print(f"FAIL dashboard row: {row}", file=sys.stderr)
                return 1

    print(f"PASS: all {len(scores)} metrics are 100/100")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--metrics-json", type=pathlib.Path, required=True)
    parser.add_argument("--dashboard-json", type=pathlib.Path, default=None)
    args = parser.parse_args()
    return verify(args.metrics_json, args.dashboard_json)


if __name__ == "__main__":
    raise SystemExit(main())
