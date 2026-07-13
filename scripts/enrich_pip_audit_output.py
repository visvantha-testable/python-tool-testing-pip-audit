"""Enrich incomplete native pip-audit JSON into full pip_audit.json with all 8 metrics."""

from __future__ import annotations

import argparse
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from pip_audit_metrics import compute_metrics, export_unified_pip_audit_output  # noqa: E402


def enrich(
    *,
    native_audit: pathlib.Path,
    output: pathlib.Path,
    tree: pathlib.Path,
    outdated: pathlib.Path,
    licenses: pathlib.Path,
    baseline: pathlib.Path,
) -> None:
    metrics = compute_metrics(
        native_audit,
        tree_json=tree,
        outdated_json=outdated,
        licenses_json=licenses,
        baseline_audit_json=baseline,
    )
    unified = export_unified_pip_audit_output(
        metrics,
        audit_path=native_audit,
        tree_path=tree,
        outdated_path=outdated,
        licenses_path=licenses,
        baseline_path=baseline,
    )
    output.write_text(json.dumps(unified, indent=2), encoding="utf-8")
    print(f"Wrote enriched {output}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--native-audit", type=pathlib.Path, required=True)
    parser.add_argument("--output", type=pathlib.Path, default=ROOT / "pip_audit.json")
    parser.add_argument("--tree", type=pathlib.Path, default=ROOT / "artifacts" / "training" / "dependency_tree.json")
    parser.add_argument("--outdated", type=pathlib.Path, default=ROOT / "artifacts" / "training" / "outdated.json")
    parser.add_argument("--licenses", type=pathlib.Path, default=ROOT / "artifacts" / "training" / "licenses.json")
    parser.add_argument("--baseline", type=pathlib.Path, default=ROOT / "artifacts" / "training" / "baseline_pip_audit.json")
    args = parser.parse_args()

    for path, label in (
        (args.tree, "dependency_tree"),
        (args.outdated, "outdated"),
        (args.licenses, "licenses"),
        (args.baseline, "baseline"),
    ):
        if not path.exists():
            print(f"ERROR: missing {label} at {path}. Run: python pip_audit_trigger.py", file=sys.stderr)
            return 1

    enrich(
        native_audit=args.native_audit,
        output=args.output,
        tree=args.tree,
        outdated=args.outdated,
        licenses=args.licenses,
        baseline=args.baseline,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
