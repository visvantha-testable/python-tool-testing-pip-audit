"""Collect all raw SCA artifacts required for 8-metric pip-audit coverage."""

from __future__ import annotations

import argparse
import json
import pathlib
import subprocess
import sys


def _run(cmd: list[str], *, cwd: pathlib.Path | None = None) -> str:
    proc = subprocess.run(cmd, capture_output=True, text=True, cwd=cwd, check=True)
    return proc.stdout


def collect(
    *,
    python_exe: str,
    requirements: pathlib.Path,
    output_dir: pathlib.Path,
    baseline_audit: pathlib.Path | None = None,
) -> dict[str, pathlib.Path]:
    output_dir.mkdir(parents=True, exist_ok=True)

    audit_path = output_dir / "pip_audit_report.json"
    _run(
        [python_exe, "-m", "pip_audit", "-r", str(requirements), "-f", "json", "-o", str(audit_path)]
    )

    tree_path = output_dir / "dependency_tree.json"
    tree_path.write_text(
        _run([python_exe, "-m", "pipdeptree", "--json-tree"]),
        encoding="utf-8",
    )

    outdated_path = output_dir / "outdated.json"
    outdated_stdout = subprocess.run(
        [python_exe, "-m", "pip", "list", "--outdated", "--format=json"],
        capture_output=True,
        text=True,
        check=False,
    ).stdout
    outdated_path.write_text(outdated_stdout or "[]", encoding="utf-8")

    licenses_path = output_dir / "licenses.json"
    license_rows = _run(
        [
            python_exe,
            "-c",
            (
                "import json, importlib.metadata as m; "
                "rows=[{'name': d.metadata.get('Name'), 'license': d.metadata.get('License','UNKNOWN')} "
                "for d in m.distributions() if d.metadata.get('Name')]; "
                "print(json.dumps(rows, indent=2))"
            ),
        ]
    )
    licenses_path.write_text(license_rows, encoding="utf-8")

    baseline_path = output_dir / "baseline_pip_audit.json"
    if baseline_audit and baseline_audit.exists():
        baseline_path.write_text(baseline_audit.read_text(encoding="utf-8-sig"), encoding="utf-8")
    else:
        baseline_path.write_text(audit_path.read_text(encoding="utf-8-sig"), encoding="utf-8")

    return {
        "audit": audit_path,
        "tree": tree_path,
        "outdated": outdated_path,
        "licenses": licenses_path,
        "baseline": baseline_path,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--python", default=sys.executable)
    parser.add_argument(
        "--requirements",
        type=pathlib.Path,
        default=pathlib.Path("sample_subject/requirements.txt"),
    )
    parser.add_argument(
        "--output-dir",
        type=pathlib.Path,
        default=pathlib.Path("artifacts/training"),
    )
    parser.add_argument("--baseline-audit", type=pathlib.Path, default=None)
    args = parser.parse_args()

    paths = collect(
        python_exe=args.python,
        requirements=args.requirements.resolve(),
        output_dir=args.output_dir.resolve(),
        baseline_audit=args.baseline_audit,
    )
    print(json.dumps({key: str(path) for key, path in paths.items()}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
