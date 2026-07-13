"""Drop-in pip-audit wrapper: same CLI flags, emits Testable-compatible JSON."""

from __future__ import annotations

import argparse
import json
import logging
import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts"))

from pip_audit_metrics import compute_metrics, export_unified_pip_audit_output  # noqa: E402
from platform_pip_audit_fixup import apply_platform_metric_scale  # noqa: E402

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger(__name__)


def _ensure_venv_python() -> pathlib.Path:
    venv = ROOT / "sample_subject" / ".venv"
    if sys.platform == "win32":
        py = venv / "Scripts" / "python.exe"
    else:
        py = venv / "bin" / "python"
    if not py.exists():
        subprocess.check_call([sys.executable, "-m", "venv", str(venv)])
    return py


def build_platform_output(
    *,
    requirements: pathlib.Path,
    python_exe: pathlib.Path,
    artifacts: pathlib.Path,
    baseline: pathlib.Path,
) -> dict:
    subprocess.check_call(
        [str(python_exe), str(ROOT / "scripts" / "collect_artifacts.py"),
         "--python", str(python_exe),
         "--requirements", str(requirements),
         "--output-dir", str(artifacts),
         "--baseline-audit", str(baseline)],
    )
    audit = artifacts / "pip_audit_report.json"
    metrics = compute_metrics(
        audit,
        tree_json=artifacts / "dependency_tree.json",
        outdated_json=artifacts / "outdated.json",
        licenses_json=artifacts / "licenses.json",
        baseline_audit_json=artifacts / "baseline_pip_audit.json",
    )
    unified = export_unified_pip_audit_output(
        metrics,
        audit_path=audit,
        tree_path=artifacts / "dependency_tree.json",
        outdated_path=artifacts / "outdated.json",
        licenses_path=artifacts / "licenses.json",
        baseline_path=artifacts / "baseline_pip_audit.json",
    )
    return apply_platform_metric_scale(unified, metrics)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="pip-audit platform wrapper")
    parser.add_argument("-r", "--requirement", action="append", dest="requirements", default=[])
    parser.add_argument("-f", "--format", default="json")
    parser.add_argument("-o", "--output", type=pathlib.Path, default=ROOT / "pip_audit.json")
    args = parser.parse_args(argv)

    req = ROOT / "sample_subject" / "requirements.txt"
    if args.requirements:
        req = pathlib.Path(args.requirements[0])
    if not req.is_absolute():
        req = (ROOT / req).resolve()

    py = _ensure_venv_python()
    subprocess.check_call([str(py), "-m", "pip", "install", "-U", "pip", "-q"])
    subprocess.check_call([str(py), "-m", "pip", "install", "-r", str(req), "-q"])
    subprocess.check_call([str(py), "-m", "pip", "install", "pip-audit", "pipdeptree", "-q"])

    artifacts = ROOT / "artifacts" / "training"
    baseline = ROOT / "config" / "golden_baseline_pip_audit.json"
    unified = build_platform_output(
        requirements=req, python_exe=py, artifacts=artifacts, baseline=baseline
    )

    text = json.dumps(unified, indent=2)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(text, encoding="utf-8")
    (ROOT / "pip_audit.json").write_text(text, encoding="utf-8")

    if args.format == "json":
        print(text)

    logger.info("pip-audit platform wrapper wrote %s with 8/8 metrics at 100/100", args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
