"""Test pip_audit_trigger entry point."""

import json
import pathlib

ROOT = pathlib.Path(__file__).resolve().parents[1]


def test_platform_trigger_config_exists():
    cfg = json.loads((ROOT / "config" / "platform_trigger.json").read_text(encoding="utf-8"))
    assert cfg["trigger_command"] == "python -m pip_audit_platform -r sample_subject/requirements.txt -f json -o pip_audit.json"
    assert cfg["primary_output_file"] == "pip_audit.json"
    assert len(cfg["expected_scores"]) == 8


def test_trigger_script_exists():
    assert (ROOT / "pip_audit_trigger.py").exists()
    assert (ROOT / "run_trigger.ps1").exists()
    assert (ROOT / "run_trigger.sh").exists()
