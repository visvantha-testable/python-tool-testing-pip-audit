"""Tests for pip-audit metric scoring."""

import json
import pathlib

import pytest

from pip_audit_metrics import compute_metrics, compute_normalized_scores


FIXTURES = pathlib.Path(__file__).parent / "fixtures"


@pytest.fixture()
def clean_audit(tmp_path: pathlib.Path):
    audit = {
        "dependencies": [
            {"name": "certifi", "version": "2026.6.17", "vulns": []},
            {"name": "urllib3", "version": "2.6.3", "vulns": []},
            {"name": "idna", "version": "3.11", "vulns": []},
        ],
        "fixes": [],
    }
    tree = [
        {"key": "certifi", "package_name": "certifi", "installed_version": "2026.6.17", "dependencies": []},
        {"key": "urllib3", "package_name": "urllib3", "installed_version": "2.6.3", "dependencies": []},
        {"key": "idna", "package_name": "idna", "installed_version": "3.11", "dependencies": []},
    ]
    audit_path = tmp_path / "audit.json"
    tree_path = tmp_path / "tree.json"
    outdated_path = tmp_path / "outdated.json"
    licenses_path = tmp_path / "licenses.json"
    audit_path.write_text(json.dumps(audit), encoding="utf-8")
    tree_path.write_text(json.dumps(tree), encoding="utf-8")
    outdated_path.write_text("[]", encoding="utf-8")
    licenses_path.write_text(
        json.dumps(
            [
                {"name": "certifi", "license": "MPL-2.0"},
                {"name": "urllib3", "license": "MIT"},
                {"name": "idna", "license": "BSD-3-Clause"},
            ]
        ),
        encoding="utf-8",
    )
    return audit_path, tree_path, outdated_path, licenses_path


def test_clean_sample_scores_100(clean_audit):
    audit, tree, outdated, licenses = clean_audit
    metrics = compute_metrics(audit, tree, outdated, licenses)
    scores = compute_normalized_scores(metrics)
    assert metrics.total_vulnerabilities == 0
    assert all(score == pytest.approx(100.0) for score in scores.values())


def test_vulnerable_sample_not_100(tmp_path: pathlib.Path):
    audit = {
        "dependencies": [
            {
                "name": "demo",
                "version": "1.0.0",
                "vulns": [
                    {
                        "id": "CVE-2024-0001",
                        "aliases": ["CVE-2024-0001"],
                        "description": "HIGH severity issue",
                        "fix_versions": ["2.0.0"],
                    }
                ],
            }
        ]
    }
    audit_path = tmp_path / "audit.json"
    audit_path.write_text(json.dumps(audit), encoding="utf-8")
    metrics = compute_metrics(audit_path)
    scores = compute_normalized_scores(metrics)
    assert metrics.total_vulnerabilities == 1
    assert scores["Vulnerability Dependency Detection"] < 100.0
