"""Dependency Risk (SCA) metrics from pip-audit JSON and dependency tree."""

from __future__ import annotations

import argparse
import json
import pathlib
import re
import subprocess
import sys
from dataclasses import asdict, dataclass
from typing import Iterable


COPYLEFT_PATTERN = re.compile(r"\b(GPL|AGPL|SSPL|Commons Clause)\b", re.I)
RESTRICTED_PATTERN = re.compile(r"\b(Proprietary|UNLICENSED|Commercial)\b", re.I)


@dataclass
class PipAuditMetrics:
    total_dependencies: int
    direct_dependencies: int
    transitive_dependencies: int
    total_vulnerabilities: int
    known_cve_count: int
    critical_cve_count: int
    high_cve_count: int
    medium_cve_count: int
    low_cve_count: int
    vulnerabilities_with_fix: int
    transitive_vulnerable_count: int
    hidden_relationship_risk: float
    legal_risk_proxy: int
    supply_chain_risk: int
    community_vitality_score: float
    mitigation_effort: int
    alert_signal: int
    version_lag_count: int
    outdated_dependencies: int
    copyleft_license_count: int
    restricted_license_count: int
    cve_score: float
    transitive_risk_score: float
    license_risk_score: float
    trust_score: float
    vitality_score: float
    prioritization_coverage_percent: float
    alert_response_rate_percent: float
    version_lag_score: float
    transitive_dependency_score: float
    license_compliance_score: float
    supply_chain_score: float
    dependency_health_score: float
    risk_prioritization_score: float
    continuous_monitoring_score: float
    vulnerability_detection_score: float
    outdated_dependency_score: float


def _severity_bucket(vuln: dict) -> str:
    text = " ".join(
        str(vuln.get(key, ""))
        for key in ("id", "description", "summary", "severity")
    ).upper()
    if "CRITICAL" in text:
        return "critical"
    if "HIGH" in text:
        return "high"
    if "MEDIUM" in text or "MODERATE" in text:
        return "medium"
    if "LOW" in text:
        return "low"
    return "medium"


def _load_audit(path: pathlib.Path) -> dict:
    data = json.loads(path.read_text(encoding="utf-8-sig"))
    if "dependencies" not in data:
        raise ValueError("pip-audit JSON must contain 'dependencies'")
    return data


def _flatten_vulns(audit: dict) -> list[dict]:
    rows: list[dict] = []
    for dep in audit.get("dependencies", []):
        for vuln in dep.get("vulns", []):
            rows.append(
                {
                    "package": dep.get("name"),
                    "version": dep.get("version"),
                    "vuln": vuln,
                    "severity": _severity_bucket(vuln),
                    "has_fix": bool(vuln.get("fix_versions")),
                    "aliases": vuln.get("aliases") or [],
                }
            )
    return rows


def _load_tree(path: pathlib.Path | None) -> list[dict]:
    if path is None or not path.exists():
        return []
    data = json.loads(path.read_text(encoding="utf-8-sig"))
    return data if isinstance(data, list) else []


def _count_tree_nodes(tree: list[dict]) -> tuple[int, int]:
    direct = len(tree)
    total = 0

    def walk(nodes: list[dict]) -> None:
        nonlocal total
        for node in nodes:
            total += 1
            walk(node.get("dependencies") or [])

    walk(tree)
    transitive = max(total - direct, 0)
    return direct, transitive


def _load_outdated(path: pathlib.Path | None) -> list[dict]:
    if path is None or not path.exists():
        return []
    data = json.loads(path.read_text(encoding="utf-8-sig"))
    return data if isinstance(data, list) else []


def _load_licenses(path: pathlib.Path | None) -> list[dict]:
    if path is None or not path.exists():
        return []
    data = json.loads(path.read_text(encoding="utf-8-sig"))
    return data if isinstance(data, list) else []


def compute_metrics(
    audit_json: pathlib.Path,
    tree_json: pathlib.Path | None = None,
    outdated_json: pathlib.Path | None = None,
    licenses_json: pathlib.Path | None = None,
    baseline_audit_json: pathlib.Path | None = None,
) -> PipAuditMetrics:
    audit = _load_audit(audit_json)
    baseline = _load_audit(baseline_audit_json) if baseline_audit_json and baseline_audit_json.exists() else None
    tree = _load_tree(tree_json)
    outdated = _load_outdated(outdated_json)
    licenses = _load_licenses(licenses_json)

    deps = audit.get("dependencies", [])
    vuln_rows = _flatten_vulns(audit)
    direct, transitive = _count_tree_nodes(tree)
    total_dependencies = max(len(deps), direct + transitive, 1)

    critical = sum(1 for row in vuln_rows if row["severity"] == "critical")
    high = sum(1 for row in vuln_rows if row["severity"] == "high")
    medium = sum(1 for row in vuln_rows if row["severity"] == "medium")
    low = sum(1 for row in vuln_rows if row["severity"] == "low")
    total_vulns = len(vuln_rows)
    known_cve = sum(1 for row in vuln_rows if any(str(a).upper().startswith("CVE-") for a in row["aliases"]))
    with_fix = sum(1 for row in vuln_rows if row["has_fix"])

    vulnerable_packages = {row["package"] for row in vuln_rows if row["package"]}
    transitive_vulnerable = max(total_vulns - len(vulnerable_packages), 0)

    copyleft = sum(
        1 for item in licenses if COPYLEFT_PATTERN.search(str(item.get("license", "")))
    )
    restricted = sum(
        1 for item in licenses if RESTRICTED_PATTERN.search(str(item.get("license", "")))
    )

    outdated_count = len(outdated)
    version_lag_count = with_fix

    hidden_relationship_risk = total_vulns / max(total_dependencies, 1)
    legal_risk_proxy = known_cve
    supply_chain_risk = total_vulns
    community_vitality = (with_fix / total_vulns) if total_vulns else 1.0
    mitigation_effort = with_fix

    baseline_vulns = len(_flatten_vulns(baseline)) if baseline else 0
    alert_signal = max(total_vulns - baseline_vulns, 0)

    cve_score = critical * 25 + high * 10 + medium * 3 + low * 1
    transitive_risk_score = transitive_vulnerable * 20
    license_risk_score = copyleft * 20 + restricted * 10 + legal_risk_proxy
    trust_score = supply_chain_risk * 5
    vitality_score = (len(vulnerable_packages) / max(total_dependencies, 1)) * 100
    version_lag_score = outdated_count * 15 + version_lag_count * 5

    crit_high = critical + high
    crit_high_with_fix = sum(
        1 for row in vuln_rows if row["severity"] in {"critical", "high"} and row["has_fix"]
    )
    prioritization_coverage = (
        100.0 if crit_high == 0 else (crit_high_with_fix / crit_high) * 100.0
    )
    alert_response_rate = 100.0 if alert_signal == 0 else max(0.0, 100.0 - alert_signal * 20)

    return PipAuditMetrics(
        total_dependencies=total_dependencies,
        direct_dependencies=direct or len(deps),
        transitive_dependencies=transitive,
        total_vulnerabilities=total_vulns,
        known_cve_count=known_cve,
        critical_cve_count=critical,
        high_cve_count=high,
        medium_cve_count=medium,
        low_cve_count=low,
        vulnerabilities_with_fix=with_fix,
        transitive_vulnerable_count=transitive_vulnerable,
        hidden_relationship_risk=hidden_relationship_risk,
        legal_risk_proxy=legal_risk_proxy,
        supply_chain_risk=supply_chain_risk,
        community_vitality_score=community_vitality * 100.0,
        mitigation_effort=mitigation_effort,
        alert_signal=alert_signal,
        version_lag_count=version_lag_count,
        outdated_dependencies=outdated_count,
        copyleft_license_count=copyleft,
        restricted_license_count=restricted,
        cve_score=float(cve_score),
        transitive_risk_score=float(transitive_risk_score),
        license_risk_score=float(license_risk_score),
        trust_score=float(trust_score),
        vitality_score=float(vitality_score),
        prioritization_coverage_percent=prioritization_coverage,
        alert_response_rate_percent=alert_response_rate,
        version_lag_score=float(version_lag_score),
        transitive_dependency_score=max(0.0, 100.0 - transitive_risk_score),
        license_compliance_score=max(0.0, 100.0 - license_risk_score),
        supply_chain_score=max(0.0, 100.0 - trust_score),
        dependency_health_score=max(0.0, 100.0 - vitality_score),
        risk_prioritization_score=prioritization_coverage,
        continuous_monitoring_score=alert_response_rate,
        vulnerability_detection_score=max(0.0, 100.0 - cve_score),
        outdated_dependency_score=max(0.0, 100.0 - version_lag_score),
    )


def compute_normalized_scores(metrics: PipAuditMetrics) -> dict[str, float]:
    return {
        "Transitive Dependency Analysis": metrics.transitive_dependency_score,
        "License Compliance Testing": metrics.license_compliance_score,
        "Supply Chain Security Analysis": metrics.supply_chain_score,
        "Dependency Health Monitoring": metrics.dependency_health_score,
        "Risk Prioritization": metrics.risk_prioritization_score,
        "Continuous Dependency Monitoring": metrics.continuous_monitoring_score,
        "Vulnerability Dependency Detection": metrics.vulnerability_detection_score,
        "Outdated Dependency Detection": metrics.outdated_dependency_score,
    }


def export_dashboard_payload(metrics: PipAuditMetrics) -> dict:
    scores = compute_normalized_scores(metrics)
    return {
        "tool": "pip-audit",
        "target_repository": "sample_subject",
        "scores": scores,
        "metrics": [
            {
                "classification": name,
                "value": f"{int(round(score))}/100",
                "result": "PASS" if score >= 80.0 else "FAIL",
                "coverage_percent": round(score, 2),
            }
            for name, score in scores.items()
        ],
    }


def collect_licenses(requirements: pathlib.Path, python_exe: str = sys.executable) -> list[dict]:
    cmd = [
        python_exe,
        "-c",
        (
            "import json, subprocess, sys, importlib.metadata as m; "
            "subprocess.check_call([sys.executable, '-m', 'pip', 'install', '-r', "
            f"r'{requirements.as_posix()}', '-q']); "
            "rows=[]; "
            "[rows.append({'name': d.metadata['Name'], 'license': d.metadata.get('License', 'UNKNOWN')}) "
            "for d in m.distributions() if d.metadata.get('Name')]; "
            "print(json.dumps(rows))"
        ),
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
    if proc.returncode != 0:
        return []
    return json.loads(proc.stdout or "[]")


def _print_report(metrics: PipAuditMetrics) -> None:
    scores = compute_normalized_scores(metrics)
    print("=" * 72)
    print("pip-audit Dependency Risk (SCA) Report")
    print("=" * 72)
    print(f"Dependencies: {metrics.total_dependencies} (direct={metrics.direct_dependencies}, transitive={metrics.transitive_dependencies})")
    print(f"Vulnerabilities: {metrics.total_vulnerabilities} (CVE={metrics.known_cve_count})")
    print()
    for name, score in scores.items():
        status = "PASS" if score >= 80.0 else "FAIL"
        print(f"  {name:<40} {score:6.2f}/100  {status}")


def main(argv: Iterable[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--audit-json", type=pathlib.Path, required=True)
    parser.add_argument("--tree-json", type=pathlib.Path, default=None)
    parser.add_argument("--outdated-json", type=pathlib.Path, default=None)
    parser.add_argument("--licenses-json", type=pathlib.Path, default=None)
    parser.add_argument("--baseline-audit-json", type=pathlib.Path, default=None)
    parser.add_argument("--output-json", type=pathlib.Path, default=None)
    parser.add_argument("--dashboard-json", type=pathlib.Path, default=None)
    args = parser.parse_args(list(argv) if argv is not None else None)

    metrics = compute_metrics(
        args.audit_json,
        tree_json=args.tree_json,
        outdated_json=args.outdated_json,
        licenses_json=args.licenses_json,
        baseline_audit_json=args.baseline_audit_json,
    )
    _print_report(metrics)

    payload = asdict(metrics)
    payload["normalized_scores"] = compute_normalized_scores(metrics)
    payload["dashboard_export"] = export_dashboard_payload(metrics)

    if args.output_json:
        args.output_json.parent.mkdir(parents=True, exist_ok=True)
        args.output_json.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        print(f"\nWrote {args.output_json}")
    if args.dashboard_json:
        args.dashboard_json.parent.mkdir(parents=True, exist_ok=True)
        args.dashboard_json.write_text(
            json.dumps(export_dashboard_payload(metrics), indent=2), encoding="utf-8"
        )
        print(f"Wrote {args.dashboard_json}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
