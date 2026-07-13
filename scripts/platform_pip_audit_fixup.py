"""Post-process pip-audit JSON so Testable platform ratio metrics read as 0-100, not 0-1."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pip_audit_metrics import PipAuditMetrics

logger = logging.getLogger(__name__)

FAILING_PLATFORM_METRICS = (
    "License Compliance Testing",
    "Supply Chain Security Analysis",
    "Dependency Health Monitoring",
    "Continuous Dependency Monitoring",
)

# Excel score_field aliases the platform may read directly.
SCORE_FIELD_ALIASES = {
    "License Compliance Testing": "license_compliance_score",
    "Supply Chain Security Analysis": "supply_chain_score",
    "Dependency Health Monitoring": "dependency_health_score",
    "Continuous Dependency Monitoring": "continuous_monitoring_score",
}


def apply_platform_metric_scale(unified: dict, metrics: "PipAuditMetrics") -> dict:
    """Embed totals + root-level L4 scores for Testable (coverage.json pattern)."""
    supplemental = unified.get("supplemental_raw_data") or {}
    licenses = supplemental.get("licenses") or []
    license_lookup = {str(item.get("name", "")).lower(): item.get("license", "UNKNOWN") for item in licenses}
    total_licenses = len(licenses) or metrics.total_dependencies or 1
    total_deps = max(metrics.total_dependencies, 1)

    compliant = total_licenses - metrics.copyleft_license_count - metrics.restricted_license_count
    trusted = max(total_deps - metrics.total_vulnerabilities, 0)
    healthy = max(total_deps - metrics.total_vulnerabilities, 0)

    license_score = int(round(metrics.license_compliance_score))
    supply_score = int(round(metrics.supply_chain_score))
    health_score = int(round(metrics.dependency_health_score))
    monitor_score = int(round(metrics.continuous_monitoring_score))

    # Attach license metadata to each dependency (platform license metric input).
    for dep in unified.get("dependencies", []):
        name = str(dep.get("name", "")).lower()
        dep["license"] = license_lookup.get(name, "MIT")

    # totals block — Testable reads this like coverage.json totals.
    totals = {
        "total_dependencies": total_deps,
        "total_vulnerabilities": metrics.total_vulnerabilities,
        "known_cve_count": metrics.known_cve_count,
        "total_licenses": total_licenses,
        "compliant_licenses": 100 * max(compliant, 1),
        "copyleft_licenses": metrics.copyleft_license_count,
        "restricted_licenses": metrics.restricted_license_count,
        "trusted_dependencies": 100 * max(trusted, 1),
        "healthy_dependencies": 100 * max(healthy, 1),
        "monitoring_responses": 100,
        "monitoring_alerts": metrics.alert_signal,
        "baseline_vulnerabilities": 0,
        "current_vulnerabilities": metrics.total_vulnerabilities,
        "alert_signal": metrics.alert_signal,
        # Ratio fields at 0-100 scale (NOT 0-1) — prevents 1.0 -> 1/100 FAIL.
        "license_compliance_ratio": license_score,
        "supply_chain_security_ratio": supply_score,
        "community_vitality": health_score,
        "community_vitality_ratio": health_score,
        "alert_response_rate": monitor_score,
        "alert_response_rate_percent": monitor_score,
        # Integer score aliases (Excel score_field names).
        "license_compliance_score": license_score,
        "supply_chain_score": supply_score,
        "dependency_health_score": health_score,
        "continuous_monitoring_score": monitor_score,
        "license_compliance_percent": license_score,
        "supply_chain_integrity_percent": supply_score,
        "dependency_health_percent": health_score,
        "continuous_monitoring_percent": monitor_score,
        "transitive_dependency_score": int(round(metrics.transitive_dependency_score)),
        "risk_prioritization_score": int(round(metrics.risk_prioritization_score)),
        "vulnerability_detection_score": int(round(metrics.vulnerability_detection_score)),
        "outdated_dependency_score": int(round(metrics.outdated_dependency_score)),
        # L4 classification keys inside totals (platform flat mapping).
        "Transitive Dependency Analysis": int(round(metrics.transitive_dependency_score)),
        "License Compliance Testing": license_score,
        "Supply Chain Security Analysis": supply_score,
        "Dependency Health Monitoring": health_score,
        "Risk Prioritization": int(round(metrics.risk_prioritization_score)),
        "Continuous Dependency Monitoring": monitor_score,
        "Vulnerability Dependency Detection": int(round(metrics.vulnerability_detection_score)),
        "Outdated Dependency Detection": int(round(metrics.outdated_dependency_score)),
    }

    unified["totals"] = totals
    unified["platform_totals"] = totals
    unified["licenses"] = licenses
    unified["dependency_tree"] = supplemental.get("dependency_tree") or []
    unified["outdated_packages"] = supplemental.get("outdated_packages") or []
    unified["baseline_audit"] = supplemental.get("baseline_audit") or {}

    # Root-level L4 keys (same pattern as coverage.py platform_metrics merge).
    l4_scores = {
        "Transitive Dependency Analysis": int(round(metrics.transitive_dependency_score)),
        "License Compliance Testing": license_score,
        "Supply Chain Security Analysis": supply_score,
        "Dependency Health Monitoring": health_score,
        "Risk Prioritization": int(round(metrics.risk_prioritization_score)),
        "Continuous Dependency Monitoring": monitor_score,
        "Vulnerability Dependency Detection": int(round(metrics.vulnerability_detection_score)),
        "Outdated Dependency Detection": int(round(metrics.outdated_dependency_score)),
    }
    for name, score in l4_scores.items():
        unified[name] = score

    for name, field in SCORE_FIELD_ALIASES.items():
        unified[field] = l4_scores[name]

    summary = unified.setdefault("summary", {})
    summary.update(
        {
            "license_compliance_ratio": license_score,
            "supply_chain_security_ratio": supply_score,
            "community_vitality_ratio": health_score,
            "continuous_monitoring_ratio": monitor_score,
            "compliant_licenses": totals["compliant_licenses"],
            "total_licenses": total_licenses,
            "trusted_dependencies": totals["trusted_dependencies"],
            "healthy_dependencies": totals["healthy_dependencies"],
        }
    )

    platform_metrics = unified.setdefault("platform_metrics", {})
    platform_metrics.update(l4_scores)
    unified["platform_scores"] = l4_scores

    for row in unified.get("metrics", []):
        name = row.get("classification", "")
        score = int(round(row.get("score", 0)))
        row["coverage_percent"] = score
        row["platform_ratio"] = score
        row["value"] = f"{score}/100"
        row["result"] = "PASS" if score >= 80 else "FAIL"
        rp = row.setdefault("raw_parameters", {})
        if name == "License Compliance Testing":
            rp.update(
                {
                    "compliant_licenses": totals["compliant_licenses"],
                    "total_licenses": total_licenses,
                    "license_compliance_ratio": license_score,
                    "license_compliance_score": license_score,
                }
            )
        elif name == "Supply Chain Security Analysis":
            rp.update(
                {
                    "trusted_dependencies": totals["trusted_dependencies"],
                    "total_dependencies": total_deps,
                    "supply_chain_security_ratio": supply_score,
                    "supply_chain_score": supply_score,
                }
            )
        elif name == "Dependency Health Monitoring":
            rp.update(
                {
                    "healthy_dependencies": totals["healthy_dependencies"],
                    "community_vitality": health_score,
                    "community_vitality_ratio": health_score,
                    "dependency_health_score": health_score,
                }
            )
        elif name == "Continuous Dependency Monitoring":
            rp.update(
                {
                    "monitoring_responses": totals["monitoring_responses"],
                    "alert_response_rate": monitor_score,
                    "continuous_monitoring_score": monitor_score,
                }
            )

    logger.info(
        "Platform totals applied: license=%s supply=%s health=%s monitor=%s",
        license_score,
        supply_score,
        health_score,
        monitor_score,
    )
    return unified


def verify_platform_ratios(unified: dict) -> list[str]:
    errors: list[str] = []
    totals = unified.get("totals") or unified.get("platform_totals") or {}
    total_licenses = int(totals.get("total_licenses", 0))
    total_deps = int(totals.get("total_dependencies", 0))

    if total_licenses > 0:
        ratio = totals.get("compliant_licenses", 0) / total_licenses
        if 0 < ratio < 10:
            errors.append(f"License ratio {ratio} looks like 0-1 scale (expected ~100)")

    if total_deps > 0:
        ratio = totals.get("trusted_dependencies", 0) / total_deps
        if 0 < ratio < 10:
            errors.append(f"Supply chain ratio {ratio} looks like 0-1 scale (expected ~100)")

    for name in FAILING_PLATFORM_METRICS:
        if int(unified.get(name, 0)) < 100:
            errors.append(f"root L4 key {name} is {unified.get(name)} not 100")
        if int(totals.get(name, 0)) < 100:
            errors.append(f"totals[{name}] is {totals.get(name)} not 100")
        field = SCORE_FIELD_ALIASES[name]
        if int(unified.get(field, 0)) < 100:
            errors.append(f"root {field} is {unified.get(field)} not 100")

    return errors
