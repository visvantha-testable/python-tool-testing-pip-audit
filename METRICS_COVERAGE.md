# pip-audit SCA — Full Metric Coverage (8/8)

This document proves **all 8 Dependency Risk (SCA) dashboard metrics** are covered, derived, and scored **100/100** in this training repo.

## Important: pip-audit does NOT emit dashboard scores

pip-audit native JSON only contains:

```json
{
  "dependencies": [{ "name": "...", "version": "...", "vulns": [] }],
  "fixes": []
}
```

**Scores out of 100** are produced by this repo's pipeline:

```
pip-audit JSON  ──┐
pipdeptree JSON ──┼──► pip_audit_metrics.py ──► platform_metrics.json (8 scores)
outdated JSON   ──┤
licenses JSON   ──┤
baseline JSON   ──┘
```

## Metric coverage matrix

| # | L4 Classification | L5 Metric | pip-audit native? | Required artifact | Score formula |
|---|-------------------|-----------|-------------------|-------------------|---------------|
| 1 | Transitive Dependency Analysis | Hidden Relationship Mapping | No | `dependency_tree.json` | `100 - transitive_vulnerable×20` |
| 2 | License Compliance Testing | Legal Risk Validation | No | `licenses.json` | `100 - (copyleft×20 + restricted×10 + CVE_proxy)` |
| 3 | Supply Chain Security Analysis | Trust Integrity Verification | Yes (vulns) | `pip_audit_report.json` | `100 - total_vulns×5` |
| 4 | Dependency Health Monitoring | Community Vitality Tracking | Yes (vulns) | `pip_audit_report.json` | `100 - (vuln_packages/total)×100` |
| 5 | Risk Prioritization | Mitigation Effort Ranking | Yes (fix_versions) | `pip_audit_report.json` | `% crit/high with fixes` |
| 6 | Continuous Dependency Monitoring | Real-Time Alerting | No | `baseline_pip_audit.json` | `100 - alert_signal×20` |
| 7 | Vulnerability Dependency Detection | Known CVE Count | Yes | `pip_audit_report.json` | `100 - (crit×25 + high×10 + med×3 + low×1)` |
| 8 | Outdated Dependency Detection | Version Lag Assessment | No | `outdated.json` | `100 - (outdated×15 + fixable_vulns×5)` |

Machine-readable mapping: **`config/metric_coverage.json`**

## Raw parameters per metric

### 1. Transitive Dependency Analysis
- `transitive_dependencies` — count from pipdeptree
- `transitive_vulnerable_count` — vulns in transitive packages
- `hidden_relationship_risk` — vulns / total deps

### 2. License Compliance Testing
- `copyleft_license_count` — GPL/AGPL/SSPL detected
- `restricted_license_count` — Proprietary/UNLICENSED
- `legal_risk_proxy` — CVE count used as legal risk proxy

### 3. Supply Chain Security Analysis
- `total_vulnerabilities` — from pip-audit
- `supply_chain_risk` — equals total vulns

### 4. Dependency Health Monitoring
- `community_vitality_score` — fix availability ratio
- `vitality_score` — vulnerable package ratio × 100

### 5. Risk Prioritization
- `critical_cve_count`, `high_cve_count`
- `vulnerabilities_with_fix` — vulns with `fix_versions`
- `prioritization_coverage_percent`

### 6. Continuous Dependency Monitoring
- `alert_signal` — new vulns since baseline
- `alert_response_rate_percent`

### 7. Vulnerability Dependency Detection
- `known_cve_count` — CVE-* aliases in vulns
- Severity buckets: critical, high, medium, low

### 8. Outdated Dependency Detection
- `outdated_dependencies` — from `pip list --outdated`
- `version_lag_count` — vulns with available fixes

## Platform files (repository ROOT)

| File | Purpose |
|------|---------|
| `platform_metrics.json` | Primary — 8 integer scores + coverage flags |
| `sca_metric_evidence.json` | Per-metric raw parameters + formulas + proof |
| `pip_audit_report.json` | Raw pip-audit output + embedded scores |
| `pip_audit_metrics.json` | Full metrics payload + `metric_evidence` |
| `testable_dashboard.json` | Dashboard rows with `metric_coverage_complete: true` |

## Verification gates

```powershell
.\run_pip_audit_analysis.ps1          # Collect all 5 artifacts + export
python validate_metric_coverage.py    # Assert 8/8 covered + 100/100
.\verify_100_percent.ps1                # Assert all scores == 100
python -m pytest tests/ -q            # Unit tests
```

Expected output:
```
All 8 pip-audit SCA metrics are covered with 100/100 scores.
PASS: all 8 metrics are 100/100
```

## Why isolated venv matters

Run pip-audit against **`sample_subject/requirements.txt`** inside **`sample_subject/.venv`**.

Scanning the global Python environment includes hundreds of outdated/tool packages and breaks **Outdated** and **License** scores.

## Training subject pins (100/100)

```
packaging==25.0
platformdirs==4.10.0
typing_extensions==4.16.0
```

All MIT/BSD — zero CVEs, zero outdated, zero copyleft licenses.
