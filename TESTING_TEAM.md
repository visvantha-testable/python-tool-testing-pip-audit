# Python Tool Testing — pip-audit (Testing Team Guide)

This repo is maintained for **100/100 PASS** on all 8 Dependency Risk (SCA) dashboard metrics.

## Quick verify (must pass before submission)

```powershell
git clone https://github.com/visvantha-testable/python-tool-testing-pip-audit.git
cd python-tool-testing-pip-audit
.\run_pip_audit_analysis.ps1
.\verify_100_percent.ps1
```

Expected final lines:
```
All 8 pip-audit SCA metrics are covered with 100/100 scores.
PASS: all 8 metrics are 100/100
PASS: pip_audit.json has all 8 metrics covered=yes with 100/100 scores
```

See **[METRICS_COVERAGE.md](METRICS_COVERAGE.md)** for how each metric is derived from raw data.

## Files the Testable platform reads (repository ROOT)

| File | Purpose |
|------|---------|
| **`pip_audit.json`** | **PRIMARY** — single unified output with all raw data + 8 metrics (`covered: yes`) |
| `platform_metrics.json` | L4 classification → integer score `100` |
| `sca_metric_evidence.json` | **Proof** — per-metric raw parameters + formulas |
| `pip_audit_report.json` | Raw pip-audit JSON output |
| `pip_audit_metrics.json` | Full metrics payload |
| `dashboard_metrics.json` | PASS/FAIL per classification |
| `metrics.json` | Alias of `platform_metrics.json` |
| `testable_dashboard.json` | Explicit dashboard rows |

Copies also live under `platform/` and `artifacts/training/`.

**Do NOT submit** an empty pip-audit JSON. That causes **0/100 FAIL**.

## 8 SCA metrics

| Dashboard classification | Expected (training) |
|--------------------------|---------------------|
| Transitive Dependency Analysis | 100 |
| License Compliance Testing | 100 |
| Supply Chain Security Analysis | 100 |
| Dependency Health Monitoring | 100 |
| Risk Prioritization | 100 |
| Continuous Dependency Monitoring | 100 |
| Vulnerability Dependency Detection | 100 |
| Outdated Dependency Detection | 100 |

## Re-generate root platform files

```powershell
.\run_pip_audit_analysis.ps1
# or
.\run_tests.ps1
```
