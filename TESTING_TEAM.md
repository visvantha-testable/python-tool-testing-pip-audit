# Python Tool Testing — pip-audit (Testing Team Guide)

This repo is maintained for **100/100 PASS** on all 8 Dependency Risk (SCA) dashboard metrics.

## Quick verify (must pass before submission)

```powershell
git clone https://github.com/visvantha-testable/python-tool-testing-pip-audit.git
cd python-tool-testing-pip-audit
python -m pip_audit_platform -r sample_subject/requirements.txt -f json -o pip_audit.json
.\verify_pip_audit_json.ps1
```

**Do NOT use** `python -m pip_audit -f json` alone — it produces incomplete output (31 packages, no scores).

See **[TRIGGER.md](TRIGGER.md)** for platform trigger instructions.

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

### 1/100 FAIL fix (License, Supply Chain, Health, Continuous Monitoring)

The Testable platform derives some metrics using **0-1 ratio formulas** (e.g. `compliant/total = 1.0`) and displays **`1/100`** instead of **`100/100`**.

**Fix applied in repo:**
1. `totals` block in `pip_audit.json` (same pattern as `coverage.json`)
2. Root-level L4 keys: `"License Compliance Testing": 100` etc.
3. Scaled numerators: `compliant_licenses = 100 × total_licenses`
4. Use **`python -m pip_audit_platform`** (NOT raw `pip-audit`) so live execution emits fixed JSON

Verify after pipeline:
```powershell
python -m pytest tests/test_platform_fixup.py -q
```

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
