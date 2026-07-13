# Python Tool Testing — pip-audit

Security White Box **Dependency Risk (SCA)** metric validation using **pip-audit**, aligned with *Testable Strategy & Metrics Reference v3.0*.

## Tool + Metric

| Field | Value |
|-------|-------|
| **Tool** | [pip-audit](https://github.com/pypa/pip-audit) |
| **Strategy** | Security White-box Testing → Dependency Risk (SCA) |
| **Training subject** | `sample_subject/` (clean pinned dependencies — **100/100**) |
| **GitHub repo** | https://github.com/visvantha-testable/python-tool-testing-pip-audit |

## 8 Dashboard Metrics

| L4 Classification | L5 Metric |
|-------------------|-----------|
| Transitive Dependency Analysis | Hidden Relationship Mapping |
| License Compliance Testing | Legal Risk Validation |
| Supply Chain Security Analysis | Trust Integrity Verification |
| Dependency Health Monitoring | Community Vitality Tracking |
| Risk Prioritization | Mitigation Effort Ranking |
| Continuous Dependency Monitoring | Real-Time Alerting |
| Vulnerability Dependency Detection | Known CVE Count |
| Outdated Dependency Detection | Version Lag Assessment |

## Quick Start (100/100 certification)

```powershell
python -m pip install -r requirements.txt
.\run_pip_audit_analysis.ps1
python validate_metric_coverage.py --metrics-json pip_audit_metrics.json
.\verify_100_percent.ps1
```

## Execution trigger

| Input | Value |
|-------|-------|
| **Requirements file** | `sample_subject/requirements.txt` |
| **pip-audit command** | `python -m pip_audit -r sample_subject/requirements.txt -f json` |
| **One-shot script** | `.\run_pip_audit_analysis.ps1` |

See `config/execution_trigger.json` for the full step sequence and expected output.

## Expected metrics (after pipeline)

| Metric | Expected value |
|--------|----------------|
| Dependencies (total / direct / transitive) | 37 / 3 / 34 |
| Vulnerabilities / CVEs | 0 / 0 |
| Outdated packages | 0 |
| All 8 SCA dashboard scores | **100/100 PASS** |
| Metric coverage | **8/8 complete** (`metric_coverage_complete: true`) |

See **[METRICS_COVERAGE.md](METRICS_COVERAGE.md)** for raw-parameter mapping and derivation formulas.

## Project layout

```
python-tool-testing-pip-audit/
├── pip_audit_metrics.py          # 8-metric extractor (0-100 scores)
├── validate_metric_coverage.py   # Verifies all 8 metrics covered
├── run_pip_audit_analysis.ps1    # End-to-end pipeline
├── METRICS_COVERAGE.md           # Full metric → raw data mapping
├── sca_metric_evidence.json      # Per-metric evidence (generated)
├── sample_subject/               # Clean training dependencies
├── config/                       # Mapping + trigger + baseline data
│   ├── metric_coverage.json      # 8-metric machine-readable map
│   └── golden_baseline_pip_audit.json
├── scripts/                      # Platform export + verify + collect
│   └── collect_artifacts.py      # Collects all 5 raw SCA artifacts
├── artifacts/training/           # Golden training outputs
└── tests/
```

## Testing team

See **[TESTING_TEAM.md](TESTING_TEAM.md)** for platform submission instructions.
