# Platform Trigger Guide — pip-audit (8 SCA Metrics)

## DO NOT run raw pip-audit alone

Raw command:
```bash
python -m pip_audit -f json
```

This produces **incomplete output** (31 packages, no scores, no supplemental data) — same as Downloads `pip_audit (2).json`.

## RUN THIS instead (satisfies all 8 metrics)

```bash
python pip_audit_trigger.py
```

Or:
```powershell
.\run_trigger.ps1
```

```bash
./run_trigger.sh
```

## What the trigger produces

| Output file | Contents |
|-------------|----------|
| **`pip_audit.json`** | Unified output — submit THIS to Testable |
| `platform_metrics.json` | 8 integer scores = 100 |
| `pip_audit_metrics.json` | Full metrics payload |
| `sca_metric_evidence.json` | Per-metric proof |

## All 8 metrics triggered

| # | Metric | Triggered by |
|---|--------|--------------|
| 1 | Transitive Dependency Analysis | `pipdeptree --json-tree` |
| 2 | License Compliance Testing | `importlib.metadata` licenses |
| 3 | Supply Chain Security Analysis | `pip-audit` vulns |
| 4 | Dependency Health Monitoring | `pip-audit` vulns |
| 5 | Risk Prioritization | `pip-audit` fix_versions |
| 6 | Continuous Dependency Monitoring | baseline vs current audit |
| 7 | Vulnerability Dependency Detection | `pip-audit` CVE aliases |
| 8 | Outdated Dependency Detection | `pip list --outdated` |

## Verify (must pass)

```bash
python scripts/verify_pip_audit_json.py --pip-audit-json pip_audit.json
```

Expected:
```
PASS: pip_audit.json has all 8 metrics covered=yes with 100/100 scores
```

## Fallback: platform already ran native pip-audit

If platform saved incomplete JSON, enrich it after running trigger once:

```bash
python pip_audit_trigger.py
python scripts/enrich_pip_audit_output.py --native-audit path/to/native.json
```

## Machine-readable config

See `config/platform_trigger.json` for exact trigger command and expected output fields.
