# Verified Metrics

## Latest quantified verified code snapshot

**Code commit:** `8427f9ecafd3438a86775a7ceaf809f4ee051b5b`  
**Successful full CI:** https://github.com/poojakira/mcp-agent-security-gateway/actions/runs/36783059917

Python 3.12 CI reports:

```text
718 passed
TOTAL 5524 statements, 969 missed
Total coverage: 82.46%
```

The Python 3.10 and 3.11 test jobs also completed successfully.

| Claim | Verified snapshot value | Evidence boundary |
|---|---:|---|
| Automated tests | **718 passed** | Cited CI snapshot |
| Statement coverage | **82.46%** | Python 3.12 CI |
| Prompt-injection collection entries | **55** | Named collection at cited snapshot |
| Elastic rule records | **9** | `detection_rules/elastic_rules.toml` |
| Core SIEM tests | **21** | `tests/test_siem.py` |
| SIEM scenario tests | **12** | `tests/test_siem_scenarios.py` |

The cited CI also completed Ruff/format checks, Pyright, Bandit, pip-audit, CodeQL, Windows control-plane validation, security scanning, SBOM steps, and Docker build validation successfully.

## Claim boundary

These measurements are repository/test evidence. They do not establish production uptime, population-level detector accuracy, or a live SOC deployment. Local and synthetic benchmarks must remain labeled as environment- or fixture-scoped.

## Reproduce

```powershell
git checkout 8427f9ecafd3438a86775a7ceaf809f4ee051b5b
python -m pip install -e ".[dev,server]"
$env:PYTHONPATH="src"
python -m pytest tests -q --cov=mcp_monitor --cov-report=term
```
