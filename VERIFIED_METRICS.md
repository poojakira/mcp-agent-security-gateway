# Verified Metrics — Current Evidence

## Full Python suite

| Run | Tests passed | Statement coverage | Evidence |
|---|---:|---:|---|
| Local Windows Python 3.12.10, October 12, 2026 | **782** | **81.47%**: 5,657 statements / 1,048 missed | Published main checkout `b6d7122ab6f008bd24fa3fcff933618e051aaae1`; local pytest + coverage run |
| Hosted Linux Python 3.12.15, October 10, 2026 | **782** | **81.93%**: 5,657 statements / 1,022 missed | [GitHub Actions run 38012954359](https://github.com/poojakira/mcp-agent-security-gateway/actions/runs/38012954359) |

**Platform boundary:** These are different environments and dates. Of the 26 additional missed Windows statements, 22 are in `defense10/network_monitor.py` (Windows 57 missed versus Linux 35) and 4 in `production/identity_shipper.py` (Windows 56 missed versus Linux 52). The source includes Linux-only `/proc/net` reading and POSIX-only directory fsync logic. Both complete Python suites passed; coverage is **not a detector effectiveness percentage**.

**Scope:** The current runtime has **69 named prompt-injection signatures**; this is a code-inventory count, not independently measured precision/recall. The repository includes 9 Elastic rule records and 21 core SIEM tests, not evidence of a live SOC. The local Python policy enforcement suite passed 15 tests. Rego/OPA verification was not performed in this audit. Only tool traffic routed through a supported integration can be inspected or blocked. The connection-table monitor is observational, not a packet-filtering firewall. The eBPF code was not demonstrated as deployed in these test runs.

## Reproduce local Windows evidence

With Python development dependencies and `pytest-cov` available at the cited checkout:

```powershell
$env:PYTHONPATH = (Join-Path (Get-Location) 'src')
$env:PYTHONDONTWRITEBYTECODE = '1'
$env:PYTEST_DISABLE_PLUGIN_AUTOLOAD = '1'
py -m pytest tests -q -p pytest_cov -p no:cacheprovider --override-ini addopts='' --cov=mcp_monitor --cov-report=term --disable-warnings
```

## Historical evidence

The previous **723 tests / 81.91% coverage / 55-signature** snapshot at `008775c8878cc70c50247baa223da3256e093316` ([CI run 37184196303](https://github.com/poojakira/mcp-agent-security-gateway/actions/runs/37184196303)) is preserved in the [dated historical archive](docs/archive/HISTORICAL_EVIDENCE.md), not presented as the current result.
