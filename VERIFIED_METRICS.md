> **Evidence reconciliation (2026-11-11; historical phase/snapshot):** Historical results below retain their original dates and denominators. Latest tested Phase 1–16 development SHA is `43a72c8984bf9a472b9055d4f9e84cc759f61718` ([CI](https://github.com/poojakira/mcp-agent-security-gateway/actions/runs/42971171992): 1,211 passed, 6 skipped per Python version), **not** a merged or production-approved release. Offline research tests require no paid provider or provider-issued API keys; deployed HTTP authentication and unverified real credential revocation remain separate. See [operating restrictions](PRODUCTION.md) and [release evidence](docs/review/PHASE1_16_RELEASE_CANDIDATE_NO_GO_20261110.md).

# Verified Metrics — Dated October 2026 Baseline

> **Evidence boundary (2026-11-09):** These test and coverage figures belong to the listed October source commits and runners, **not** to the unmerged phases 1–16 integration head or any deployed product. For integration validation, inspect [PR #167](https://github.com/poojakira/mcp-agent-security-gateway/pull/167) and its exact-head GitHub Actions. Passing CI is not production release authorization.

## Full Python suite

| Run | Tests passed | Statement coverage | Evidence |
|---|---:|---:|---|
| Local Windows Python 3.12.10, October 12, 2026 *(for reproducibility reference)* | 782 | 81.47%: 5,657 statements / 1,048 missed | Local run at `b6d7122`; 26-statement gap due to Linux-only paths; see platform note below |
| **Hosted Linux Python 3.12.15, October 13, 2026** | **782** | **81.93%**: 5,657 statements / 1,022 missed | [GitHub Actions run 38462601803](https://github.com/poojakira/mcp-agent-security-gateway/actions/runs/38462601803), commit `c75c52db` — **authoritative for this dated October snapshot only** |

**Platform boundary:** These are different environments and dates. Of the 26 additional missed Windows statements, 22 are in `defense10/network_monitor.py` (Windows 57 missed versus Linux 35) and 4 in `production/identity_shipper.py` (Windows 56 missed versus Linux 52). The source includes Linux-only `/proc/net` reading and POSIX-only directory fsync logic. Both complete Python suites passed; coverage is **not a detector effectiveness percentage**.

**Scope:** The current runtime has **69 named prompt-injection signatures**; this is a code-inventory count, not independently measured precision/recall. The repository includes 9 Elastic rule records and 21 core SIEM tests, not evidence of a live SOC. The local Python policy enforcement suite passed 15 tests. Rego/OPA verification was not performed in this audit. Only tool traffic routed through a supported integration can be inspected or blocked. The connection-table monitor is observational, not a packet-filtering firewall. The eBPF code was not demonstrated as deployed in these test runs.

## Reproduce local Windows evidence

With Python development dependencies and `pytest-cov` available at the cited checkout. Select Python 3.12 explicitly; use **Python 3.12.10** when exact patch-level reproduction is required:

```powershell
$env:PYTHONPATH = (Join-Path (Get-Location) 'src')
$env:PYTHONDONTWRITEBYTECODE = '1'
$env:PYTEST_DISABLE_PLUGIN_AUTOLOAD = '1'
py -3.12 -m pytest tests -q -p pytest_cov -p no:cacheprovider --override-ini addopts='' --cov=mcp_monitor --cov-report=term --disable-warnings
```

## Historical evidence

The previous **723 tests / 81.91% coverage / 55-signature** snapshot at `008775c8878cc70c50247baa223da3256e093316` ([CI run 37184196303](https://github.com/poojakira/mcp-agent-security-gateway/actions/runs/37184196303)) is preserved in the [dated historical archive](docs/archive/HISTORICAL_EVIDENCE.md), not presented as the current result.
