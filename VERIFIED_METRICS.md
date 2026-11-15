> **Verification update (2026-11-15 UTC; exact source SHA):** Gateway commit `8049ec46e8337ee4eabff9cfa97ffe4663f4febc` passed [nine-job Phase 1–16 integrated security CI](https://github.com/poojakira/mcp-agent-security-gateway/actions/runs/43748347243) and [Poster Artifact Parity](https://github.com/poojakira/mcp-agent-security-gateway/actions/runs/43748347212). The earlier PDF raster mismatch was traced to continuously animated SVG print frames; the print stylesheet now freezes animations, and the three committed poster binaries were regenerated ([reconciliation run](https://github.com/poojakira/mcp-agent-security-gateway/actions/runs/43748301101)). Historical 782/81.93%, 1,245/6 and 1,246/6 figures belong only to their cited dated CI runs; the final nine-job run is **not** a newly measured coverage figure. This note records successful verification of the cited SHA, not automatic certification of later edits. **PRODUCTION NO-GO** remains in force.

> **Latest verified development evidence (2026-11-14 Phoenix / 2026-11-15 UTC):** [Integrated run 43657894182](https://github.com/poojakira/mcp-agent-security-gateway/actions/runs/43657894182) on audit commit `2158ab58e4a07a5c49b70c659996653a92f661c8`: **1,245 passed / 6 skipped per Python 3.10, 3.11 and 3.12; 5/5 jobs green**. This run is newer than the pinned poster evidence manifest, which intentionally references the earlier same-SHA pair [integrated 43657370973](https://github.com/poojakira/mcp-agent-security-gateway/actions/runs/43657370973) and [poster 43657370960](https://github.com/poojakira/mcp-agent-security-gateway/actions/runs/43657370960) on `a24f92c17f93d5c150eafe4ba7dce507ecb534b6`. The current documentation-fix commit is not covered by those historical runs. **PRODUCTION NO-GO.**

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


### November 15, 2026 verification boundary

The Phase 1–16 integrated candidate completed all nine CI jobs in [run 43744627479](https://github.com/poojakira/mcp-agent-security-gateway/actions/runs/43744627479), including real Docker and official MCP filesystem integration. This does not supersede separately dated historical test-count or coverage measurements and is not a production certification. Regenerated poster binaries were committed at `f1b8ee9574ed33683ab4149bb797ac45e97d090e`, but later exact-head poster parity failed intermittently on PDF raster pixels despite matching text and PNG pixels. See [remediation tracker](docs/review/PHASE1_16_REMEDIATION_TRACKER_20261114.md). **Production NO-GO:** deployment CNI enforcement, issuer-side credential revocation, end-to-end authorization non-bypassability, and external side-effect reconciliation remain unverified.
