# Reproducibility — MCP Gateway Integration Poster

**Reviewed PR #167 source head:** `25bc77445df5fa5fdcdff64478b0f63079dbb8ca`  
**CI-tested synthetic merge commit:** `2ab3380d1457cdcb16c3ba143db9d8e339b057e2`  
**GitHub Actions CI:** [42748742036](https://github.com/poojakira/mcp-agent-security-gateway/actions/runs/42748742036), 2026-11-10 UTC.

To inspect the source candidate and run the suite with local dependencies:

```bash
git clone https://github.com/poojakira/mcp-agent-security-gateway.git
cd mcp-agent-security-gateway
git fetch origin integration/phase1-16-remediation-20261109
git checkout 25bc77445df5fa5fdcdff64478b0f63079dbb8ca
python -m pip install -e ".[dev,server,oidc]"
python -m pytest tests -q --cov=mcp_monitor --cov-report=term
```

The exact published measurements come from the GitHub PR **synthetic merge tree**, not a claim that a local checkout of the branch head is byte-identical to that merge. For exact archived PR-merge content, use CI run 42748742036 and the merge commit above; rerunning a moved PR ref can select newer code. Environment and dependency variation can change results.

## Validated results

- Python 3.12.16, hosted Linux: **1,158 passed, 6 skipped, 0 failed; 83.10% statement coverage; 7,327 statements and 1,238 missed**.
- Python 3.10 / 3.11: each **1,158 passed, 6 skipped**, respective coverage **83.13% / 83.10%**.
- Source inventories: **69** named injection signatures, **9** Elastic rules, **21** core SIEM tests, **7** SIEM scenario tests (confirmed, not 12).
- The [security release gate](../docs/review/PHASE13_RELEASE_READINESS.md) remains **PRODUCTION NO-GO**.

## Previous poster preserved as historical evidence

The October 14, 2026 [CI run 38502413461](https://github.com/poojakira/mcp-agent-security-gateway/actions/runs/38502413461) reported **782 passing tests and 81.93% statement coverage** from a separate source snapshot. Do not cite those as the active integration's metrics or claim detection accuracy from signature inventory.
