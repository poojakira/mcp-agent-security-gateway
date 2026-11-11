# Claim Ledger — MCP Gateway Integration Poster

> Reviewed candidate: PR #167 head `25bc77445df5fa5fdcdff64478b0f63079dbb8ca`; CI checks ran synthetic PR merge `2ab3380d1457cdcb16c3ba143db9d8e339b057e2` on 2026-11-10 UTC. This is research/development evidence, **not a production-release certificate**.

Classification key: CI_VERIFIED_AT_PR_MERGE / SOURCE_INVENTORY / LAB_VERIFIED / HISTORICAL / UNVERIFIED.

| # | Claim | Classification | Evidence |
|---|---|---|---|
| 1 | **1,158 passed, 6 skipped, 0 failed**, Python 3.12 | CI_VERIFIED_AT_PR_MERGE | [CI run 42748742036](https://github.com/poojakira/mcp-agent-security-gateway/actions/runs/42748742036) |
| 2 | **83.10% statement coverage**, Python 3.12, 7,327 statements, 1,238 missed | CI_VERIFIED_AT_PR_MERGE | Same full CI run, exact Python 3.12 job |
| 3 | Python 3.10: 1,158 passed / 6 skipped / **83.13%** coverage | CI_VERIFIED_AT_PR_MERGE | Same full CI run, Python 3.10 job |
| 4 | Python 3.11: 1,158 passed / 6 skipped / **83.10%** coverage | CI_VERIFIED_AT_PR_MERGE | Same full CI run, Python 3.11 job |
| 5 | **69** named prompt-injection detector signatures | SOURCE_INVENTORY | `src/mcp_monitor/detectors/prompt_injection.py`; not a detection rate |
| 6 | **9** Elastic rule records | SOURCE_INVENTORY | `detection_rules/elastic_rules.toml` |
| 7 | **21** core SIEM test functions | SOURCE_INVENTORY | `tests/test_siem.py` |
| 8 | **7** SIEM scenario test functions (not 12) | CI_VERIFIED_AT_PR_MERGE | `tests/test_siem_scenarios.py`, 7 passed in full CI |
| 9 | Focused security regression: **42 passed** | LAB_VERIFIED | [Integrated CI run 42748741925](https://github.com/poojakira/mcp-agent-security-gateway/actions/runs/42748741925), Python 3.12 |
| 10 | Real pinned filesystem MCP smoke test: **1 passed** | LAB_VERIFIED | [Run 42748742254](https://github.com/poojakira/mcp-agent-security-gateway/actions/runs/42748742254) |
| 11 | **782 passed / 81.93%** statement coverage | HISTORICAL | October 14 run 38502413461 at `f1f226f`; this is not the November integrated result |
| 12 | Independently measured production detector precision/recall, incident prevention or customer deployment | UNVERIFIED | No representative blind benchmark or live production deployment evidence |

## Integrity rules

Keep the PR merge commit, date, Python version and test denominator beside every numerical claim. A GitHub Actions workflow named `Production Gate` passing does **not** satisfy the human release gate. The production decision is **NO-GO** with open identity, egress, effect recovery, transport and independent validation requirements. No paid provider token or external target was used.

## Historical poster correction

The October poster's statement of **12 SIEM scenario tests** was incorrect: the cited old code and the reviewed new code each contain **7** scenario-runner `test_*` functions. The older 782-test and 81.93%-coverage values were valid for their own cited October CI; the revised poster replaces the active headline with verified November integration values.
