# Verified Metrics — MCP Gateway Integration Poster

> PR #167, CI merge commit `2ab3380d1457cdcb16c3ba143db9d8e339b057e2`, GitHub Actions [run 42748742036](https://github.com/poojakira/mcp-agent-security-gateway/actions/runs/42748742036) (2026-11-10 UTC). **Development integration only · production NO-GO.**

| Metric | Snapshot value | Scope |
|---|---:|---|
| Tests passed | **1,158** | Python 3.12, reviewed PR merge commit |
| Tests skipped | **6** | Python 3.12 CI; 0 failed |
| Statement coverage | **83.10%** | Linux Python 3.12, not detector accuracy |
| Statements measured | **7,327** | 1,238 missed; same CI job |
| Prompt-injection signatures | **69** | Source inventory; not population recall |
| Elastic Security rules | **9** | `detection_rules/elastic_rules.toml` |
| Core SIEM tests | **21** | `tests/test_siem.py` |
| SIEM scenario tests | **7** | `tests/test_siem_scenarios.py`; corrected from 12 |

## Additional measured checks

Python 3.10 / 3.11 each recorded 1,158 passed and 6 skipped, with 83.13% / 83.10% statement coverage. The focused combined security suite recorded 42 passing cases on Python 3.12. A real disposable filesystem MCP smoke test recorded one passing case; this is **not** a production deployment test.

## Not established

- Independent, representative prompt-injection precision/recall.
- Universal prevention of tool-server bypass or arbitrary host/OS access.
- External identity assurance, complete transport interoperability and production-restricted outbound egress.
- Customer deployments, SOC response SLOs, uptime or human production authorization.

## Historical comparison (not a merged measurement)

October 14, 2026 main CI [run 38502413461](https://github.com/poojakira/mcp-agent-security-gateway/actions/runs/38502413461) at `f1f226f`: **782 passed / 81.93%** statement coverage, 5,657 statements / 1,022 missed. Do not combine those measurements with the November run.
