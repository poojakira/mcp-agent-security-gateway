# Verified Metrics - Poster 01

> Main code snapshot: `f1f226feb0d527f27b90081806d7e9bd90ba0574` (October 14, 2026 UTC)
> Successful CI: https://github.com/poojakira/mcp-agent-security-gateway/actions/runs/38502413461

| Metric | Snapshot value | Scope |
|---|---:|---|
| Tests passed | **782** | Python 3.12 CI; Python 3.10/3.11 also green |
| Tests failed | **0** | Cited CI run |
| Statement coverage | **81.93%** | 5,657 statements, 1,022 missed |
| Prompt-injection collection entries | **69** | Named runtime collection; current main-branch implementation |
| Elastic rule records | **9** | `detection_rules/elastic_rules.toml` |
| Core SIEM tests | **21** | `tests/test_siem.py` |
| SIEM scenario tests | **12** | `tests/test_siem_scenarios.py` |

## Verification gates

The cited CI completed lint/format, type checking, Bandit, pip-audit, CodeQL, security scanning, Windows control-plane validation, Python 3.10/3.11/3.12 tests, SBOM work, and Docker build validation successfully.

## Not established

- External population-level false-positive / false-negative rates.
- Production latency, throughput, uptime, or reliability SLOs.
- A live SOC deployment.
- Universal enforcement semantics outside traffic routed through the implemented integration paths.