# Verified Metrics - Poster 01

> Verified code snapshot: `008775c8878cc70c50247baa223da3256e093316`
> Successful CI: https://github.com/poojakira/mcp-agent-security-gateway/actions/runs/37184196303

| Metric | Snapshot value | Scope |
|---|---:|---|
| Tests passed | **723** | Python 3.12 CI; Python 3.10/3.11 also green |
| Tests failed | **0** | Cited CI run |
| Statement coverage | **81.91%** | 5,644 statements, 1,021 missed |
| Prompt-injection collection entries | **55** | Named runtime collection |
| Current merged detector (PR #123) | **69** | Current main at c30075d; separate from the 55-entry historical snapshot, 15/15 development attacks, 3/15 benign flags |
| Elastic rule records | **9** | `detection_rules/elastic_rules.toml` |
| Core SIEM tests | **21** | `tests/test_siem.py` |
| SIEM scenario tests | **7** | `tests/test_siem_scenarios.py` |

## Verification gates

The cited CI completed lint/format, type checking, Bandit, pip-audit, CodeQL, security scanning, Windows control-plane validation, Python 3.10/3.11/3.12 tests, SBOM work, and Docker build validation successfully.

## Not established

- External population-level false-positive / false-negative rates.
- Production latency, throughput, uptime, or reliability SLOs.
- A live SOC deployment.
- Universal enforcement semantics outside traffic routed through the implemented integration paths.


## Claim audit and rendered-source boundary, October 13, 2026 UTC

The reviewed printed claims, source and test commit anchors, CI dates and benchmark limitations are in `verified_claims.json`. The PDF is generated from that manifest and the PNG is rasterized from the same page by `render_poster.py`. Source inventory, dated CI and separate reported experiments must not be combined into one result. Earlier artifact versions remain in Git history; these corrections do not assert production readiness.

Offline poster rendering: `python -m pip install reportlab==4.4.9 PyMuPDF==1.26.6`, then `python poster/render_poster.py`. The font is bundled with the pinned ReportLab package; no browser or network fetch is used during rendering.
