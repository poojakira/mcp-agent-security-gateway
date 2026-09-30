# Verified Metrics

This file is the evidence anchor for quantitative claims about this repository.

## Current verified code snapshot

**Code commit:** `e249bde03affc6dcece172f991269cfe1c26417a`  
**Successful Production Gate:** https://github.com/poojakira/mcp-agent-security-gateway/actions/runs/36655829130  
**Successful full CI:** https://github.com/poojakira/mcp-agent-security-gateway/actions/runs/36655829094  
**Verification time:** 2026-09-30 UTC (2026-09-29 America/Phoenix)

The Python 3.12 CI job reports:

```text
TOTAL                                               5342    916    83%
Required test coverage of 77% reached. Total coverage: 82.85%
707 passed in 141.56s
```

The Production Gate independently reports:

```text
707 passed in 79.52s
All checks passed!
```

| Claim | Current verified value | Evidence boundary |
|---|---:|---|
| Automated tests | **707 passed** | Python 3.12 CI and Production Gate on the cited code commit; the same suite is green on Python 3.10 and 3.11 |
| Statement coverage | **82.85%** | 5,342 statements, 916 missed on Python 3.12 |
| Prompt-injection regex patterns | **55** | `INJECTION_PATTERNS` in `src/mcp_monitor/detectors/prompt_injection.py` |
| Elastic Security rules | **9** | `detection_rules/elastic_rules.toml` |
| Core SIEM tests | **21** | `tests/test_siem.py` |
| Additional SIEM scenario-runner tests | **12** | `tests/test_siem_scenarios.py` |
| Identity telemetry helper coverage | **81%** | `src/mcp_monitor/production/identity_telemetry.py` in the current Python 3.12 coverage report |
| Production server coverage | **65%** | `src/mcp_monitor/production/server.py` in the current Python 3.12 coverage report |
| Red-team simulator coverage | **99%** | `src/mcp_monitor/redteam/simulator.py` in the current Python 3.12 coverage report |

The full CI is green for Ruff/formatting, Pyright, security scan, CodeQL, Windows control-plane checks, Docker build, and the Python 3.10/3.11/3.12 test matrix.

Subsequent documentation-only commits may move `main` beyond the cited code SHA without changing these runtime/test results. Re-run CI before changing quantitative claims after any implementation or test change.

## Current credential/network telemetry state

The production gateway now supports:

- legacy `MCP_API_KEY` plus optional comma-separated stable credentials through `MCP_API_KEYS`;
- socket-peer source capture by default;
- `X-Forwarded-For` only when the socket peer belongs to an explicitly configured `MCP_TRUSTED_PROXY_CIDRS` network;
- normalization of IPv4, IPv4-with-port, bracketed IPv6, RFC 7239-style `for=` values, and IPv4-mapped IPv6;
- HMAC-SHA256 fingerprints truncated to the first 32 lowercase hex characters;
- exact-address, /24-or-/64 network, and /16-or-/48 block fingerprints;
- local event generation without raw credentials or raw source addresses;
- `tokens_in = 0` and `tokens_out = 0` when token accounting is unavailable at the MCP inspection layer.

The static event and transport mapping is implemented and contract-checked. The repository does **not** claim that a live validation baseline, external alert-quality evaluation, or production deployment has completed.

## Historical main CI baseline

**Code commit:** `a5d39be286a9bac62b01d898ace17607ae058e89`  
**Successful main CI run:** https://github.com/poojakira/mcp-agent-security-gateway/actions/runs/35809388960  
**Verification date:** 2026-09-23

| Claim | Historical verified value |
|---|---:|
| Automated tests | **641 passed** |
| Statement coverage | **79.54%** |
| Prompt-injection regex patterns | **55** |
| Elastic Security rules | **9** |
| Core SIEM tests | **21** |
| Additional SIEM scenario-runner tests | **12** |

These values remain historical evidence and must not be presented as the current repository state.

## Reproduce

Use the repository CI workflow for the authoritative dependency set and Python matrix. For a local check:

```bash
python -m pytest tests/ -q --cov=mcp_monitor --cov-report=term
ruff check src tests
ruff format --check src tests
```

For static-count claims:

- count entries in `INJECTION_PATTERNS` for the 55 prompt-injection patterns;
- count `[[rule]]` records in `detection_rules/elastic_rules.toml` for the 9 Elastic rules;
- count `test_*` functions in `tests/test_siem.py` for the 21 core SIEM tests.

When implementation or tests change, update this file only after re-running CI and reconciling README, poster evidence, résumé evidence, and portfolio claims.
