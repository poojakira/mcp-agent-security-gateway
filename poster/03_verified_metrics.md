# Verified Metrics — Poster 01

## Current local verification (independent re-run for this poster)
- **Date:** 2026-09-26
- **Environment:** Windows, CPython 3.12.10, fresh `venv`, `pip install -e ".[dev,server]"`, `PYTHONPATH=src`
- **Repo HEAD:** `a5ef8e370522776b4a9a55309c5def28540d9190`
- **Command:** `python -m pytest tests -q --cov=mcp_monitor --cov-report=term`

| Metric | Value | Scope |
|---|---:|---|
| Tests passed | 652 | Current checkout, local Py 3.12.10 |
| Tests failed | 0 | Current checkout |
| Wall time | ~92 s | Single run, this machine |
| Statement coverage (aggregate) | 79.23% | 4804 statements, 998 missed |
| INJECTION_PATTERNS entries | 55 | Runtime `len()` of the named collection |
| Elastic `[[rule]]` records | 9 | `detection_rules/elastic_rules.toml` |
| Core SIEM tests | 21 | `tests/test_siem.py` |
| SIEM scenario tests | 7 | `tests/test_siem_scenarios.py` |

### Coverage is uneven (honest breakdown, from same run)
| Module | Coverage |
|---|---:|
| `siem/ecs_formatter.py` | 100% |
| `production/metrics.py` / `rate_limiter.py` | 100% |
| `protocol/jsonrpc.py` | 99% |
| `siem/correlation.py` | 93% |
| `proxy/stdio_proxy.py` | 70% |
| `production/server.py` | 66% |
| `siem/shipper.py` | 53% |
| `server/realtime.py` | 36% |
| `redteam/simulator.py` | 0% |

## Historical validation snapshot (NOT current checkout)
Main CI run `35809388960`, commit `a5d39be`, 2026-09-23: **641 passed**, **79.54% coverage**; gates: Ruff, Pyright, Bandit, pip-audit, CodeQL, Trivy, Grype, SBOM, Docker build, Python 3.10/3.11/3.12. These gates have not re-run against the current commit.

## Not measured by this repository
- Detector false-positive / false-negative / precision / recall / F1 on an external corpus.
- Production latency, throughput, p95/p99, uptime, or any deployment SLO.
