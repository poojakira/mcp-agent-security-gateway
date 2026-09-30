# Verified Metrics — Poster 01

> Evidence status: This Markdown companion is refreshed to the latest verified code snapshot. The rendered poster PDF remains a historical artifact at its printed commit and date.

## Current GitHub Actions verification

- **Verification:** 2026-09-30 UTC / 2026-09-29 America/Phoenix
- **Code snapshot:** `cbdf733858d186bb4d72ca57a9c10e74ee84dd65`
- **Production Gate:** https://github.com/poojakira/mcp-agent-security-gateway/actions/runs/36652602543
- **Full CI:** https://github.com/poojakira/mcp-agent-security-gateway/actions/runs/36652602526

| Metric | Value | Scope |
|---|---:|---|
| Tests passed | **707** | Production Gate and Python 3.12 CI; same suite green on Python 3.10/3.11 |
| Tests failed | **0** | Cited successful runs |
| Statement coverage | **82.84%** | 5,337 statements, 916 missed |
| INJECTION_PATTERNS entries | **55** | Runtime named collection |
| Elastic `[[rule]]` records | **9** | `detection_rules/elastic_rules.toml` |
| Core SIEM tests | **21** | `tests/test_siem.py` |
| SIEM scenario tests | **12** | `tests/test_siem_scenarios.py` |

### Current coverage is uneven

| Module | Coverage |
|---|---:|
| `siem/ecs_formatter.py` | 100% |
| `production/metrics.py` / `rate_limiter.py` | 100% |
| `redteam/simulator.py` | 99% |
| `protocol/jsonrpc.py` | 99% |
| `siem/correlation.py` | 94% |
| `production/identity_telemetry.py` | 81% |
| `proxy/stdio_proxy.py` | 70% |
| `production/server.py` | 65% |
| `siem/shipper.py` | 53% |
| `server/realtime.py` | 36% |

## New credential/network telemetry evidence

The verified code snapshot includes stable multi-credential authentication, trusted-proxy-aware source selection, IPv4/IPv6 canonicalization, and local HMAC-SHA256 fingerprints for credential, exact address, network, and block inputs. Raw credentials and raw source addresses are not written to the event output.

This is implementation evidence only. It is **not** evidence that an external external validation pilot has completed.

## Historical validation snapshot

Main CI run `35809388960`, commit `a5d39be`, 2026-09-23: **641 passed**, **79.54% coverage**. This remains historical evidence only.

## Not measured by this repository

- Detector false-positive / false-negative rates on an external population.
- Production uptime or deployment SLOs.
- Independent external external validation alert quality or live-baseline results.
