# Claim Ledger — Poster 01 (mcp-agent-security-gateway)

> Evidence status: The verification below applies to the cited 2026-09-27 commit. The rendered PDF has its own printed commit and date. Neither artifact asserts a fresh run on the latest `main`.

Audited HEAD: `c68e200d320ce68793096598e516b4d015bc21ad`. Local env: Windows, Python 3.12.10.

Classification key: VERIFIED_AT_SNAPSHOT / VERIFIED_HISTORICAL / PARTIAL / UNVERIFIED / UNSUPPORTED.

| # | Claim | Classification | Evidence |
|---|---|---|---|
| 1 | 659 automated tests pass | VERIFIED_AT_SNAPSHOT | `pytest tests -q` → "659 passed" on a clean venv (Py 3.12.10); also green in GitHub Actions on `main`. |
| 2 | 82% statement coverage | VERIFIED_AT_SNAPSHOT | `--cov=mcp_monitor` → TOTAL 4804 stmts, 880 missed = 82%. |
| 3 | 55 prompt-injection regex patterns | VERIFIED_AT_SNAPSHOT | `len(prompt_injection.INJECTION_PATTERNS)` == 55 (imported module). Note: file has 59 `re.compile` calls total; 4 are outside the collection — README's "55" is correct for the named list. |
| 4 | 9 Elastic Security rules | VERIFIED_AT_SNAPSHOT | 9 `^[[rule]]` records in `detection_rules/elastic_rules.toml`. |
| 5 | 21 core SIEM tests | VERIFIED_AT_SNAPSHOT | 21 `def test_` in `tests/test_siem.py`. |
| 6 | 7 SIEM scenario tests | VERIFIED_AT_SNAPSHOT | 7 `def test_` in `tests/test_siem_scenarios.py`. |
| 7 | Inline MCP stdio proxy exists; rejects malformed/duplicate-key JSON | VERIFIED_AT_SNAPSHOT | `src/mcp_monitor/proxy/stdio_proxy.py` present (233 stmts); README behavior; tests cover proxy paths. |
| 8 | JSON-RPC parsing/validation | VERIFIED_AT_SNAPSHOT | `src/mcp_monitor/protocol/jsonrpc.py` present, 99% covered. |
| 9 | Hash-chained audit log + WAL | VERIFIED_AT_SNAPSHOT | `src/mcp_monitor/audit/log.py`, `audit/wal.py` present; THREAT_MODEL cites SHA-256 chaining. (Chaining scheme reviewed in source; cryptographic strength not independently audited.) |
| 10 | Circuit breaker fails closed to DENY | PARTIAL | `production/circuit_breaker.py` present; THREAT_MODEL states fail-closed "on this specific path." Behavior path-specific, not global — cite as path-scoped. |
| 11 | Historical: 641 passed, 79.54% coverage, full CI gate matrix | VERIFIED_HISTORICAL | VERIFIED_METRICS.md cites CI run 35809388960, commit a5d39be, 2026-09-23. Not re-run against current commit. Label as historical snapshot. |
| 12 | Production SOC deployment / uptime / SLO | UNSUPPORTED (correctly disclaimed) | README explicitly makes no production latency/throughput guarantee; detection lab "not evidence of production SOC deployment." Poster must NOT claim production. |
| 13 | Enforcement identical across integration paths | UNSUPPORTED | README states stdio proxy, FastAPI control plane, and HTTP surfaces "do not provide identical enforcement behavior." Poster must state per-path differences. |
| 14 | Measured false-positive / false-negative rate | UNVERIFIED / Not measured | No external labeled corpus benchmark for detector FP/FN in repo. State "Not measured." |
| 15 | ATT&CK-mapped Elastic rules present | VERIFIED_AT_SNAPSHOT | elastic_rules.toml + detection_lab; mapping describes technique relationships, not proof of attack occurrence. |

## Removed / downgraded for poster
- No production reliability, adoption, user counts, uptime, or SLO claims (none in repo; would be fabrication).
- Detector accuracy/precision/recall/F1: **Not measured by this repository** → shown as such.
- Circuit-breaker fail-closed shown as path-scoped, not universal.
