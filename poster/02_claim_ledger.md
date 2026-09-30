# Claim Ledger — Poster 01 (mcp-agent-security-gateway)

> Evidence status: This ledger is refreshed to the latest verified code snapshot. The rendered poster PDF remains a historical artifact at its printed commit/date.

Verified code snapshot: `59eeac5221ab4eff3d5c5e421ccb46407de08037`. Authoritative evidence: successful GitHub Actions CI and Production Gate.

Classification key: VERIFIED_AT_SNAPSHOT / VERIFIED_HISTORICAL / PARTIAL / UNVERIFIED / UNSUPPORTED.

| # | Claim | Classification | Evidence |
|---|---|---|---|
| 1 | 702 automated tests pass | VERIFIED_AT_SNAPSHOT | Production Gate: "702 passed"; Python 3.12 CI: "702 passed" with the same suite green on Python 3.10/3.11. |
| 2 | 82.76% statement coverage | VERIFIED_AT_SNAPSHOT | Python 3.12 CI: TOTAL 5,324 statements, 918 missed; coverage.py reports 82.76%. |
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
| 16 | Multiple stable API credentials supported | VERIFIED_AT_SNAPSHOT | `Config.api_keys` combines legacy `MCP_API_KEY` and optional `MCP_API_KEYS`; protected routes compare the supplied credential against the configured set. |
| 17 | Trusted source-address boundary implemented | VERIFIED_AT_SNAPSHOT | Socket peer is authoritative unless it belongs to `MCP_TRUSTED_PROXY_CIDRS`; only then is normalized `X-Forwarded-For` used. |
| 18 | Privacy-preserving credential/network fingerprints | VERIFIED_AT_SNAPSHOT | `production/cerberus.py` uses HMAC-SHA256 truncated to 32 lowercase hex characters for credential, exact IP, network, and block inputs; raw credentials/IPs are not written to the event output. |
| 19 | External Cerberus pilot completed | UNSUPPORTED / pending | Event-generation code is implemented; external ingestion-contract approval, tenant provisioning, and live baseline are separate and not yet repository-verified. |

## Removed / downgraded for poster
- No production reliability, adoption, user counts, uptime, or SLO claims (none in repo; would be fabrication).
- Detector accuracy/precision/recall/F1: **Not measured by this repository** → shown as such.
- Circuit-breaker fail-closed shown as path-scoped, not universal.
