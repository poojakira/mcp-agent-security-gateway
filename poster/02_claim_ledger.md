# Claim Ledger - Poster 01

> Verified code snapshot: `8427f9ecafd3438a86775a7ceaf809f4ee051b5b`. Cited CI evidence: run `36783059917`, 2026-09-30.

Classification key: VERIFIED_AT_SNAPSHOT / PARTIAL / UNVERIFIED / UNSUPPORTED.

| # | Claim | Classification | Evidence |
|---|---|---|---|
| 1 | 718 automated tests pass | VERIFIED_AT_SNAPSHOT | Python 3.12 CI job in run `36783059917`; Python 3.10/3.11 jobs also succeeded. |
| 2 | 82.46% statement coverage | VERIFIED_AT_SNAPSHOT | Python 3.12 CI: 5,524 statements, 969 missed. |
| 3 | 55 prompt-injection patterns in the named runtime collection | VERIFIED_AT_SNAPSHOT | Current detector collection and regression suite. |
| 4 | 9 Elastic Security rule records | VERIFIED_AT_SNAPSHOT | `detection_rules/elastic_rules.toml`. |
| 5 | 21 core SIEM tests + 12 SIEM scenario tests | VERIFIED_AT_SNAPSHOT | `tests/test_siem.py` and `tests/test_siem_scenarios.py`. |
| 6 | JSON-RPC validation rejects malformed and duplicate-key inputs | VERIFIED_AT_SNAPSHOT | Current stdio/protocol tests pass in CI. |
| 7 | Hash-chained audit and WAL implementation exists | VERIFIED_AT_SNAPSHOT | Current audit modules and tests. |
| 8 | Policy enforcement is identical across all integration paths | UNSUPPORTED | Paths have different enforcement semantics; do not present as universal. |
| 9 | Population-level detector precision/recall | UNVERIFIED | No external labeled population benchmark establishes it. |
| 10 | Production uptime, SLO, or live-SOC deployment | UNSUPPORTED | Repository and CI do not establish production deployment. |

## Poster policy

Prominent numbers must be tied to the cited snapshot. Synthetic fixtures, local microbenchmarks, and historical figures must stay explicitly scoped and must not be restated as production performance.
