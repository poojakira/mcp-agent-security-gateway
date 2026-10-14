# Claim Ledger - Poster 01

> Current verified main snapshot: `f1f226feb0d527f27b90081806d7e9bd90ba0574`. [Python 3.12 CI run 38502413461](https://github.com/poojakira/mcp-agent-security-gateway/actions/runs/38502413461) (October 14, 2026 UTC); distinct from the archived October 4 poster values below.

Classification key: VERIFIED_AT_SNAPSHOT / PARTIAL / UNVERIFIED / UNSUPPORTED.

| # | Claim | Classification | Evidence |
|---|---|---|---|
| 1 | **782 automated tests passed** | VERIFIED_AT_SNAPSHOT | Python 3.12 CI run `38502413461`; Python 3.10/3.11 also passed |
| 2 | **81.93% statement coverage** | VERIFIED_AT_SNAPSHOT | 5,657 statements, 1,022 missed in the same Python 3.12 job |
| 3 | **69 named runtime prompt-injection signatures** | VERIFIED_SOURCE_INVENTORY | Separate named collection inventory at the cited source snapshot; this is not a recall rate |
| 4 | **9 Elastic Security rule records** | VERIFIED_SOURCE_INVENTORY | `detection_rules/elastic_rules.toml` |
| 5 | **21 core SIEM tests + 12 SIEM scenario tests** | VERIFIED_SOURCE_INVENTORY | `tests/test_siem.py` and `tests/test_siem_scenarios.py` |
| 6 | JSON-RPC validation rejects malformed and duplicate-key inputs | VERIFIED_AT_SNAPSHOT | Protocol tests in cited CI |
| 7 | Hash-chained audit and WAL implementation exists | VERIFIED_AT_SNAPSHOT | Audit modules and tests at cited commit |
| 8 | Policy enforcement is identical across every integration path | UNSUPPORTED | Paths differ in enforcement semantics |
| 9 | Population-level detector precision or recall | UNVERIFIED | No independent representative labeled benchmark |
| 10 | Production uptime, SLOs or live-SOC deployment | UNSUPPORTED | No field deployment evidence in cited run |

## Archived October 4, 2026 evidence (not this poster's current metric row)

Code `008775c8878cc70c50247baa223da3256e093316`, [run 37184196303](https://github.com/poojakira/mcp-agent-security-gateway/actions/runs/37184196303): **723 passed, 81.91% statement coverage, 55 named prompt-injection signatures**. These numbers remain historical and must not be paired with the current CI values as one run.

## Poster policy

Only combine values from the same cited execution, with source-inventory and curated-fixture results expressly labeled as separate evidence. The Cerberus integration/pilot configuration and its detector effectiveness are outside the poster verification.
