> **Evidence reconciliation (2026-11-11; living reference):** Historical results below retain their original dates and denominators. Latest tested Phase 1–16 development SHA is `43a72c8984bf9a472b9055d4f9e84cc759f61718` ([CI](https://github.com/poojakira/mcp-agent-security-gateway/actions/runs/42971171992): 1,211 passed, 6 skipped per Python version), **not** a merged or production-approved release. Offline research tests require no paid provider or provider-issued API keys; deployed HTTP authentication and unverified real credential revocation remain separate. See [operating restrictions](../../PRODUCTION.md) and [release evidence](../../docs/review/PHASE1_16_RELEASE_CANDIDATE_NO_GO_20261110.md).

# Detection Precision / Recall (synthetic fixtures)

> **Review context (2026-11-09):** The stated perfect precision and recall are exclusively from the small curated fixture set. They are not estimates on unknown, independent or production traffic. The [integrated release-readiness gate](../../docs/review/PHASE13_RELEASE_READINESS.md) is **PRODUCTION NO-GO**.
> SYNTHETIC FIXTURES ONLY. These sequences are hand-crafted to exercise specific rule logic and are NOT real-world MCP traffic. Metrics describe behaviour on these fixtures only and must not be read as real-world detection efficacy.

- Generated: `2026-09-28T06:21:46Z`
- Sequences: **9** (6 malicious, 3 benign)

## Per-rule metrics

| Rule | TP | FP | FN | TN | Precision | Recall | F1 |
|---|---|---|---|---|---|---|---|
| `COR-001` | 1 | 0 | 0 | 8 | 1.000 | 1.000 | 1.000 |
| `COR-002` | 1 | 0 | 0 | 8 | 1.000 | 1.000 | 1.000 |
| `COR-003` | 1 | 0 | 0 | 8 | 1.000 | 1.000 | 1.000 |
| `COR-004` | 1 | 0 | 0 | 8 | 1.000 | 1.000 | 1.000 |
| `COR-005` | 1 | 0 | 0 | 8 | 1.000 | 1.000 | 1.000 |
| `COR-006` | 1 | 0 | 0 | 8 | 1.000 | 1.000 | 1.000 |

## Micro-average (all rules)

- Precision on these synthetic fixtures only: **1.000**
- Recall on these synthetic fixtures only: **1.000**
- F1: **1.000**
- Confusion: TP=6 FP=0 FN=0 TN=48
