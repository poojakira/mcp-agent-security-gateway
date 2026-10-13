# Claim Ledger - Poster 01

> Verified code snapshot: `008775c8878cc70c50247baa223da3256e093316`. Cited CI evidence: run `37184196303`, 2026-10-04.

Classification key: VERIFIED_AT_SNAPSHOT / PARTIAL / UNVERIFIED / UNSUPPORTED.

| # | Claim | Classification | Evidence |
|---|---|---|---|
| 1 | 723 automated tests pass | VERIFIED_AT_SNAPSHOT | Python 3.12 CI job in run `37184196303`; Python 3.10/3.11 jobs also succeeded. |
| 2 | 81.91% statement coverage | VERIFIED_AT_SNAPSHOT | Python 3.12 CI: 5,644 statements, 1,021 missed. |
| 3 | 55 prompt-injection patterns in the named runtime collection | VERIFIED_AT_SNAPSHOT | Detector collection and regression suite at the cited snapshot. |
| 4 | 9 Elastic Security rule records | VERIFIED_AT_SNAPSHOT | `detection_rules/elastic_rules.toml`. |
| 5 | 21 core SIEM tests + 7 SIEM scenario tests | VERIFIED_AT_SNAPSHOT | `tests/test_siem.py` and `tests/test_siem_scenarios.py`. |
| 6 | JSON-RPC validation rejects malformed and duplicate-key inputs | VERIFIED_AT_SNAPSHOT | Cited snapshot stdio/protocol tests pass in CI. |
| 7 | Hash-chained audit and WAL implementation exists | VERIFIED_AT_SNAPSHOT | Audit modules and tests at the cited snapshot. |
| 8 | Policy enforcement is identical across all integration paths | UNSUPPORTED | Paths have different enforcement semantics; do not present as universal. |
| 9 | Population-level detector precision/recall | UNVERIFIED | No external labeled population benchmark establishes it. |
| 10 | Production uptime, SLO, or live-SOC deployment | UNSUPPORTED | Repository and CI do not establish production deployment. |

## Poster policy

Prominent numbers must be tied to the cited snapshot. Synthetic fixtures, local microbenchmarks, and historical figures must stay explicitly scoped and must not be restated as production performance.


## Claim audit and rendered-source boundary, October 13, 2026 UTC

The reviewed printed claims, source and test commit anchors, CI dates and benchmark limitations are in `verified_claims.json`. The PDF is generated from that manifest and the PNG is rasterized from the same page by `render_poster.py`. Source inventory, dated CI and separate reported experiments must not be combined into one result. Earlier artifact versions remain in Git history; these corrections do not assert production readiness.

Offline poster rendering: `python -m pip install reportlab==4.4.9 PyMuPDF==1.26.6`, then `python poster/render_poster.py`. The font is bundled with the pinned ReportLab package; no browser or network fetch is used during rendering.
