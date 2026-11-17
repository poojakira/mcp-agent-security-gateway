# Candidate evidence contract

Release decision: **PARTIAL / NOT VERIFIED for the complete master acceptance contract**. Source code and documentation do not contain a claim to their own commit hash. Generate final results after freezing the candidate; write artifacts outside the checkout.

The executable browser harness is `scripts/workbench_e2e.py`; the regression suite is `tests/`. Record exact source SHA, branch, clean/dirty status, UTC start/end, environment, installed dependency snapshot/checksum, exact commands and exit codes, JUnit totals, coverage configuration, browser captures, build outputs and artifact SHA256 checksums. Historical metrics and old CI runs must not be republished as current candidate evidence.

Baseline history and limitations: `docs/internal/REPOSITORY_AUDIT.md`. The all-file baseline hash inventory is `docs/internal/baseline-inventory.json`. It records the audited main before this candidate's additions, not a final candidate inventory.

Outstanding release blockers: full per-file semantic/documentation reconciliation, current MCP compatibility/cancellation tests, production containment and operational signoff, integration of separately reviewed protected execution/revocation work, full branch semantic reconciliation and protection visibility, release package provenance outside Git. All unique or ambiguous branches remain HELD; no remote branch is deleted by this change.

The dedicated `Local MCP workbench acceptance` workflow runs the complete local regression at the unchanged 77% coverage gate, lint/format, real browser harness and package build on pull requests/manual dispatch. It uses read-only repository permissions, pinned existing actions and no credentials or deployment. `requirements-workbench-test.txt` pins direct tooling; generated dependency snapshots describe transitives. `scripts/workbench_manifest.py` identifies the checked-out source dynamically and generates checksums out of tree, including failed-job status. Remote execution is NOT VERIFIED until an actual run exists for the published candidate.
