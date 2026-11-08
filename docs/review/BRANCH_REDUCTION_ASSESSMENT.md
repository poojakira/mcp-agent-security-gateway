# Branch reduction assessment — 7 November 2026

This document records a branch review before deletion. **No branches have been deleted.** Keep draft PR #148 unmerged. Branches are not interchangeable: several contain commits not reachable from `main`, and protected `main` must not be force-updated.

## Target arrangement (after reconciliation)

1. `main` — protected, tested release history.
2. `fix/enforce-policy-in-stdio-proxy` — active small-product development and draft PR #148.
3. `fix/stdio-policy-enforcement-20261107` — temporary preservation of PR #147 while its unique changes are reviewed. Only retire or consolidate it after PR #147's changes have been accounted for and the owner confirms closure. A long-lived `release/*` branch would be a better third branch **after** PR #147 is resolved.

This is a **proposed target**, not a completed reduction. Open Dependabot branches may be recreated by automation and need separate handling through their PRs.

## Observed branch inventory (14 branches)

The ahead/behind counts below compare each November 7 branch head with `main` at `9bad1c2f06563e7fdf637b1f70dc75521d6c2e5e`. A positive ahead count means code/history not reachable from that `main` snapshot; it does **not** establish whether that work is useful or whether an equivalent change was incorporated via squash/cherry-pick.

| Branch | Ahead | Behind | Changed-file focus | Proposed action |
|---|---:|---:|---|---|
| `main` | — | — | protected release base | Keep |
| `fix/enforce-policy-in-stdio-proxy` | n/a | n/a | active draft PR #148 | Keep |
| `fix/stdio-policy-enforcement-20261107` | 3 | 0 | stdio authorization, test and documentation | Keep pending PR #147 reconciliation |
| `fix/poster-evidence-parity-20261013` | 9 | 1 | poster files, PDFs and claim ledger | Compare binary poster artifacts and verification evidence against current files before retiring |
| `docs/cerberus-integration-closure-2026-10-09` | 2 | 16 | older README, Cerberus validation closure | Preserve historical evidence in an archive if relevant; compare before retiring |
| `docs/fix-metrics-consistency-oct13-2026-r2` | 3 | 3 | dated metric evidence and case study | Reconcile verified numbers before retiring |
| `docs/prospective-proprietary-license-2026-10-13` | 3 | 6 | license, license history, README | Check provenance and licensing history before retiring |
| `dependabot/github_actions/docker/login-action-4.7.0` | 1 | 0 | `.github/workflows/release.yml` | Resolve associated dependency update PR before retiring |
| `dependabot/github_actions/github/codeql-action/analyze-4.39.0` | 1 | 0 | `.github/workflows/ci.yml` | Resolve update PR; compare with newer versions |
| `dependabot/github_actions/github/codeql-action/init-4.39.0` | 1 | 0 | `.github/workflows/ci.yml` | Resolve update PR; compare with newer versions |
| `dependabot/github_actions/github/codeql-action/init-4.39.1` | 1 | 0 | `.github/workflows/ci.yml` | Resolve update PR; compare with older versions |
| `dependabot/github_actions/github/codeql-action/upload-sarif-4.39.0` | 1 | 0 | `.github/workflows/ci.yml` | Resolve update PR; compare with newer versions |
| `dependabot/pip/ruff-0.17.1` | 1 | 0 | `pyproject.toml` | Review major formatter/version drift first |
| `dependabot/pip/ruff-0.17.3` | 1 | 0 | `pyproject.toml` | Review latest Ruff version against CI and formatting |

## Deletion criteria

For each candidate branch: identify its open PR, compare commits and changed files against both the current `main` and draft PR #148, preserve valuable standalone documents or binary artifacts, verify superseding commits and CI, and obtain explicit branch-deletion authorization if the workflow requires it. **Never delete solely to reach a number**. Also check whether Dependabot creates new branches automatically; a strict permanent three-branch cap may require changing Dependabot settings, which should be considered independently from branch cleanup.

## Current implementation limits

The connected GitHub actions available for this review can inspect branches and update files but do not expose a safe branch-ref deletion action. The branch count therefore remains **14**. Do not claim the requested three-branch target has been reached.
