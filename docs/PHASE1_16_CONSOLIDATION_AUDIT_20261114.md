# Phase 1–16 consolidation and adversarial release audit

Date: 2026-11-14
Status: OPEN — NOT PRODUCTION APPROVED

## 2026-11-14 post-deletion recovery and verification update

- Public `integration/phase1-16-verified` was deleted manually and recreated from `security/phase1-16-audit`. A subsequent GitHub comparison returned **identical** (0 ahead / 0 behind). This confirms equality at recovery time, **not** recovery of the integration branch's former SHA or independent verification of its contents.
- The private repository's integration branch was present when checked and was not recreated.
- The public audit branch was 384 commits ahead of `main` and 0 behind when compared. This is commit ancestry only, not security validation.
- The exact audit-head pull-request workflow lookup for `4d37d68330b79cde36376272f47d007d234681fd` returned no runs. This API only returns PR-triggered runs on its first page; absence does not prove no other Actions runs exist.
- Historical 1,211 passed / 6 skipped per Python version belongs exclusively to SHA `43a72c8984bf9a472b9055d4f9e84cc759f61718`. The five newly authored revocation tests have **not** been observed passing on the latest audit head.
- Open PRs and divergent branches must be reconciled before further cleanup or promotion. **Production NO-GO.**

## Repository policy
- Preserve `main` as the stable branch; do not fast-forward or merge to main without a verified release gate.
- Candidate integration branch: `integration/phase1-16-verified`.
- Adversarial remediation branch: `security/phase1-16-audit`.
- Do not delete source branches until unique commits, tags, PR references, CI evidence, and licensing implications are reviewed and backed up. Branch-count goal is pending, not achieved.

## Baseline provenance
- Public integration candidate originated from `release/phase1-16-offline-rc-20261111` (363 commits ahead of main at comparison time).
- Private integration candidate originated from `test/pre17-revocation-read-20261114` (5 commits ahead of main at comparison time).
- Public `phase16/transactional-revocation-fence` diverged from main (228 ahead, 2 behind); review for security changes missing from release candidate.
- Public `docs/phase1-16-evidence-and-poster-20261111` diverged from main (347 ahead, 2 behind); reconcile poster metrics and evidence, do not copy unsupported claims.

## Devil's-advocate / autopsy gates
1. Identity: verify cryptographically bound caller identity, reject user-supplied actor spoofing, test stale sessions and key rotation.
2. Revocation: test all `tools/list`, `tools/call`, resources, prompts, manifest, direct and alternate transport paths, including concurrent in-flight calls.
3. Authorization: deny-by-default; confirm denied operations never reach the downstream server; distinguish gateway decision from observed side effects.
4. Egress: verify OS/container-level network isolation, DNS rebinding, redirects, internal ranges, IPv6, alternate protocols, and proxy bypass.
5. Protocol: malformed JSON-RPC, duplicate keys, batches, cancellation, progress, multiplexing, errors, reconnection and stream framing.
6. Durability: crash between authorization and execution, uncertain outcome reconciliation, replay, WAL corruption, multi-process consistency.
7. Detection: held-out adversarial cases, false positives/negatives, Unicode normalization, encoded payloads, result-side injection.
8. Supply chain: pin digests, dependency CVEs, SBOM, secret scanning across history, license compatibility, CI permissions.
9. Independent validation: frozen corpus, independently observed tool-state changes, no synthetic-only production efficacy claims.
10. Release: complete CI matrix, actual execution logs, commit SHAs, artifacts, signed-off threat model and explicit residual risks.

## Required test commands (run in isolated local/CI environment)
- Run the repository's documented full Python test suite on supported Python versions.
- Run lint, static analysis, secret scan, dependency/SBOM audit, and all Phase 1–16 integration workflows.
- Execute isolated first-party MCP server tests with disposable files, no external API keys, and deny/bypass/revocation fault injection.
- Save per-test pass/fail, commit, environment, side-effect evidence and coverage report. Do not report tests as passed until execution is observed.

## Poster truthfulness checklist
- State clearly: research prototype, not production-certified.
- Show client → trusted identity/session → JSON-RPC validation → policy/detection → allow/deny → downstream tool → observed side effect → audit/WAL.
- Distinguish audit evidence from independent side-effect verification.
- Include accessible static diagram alongside an animated diagram for digital display; animation does not run in printed posters.
- Report test counts, coverage, detector signatures, latency and date only with commit-specific evidence.

## Current verified activity in this session
- Enumerated 5 private and 53 public branches before creating working branches.
- Compared selected integration, release, remediation and poster branches against main.
- Created integration and security audit branches in both repositories.
- No full CI suite executed; no source branches deleted; no production approval granted.
