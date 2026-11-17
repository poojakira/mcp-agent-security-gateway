# MCP local workbench release assessment

PRODUCT: poojakira/mcp-agent-security-gateway
SOURCE: c36664757c20bbc4c9d1614ec0c9e7c9e10558cd   BRANCH: codex/local-workbench-20261116   UTC: 2026-11-17T05:53:20.540405+00:00
PHASE: Implementation, independent remediation review, and local release gate
DECISION: PARTIAL. No production or complete-contract release approval.

## Product and working entry point

Agent developers can submit editable JSON-RPC to the repository's actual PolicyEngine and StdioMCPProxy, execute constrained first-party stdio tools in a disposable directory, change the allowlist and rerun the same request, inspect actual receipts/file state, and export redacted evidence. The frontend does not implement separate detection logic. The local comparator changes only the tool allowlist.

From the source candidate: `python -m venv .venv`, activate it, `python -m pip install -e .`, then `python -m mcp_monitor.workbench`. Open http://127.0.0.1:8761. Stop with Ctrl+C. No provider credentials, model calls or paid services are used. This is a single-user loopback application with a fixed first-party target.

## Completed work and evidence

DONE: Browser editor, actual stdio execution, policy comparison, independently observed state/outcomes, request bounds, same-origin/Host gates, rate limiting, fixed paths/no outbound implementation, subprocess teardown, redacted export, version/config/input provenance, browser harness, pinned-action CI source, product/threat/API/operations documentation, baseline inventory and independent remediation.

EXECUTED: Exact commands, UTC start/end, environment, exit codes, dependency snapshot, coverage settings and artifact hashes are generated in [manifest.json](manifest.json). Independent commands/results are in [the remediation review](independent-review/PUBLICATION_RECHECK.md) and its hashed artifacts. [Security checks](security-checks.json) record fresh syntax/link, heuristic-secret and Bandit commands.

RESULTS: Python 3.12 full regression: 829 passed, 0 failed, 0 errors, 0 skipped. Statement coverage 81.81056161% with the unchanged 77% gate. Lint, formatting, real browser E2E, build, isolated installed-wheel execution and dependency audit passed. Independent Python 3.10 subset: 23/23 passed. Independent adversarial/browser checks: 22/22 passed. No performance benchmark or field detection rate is claimed.

NEGATIVE / ADVERSARIAL TESTS: Real denied writes, cross-workspace paths, injection arguments, malformed/duplicate-key messages, alternate methods, metadata egress, crash, timeout, duplicate delivery effects, tool notifications without completion, invalid configuration, hostile Host/Origin, oversized/deep JSON, form CSRF, rate exhaustion, HTML-shaped content and export redaction. See test files and independent JSON; these checks do not establish security for arbitrary MCP servers.

CLAIMS VERIFIED: Actual bounded browser-to-engine-to-tool workflow and the named checks at this source. All three independent findings (Python 3.10 timeout, unrelated Git attribution, omitted repeat configuration) were fixed and independently closed. Exported installed-wheel provenance honestly remains UNKNOWN.

CLAIMS RETRACTED: Earlier test counts/coverage and dirty preview screenshots are not current candidate evidence. Historical changelog metrics are labeled historical. No identity revocation, PII filtering, arbitrary-server containment, durable reconciliation, exactly-once delivery, full current MCP conformance, or production-readiness claim is made.

## Implementation and unmet acceptance

| Contract area | Status | Location or remaining requirement |
|---|---|---|
| Editable input, policy change, actual tool execution and export | OBSERVED / TESTED | src/mcp_monitor/workbench; tests/test_workbench.py; browser artifacts |
| Errors, denial, uncertainty, duplicate effects and bounded local input | TESTED | Runtime and independent negative checks |
| Initialize/list/call protocol subset | TESTED | 2025-03-26 first-party stdio subset; full conformance/cancellation/current version NOT VERIFIED |
| Credential lifecycle and output PII/indirect-output injection | NOT IMPLEMENTED in this local flow | Separate implementation and acceptance required |
| Arbitrary-server OS containment and durable external effects | NOT IMPLEMENTED in this local flow | Reviewed isolation/provider/recovery contracts required |
| Source packaging outside Git / full transitive locks | PARTIAL | Wheel runs but reports UNKNOWN source; direct tools pinned, snapshot captured |
| Whole-file type validation | TESTED | 234 tracked candidate files; syntax/local link targets; semantic review is incomplete |
| Every legacy document/claim/example | NOT VERIFIED | New workflow docs reconciled; exhaustive legacy reconciliation remains outstanding |
| Remote CI / protected checks | NOT VERIFIED at evidence generation | CI source added; actual remote run must be inspected separately; protection read returned 403 |
| Branch consolidation / release tag | BLOCKED / not performed | Retain unique work and unresolved PRs pending semantic reconciliation and review |

## Documentation, branch governance and release manifest

The source README, WORKBENCH, EVIDENCE and changelog identify the supported workflow and limitations. Baseline audit and file hashes remain in docs/internal; candidate inventory is in candidate-type-validation.json. Baseline PR pagination was subsequently completed and public external-link HEAD checks observed 48/48 accessible, but these do not prove all document facts or anchors. Source screenshot now points to this separate evidence ref, whose image was generated at the exact source commit.

BRANCH CHANGES: One new candidate review branch and one dedicated evidence ref. Existing default, unique feature/security, dependency and PR branches are KEEP or HELD. No existing branch was merged, deleted or force-pushed. The 528-commit advanced MCP branch remains unmerged; its prior image acceptance failure is not repaired or represented as a pass here. Ref SHAs and detailed dispositions are preserved in the baseline audit. The evidence ref attests to the source commit above; its own packaging commit is not a tested source candidate.

Release manifest: software/package version 0.1.0; protocol subset 2025-03-26; actual engine/rule source is the source commit above; dependency snapshot and tool-pins checksum are recorded. No release tag or public service was created. All downloadable artifact hashes are generated in manifest.json. Prior-source failed/aborted runs remain local historical records and are excluded from this final bundle.

RISKS / BLOCKERS: Missing master-contract features and operational approval listed above; complete legacy semantic/documentation and branch reconciliation; API protection visibility; complete build provenance and transitive locks. Local tests and controlled fixtures do not resolve these gaps.

NEXT SAFE ACTION: Review the candidate PR and exact-source evidence, inspect actual remote CI, then implement and adversarially test the remaining containment/identity/recovery/protocol requirements before any release designation. Preserve existing refs and use the baseline main commit as a recovery pointer after preserving local edits.

## Publication privacy and supplementary CI checks

GitHub GH007 rejected the original unpublished history because its configured email was private. Protection was retained. Original commits remain on local unpublished-only recovery refs; they must not be pushed. This candidate is a new commit from the identical reviewed tree, using the account's existing public noreply address, with original main as its parent. No existing repository history was rewritten. All required candidate checks and independent review were freshly repeated at the source above.

The unchanged CI warning-as-error regression was also executed: 829 passed with the 77% coverage gate retained. The existing focused Pyright gate passed with zero errors/warnings. Its first setup attempt failed on an unwritable npm cache; an explicit workspace cache repaired the prerequisite without relaxing checks. Strict logs/JUnit, Pyright command/timing, and tree/provenance records are included.
