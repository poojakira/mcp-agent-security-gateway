# Evidence and release status

**Full-contract decision: PARTIAL.** Evidence must identify the exact source it executed. A later documentation/source commit does not inherit an earlier green run. Source files do not embed a claim to their own future commit hash.

## Published implementation-source evidence

The published source is **`4b6bb486d83f4410037113e64848a22e4a06f713`**, candidate branch `codex/local-workbench-20261116`, draft [PR #194](https://github.com/poojakira/mcp-agent-security-gateway/pull/194). It recorded 829 passed, 0 skipped and 81.80446084185813% statement coverage with the unchanged 77% gate. Six associated hosted workflows succeeded, including Docker build/runtime smoke. Focused independent review closed the timeout, wheel-provenance and repeat-hash findings at that source; it is distinct from the full regression.

- [Assessment and limits](https://github.com/poojakira/mcp-agent-security-gateway/blob/d0d78a97802b203a9652b7fceb50acc0711a66e1/release-evidence/RELEASE_ASSESSMENT.md)
- [Manifest with exact commands, timing, environment and hashes](https://github.com/poojakira/mcp-agent-security-gateway/blob/d0d78a97802b203a9652b7fceb50acc0711a66e1/release-evidence/manifest.json)
- [Actual browser screenshot](https://github.com/poojakira/mcp-agent-security-gateway/blob/d0d78a97802b203a9652b7fceb50acc0711a66e1/release-evidence/browser/desktop.png)

The archive tag `evidence/local-workbench-20261116` points to evidence-only commit `d0d78a97802b203a9652b7fceb50acc0711a66e1`. It is an immutable non-release archive, not the tested implementation source or a deployment. Parent publication verification matched 52 archived artifact hashes. These numbers remain tied to that implementation source after the documentation pass.

## Documentation-reconciliation head

New-head full regression/browser/security/build/independent document checks are **pending until freshly executed evidence identifies that head**. The planned archive is `evidence/docs-reconciliation-20261118`, stored out of the source branch and published only after generation/review. A planned name is not proof it exists. The draft PR records actual publication status; do not cite the implementation-source counts as new-head execution.

[DOCUMENTATION_AUDIT.md](DOCUMENTATION_AUDIT.md) records every tracked instruction/document disposition, source checks and execution limits. The earlier [forensic baseline](internal/REPOSITORY_AUDIT.md) and [baseline inventory](internal/baseline-inventory.json) describe pre-implementation main, not this candidate's final state.

## Reproduce and record

Use the complete commands/prerequisites in [README.md](../README.md#develop-and-verify). The browser harness starts a real temporary loopback server, uses actual proxy/child execution, checks same-input permission changes, verifies export redaction and captures desktop/mobile results. It tears down its own server. Optional native/Rego/lab paths need their own toolchains/services and must not be called passing merely because Python checks pass.

The `Local MCP workbench acceptance`workflow checks out the actual PR head, runs the full Python suite at the unchanged77% coverage gate, lint/format, actual browser harness and package build. It uses pinned actions/read-only repository permission. `requirements-workbench-test.txt` pins direct tools, not all transitives. The main CI includes additional platform/security/container checks; distinguish head checkout from a PR merge-tree check.

Record source SHA, branch and clean state, UTC start/end, platform/tool/dependency versions and lock/snapshot hashes, exact commands/exits, JUnit pass/fail/skip totals, coverage configuration, browser/runtime proof, artifact digests and unresolved checks. `scripts/workbench_manifest.py` dynamically identifies the checkout and can record failure status. Generate artifacts outside the checkout; independently compare archived bytes, including logs/ignored package/coverage outputs. An omitted file is a failed archive-completeness check, not permission to invent its result.

## Branch disposition

The completed implementation pass retained eight remote branches: protected main, the single candidate, four active dependency PR branches, unique unmerged docs work and the advanced unique security-fix branch. Three proven obsolete remote branches were deleted after dependency/content/recovery checks:

| Deleted branch | Recovery reference |
|---|---|
| `integration/phase1-16-verified` | `archive/mcp/integration-phase1-16-20261116` |
| `security/phase1-16-audit` | `archive/mcp/security-phase1-16-20261116` |
| `codex/evidence-local-workbench-20261116` | Exact tip preserved in the final immutable evidence archive ancestry |

A verified private Git bundle is retained locally and is not published. Deleted phase tips remain reachable from the retained advanced branch/recovery tags. Ancestry counts alone do not establish squash-merge equivalence. The unmerged docs PR was closed without merge; unique work remains HELD. No main history rewrite, default merge, public deployment or software release occurred. Re-read current remote state before any later cleanup; this table is the completed pass's disposition, not a live branch API.

## Remaining gates

Complete current MCP conformance/cancellation/concurrency, credential identity lifecycle, output PII filtering, arbitrary-server containment, durable provider effects, independent audit anchors, operational/privacy/load/recovery approval and review/integration of preserved unique security work remain incomplete or unverified. The advanced branch's historical exact-image gate failure is not resolved by keeping it unmerged. All-document local semantic reconciliation does not verify external historical assertions, third-party benchmarks, diagrams' field efficacy or deployment examples. See [PRODUCTION.md](../PRODUCTION.md) and [the capability matrix](WORKBENCH.md#acceptance-status-matrix).
