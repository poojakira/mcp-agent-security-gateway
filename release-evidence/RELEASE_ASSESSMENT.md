# MCP candidate assessment

PRODUCT: poojakira/mcp-agent-security-gateway
SOURCE: 4b6bb486d83f4410037113e64848a22e4a06f713
BRANCH: codex/local-workbench-20261116
DECISION: **PARTIAL** under the complete acceptance contract; no production approval.

The local browser workbench invokes the actual PolicyEngine and StdioMCPProxy against a fixed first-party stdio test server. It supports operator-provided request/note input, effective-policy comparison, actual tool-side receipts/state, honest UNKNOWN crash/timeout outcomes, and redacted exports. The policy OFF comparison changes only the exposed tool allowlist. It does not remove unrelated security controls. App version0.1.0; tested MCP2025-03-26 subset. Current full protocol conformance is not established.

## Fresh executed evidence

The clean exact-source local engineering run started2026-11-17T20:48:31.666263+00:00. It recorded829 passing tests, no failed/skipped tests, and81.80446084185813% statement coverage. The existing77% gate remains unchanged. Exact commands, UTC intervals, environment snapshots and hashes are in manifest.json. Lint, formatting, focused typing, workflow validation, browser acceptance, package build, dependency audit and installed-wheel checks passed. The dependency audit used the corrected writable cache; its log is authoritative over the earlier cache-path attempt. Bandit reported no medium/high findings. All215 new secret-heuristic matches were baseline-inventory file hashes; heuristic scanning is not proof of absence of secrets.

Independent review at the same source ran23/23 Python3.10 tests and22/22 independent engine/HTTP/Chromium checks, verified all34 then-frozen engineering artifacts, and installed the new wheel inside an unrelated Git project. Its real read succeeded while source provenance correctly remainedUNKNOWN. Prior timeout, unrelated-Git provenance and incomplete configuration-hash findings remain closed. The review did not repeat all829 tests. Its statement that remote CI was not verified describes the reviewer scope; the subsequent run-status.json and downloaded artifact provide that separate proof.

All six exact-head GitHub workflows succeeded: Security Hygiene44173598434; Documentation Integrity44173598454; Focused AppSec44173598574; Production Gate44173598473; Local MCP workbench44173598380; CI44173598509. The workflow named Production Gate does not confer deployment approval. CI jobs include Python3.10/3.11/3.12, Windows, typing, CodeQL, security scanning and Docker build/runtime smoke. All succeeded. The standard remote Docker build and runtime smoke passed at this source; no image was pushed. Earlier local Docker attempts at superseded source were blocked by managed-CA trust and the8GB/vfs filesystem. Those failures are not represented as a local pass. No local current-source container pass is claimed.

The actual remote workbench artifact ZIP SHA256 isfd24e09b3b7fe69e4cda2976cf06a7e38979a319ab19a3c414db5f412dfc3965. Its source is the exact candidate head despite an event-merge-SHA artifact name. All10 embedded artifact digests matched. Remote and local build bytes are distinct and each retains its own hashes.

## Actual workflow and safety boundaries

Follow README.md and docs/WORKBENCH.md on the source branch to launch `python -m mcp_monitor.workbench` after the documented editable install. Browser images and downloaded redacted reports come from actual running Chromium sessions. The workbench binds loopback, constrains requests/paths/destinations, uses disposable first-party state and rejects unsupported inputs. It is a single-operator local workbench. It does not authorize arbitrary remote servers or provide public multi-user isolation.

Actual adversarial checks cover request throttling, malformed/duplicate JSON keys, hostile HTML, disallowed metadata destinations, cross-workspace paths, alternate methods, origin/host/body/type limits, timeout/crash reconciliation and repeated side effects. A receipt alone does not establish success. Exactly-once delivery is not claimed. See the independent report and browser exports for the precise observed checks.

## Branch disposition and recovery

Default main is unchanged. DraftPR194 contains the candidate source. The advanced fix/evidence-provenance-20261114 branch and unique/open-PR work remain held. Two obsolete phase branches were archived and deleted only after ancestor, PR, protection, active-CI and reference checks; exact tips and recovery tags are recorded in branch-disposition.json. This evidence archive is an immutable non-release tag, not a new permanent branch or software release. The temporary earlier evidence branch will be removed only after archive reachability and remote dependency checks succeed; its final deletion proof is recorded separately.

## Remaining acceptance blockers

Full current MCP conformance/cancellation/concurrency, credential lifecycle, output injection/PII handling, arbitrary-server OS containment, durable side-effect reconciliation, complete dependency lock/build-source provenance, exhaustive historical document/diagram/example validation, complete branch consolidation/protection-rule visibility and environment-specific operational approval remain NOT VERIFIED or NOT IMPLEMENTED as documented. The baseline audit was bounded and must not be described as an exhaustive semantic review. Existing advanced security work remains unmerged. These gaps prevent VERIFIED LOCAL RELEASE CANDIDATE and production approval.

NEXT SAFE ACTION: reviewPR194 and retained unique work, finish the documented outstanding contract gates, and independently verify any later source revision. No source merge, public deployment or software release occurred.
