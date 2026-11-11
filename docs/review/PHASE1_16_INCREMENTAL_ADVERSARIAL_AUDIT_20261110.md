> **Evidence reconciliation (2026-11-11; historical phase/snapshot):** Historical results below retain their original dates and denominators. Latest tested Phase 1–16 development SHA is `43a72c8984bf9a472b9055d4f9e84cc759f61718` ([CI](https://github.com/poojakira/mcp-agent-security-gateway/actions/runs/42971171992): 1,211 passed, 6 skipped per Python version), **not** a merged or production-approved release. Offline research tests require no paid provider or provider-issued API keys; deployed HTTP authentication and unverified real credential revocation remain separate. See [operating restrictions](../../PRODUCTION.md) and [release evidence](../../docs/review/PHASE1_16_RELEASE_CANDIDATE_NO_GO_20261110.md).

# Phase 1–16 adversarial audit — incremental evidence register (2026-11-10)

> **PRODUCTION NO-GO.** This is an incremental source-and-CI review, not a completed audit of every repository file, a full penetration test, live key inventory, or a production release approval. The audit branch is a draft review branch and has not been merged.

## Baseline and methods

- Integration baseline: `861a80258bd91a8c1d84b9a9c4e4f8c533f6467e`, draft PR #167, 156 files changed against main at review.
- CI from baseline: named GitHub Actions workflows CI, Phase 1–16 integrated security candidate, Security Hygiene, and Real MCP Filesystem Smoke Test reported success. **A workflow named Production Gate passing does not prove deployment safety.**
- Source files inspected in detail include `src/mcp_monitor/proxy/stdio_proxy.py`, `src/mcp_monitor/policy/policy_engine.py`, `src/mcp_monitor/protected_repo_server.py`; selected regression tests, dependency manifest, selected workflows, and `PRODUCTION.md`, `PHASE13_RELEASE_READINESS.md`, `PHASE14_BYPASS_DECISION.md`. This is **not** all source, tests, configuration, or Markdown files.
- No live third-party key or paid service was intentionally created or used. GitHub connector authorization is managed outside the project; this audit did not commit credentials.
- No local full repository checkout was possible in the execution environment because external Git remote name resolution failed. Source/CI evidence came from GitHub's repository interface. New focused tests require CI validation.

## Findings (severity is provisional; acceptance requires independent validation)

| ID | Priority | Evidence / mechanism | Repair and acceptance |
|---|---|---|---|
| MCP-001 | High | Hardened `tools/list` historically returned descriptions of non-authorized tools, even while `tools/call` blocked them. This is an instruction/tool-poisoning exposure, not proof of unauthorized execution. | Draft PR #169 filters tool discovery to policy-authorized capabilities, rejects malformed/duplicate listings and adds focused tests. **Exact-head CI PASSED** for PR #169 head `7f62c0a5c9cb4d896bdb3c4cbc883483cf076066` ([run #42962274335](https://github.com/poojakira/mcp-agent-security-gateway/actions/runs/42962274335)); independent adversarial review and merge remain OPEN. |
| MCP-002 | Critical release blocker | `PRODUCTION.md` and Phase 14 record that users or agents with direct host/subprocess privileges can bypass the gateway. A middle-layer check is not an OS boundary. | Prove enforced routing and deployment isolation with direct-server, direct-network and host-credential bypass attempts. |
| MCP-003 | High | In `StdioMCPProxy`, `strict_mcp_methods=False` and a `PolicyEngine` without a tool allowlist remain supported library defaults. The hardened CLI opts into strictness. Safety therefore depends on the deployment entry point. | Explicit production-only constructor/profile that refuses permissive defaults; all configured entry points tested. |
| MCP-004 | High | The optional effect journal accepts `_gateway_operation_key` from MCP parameters. The journal reserves before sending, but key issuance is not by itself a verified trusted authority. | Bind operation IDs to authenticated user, approved intent and immutable request digest in a separate trusted issuer. Test forgery, reuse and restart. |
| MCP-005 | High | On a completed downstream JSON-RPC result, the generic proxy can mark a journal operation completed, but downstream success is not independent proof of external side effect. Separate Phase 15 consequence verifier applies only to the scoped protected manifest adapter. | Carry an explicit UNKNOWN outcome; independently reconcile business effects before reporting VERIFIED. Never blindly retry UNKNOWN writes. |
| MCP-006 | High | Egress checks in the policy engine inspect recognized destination-shaped argument keys, not arbitrary implicit server-side network behavior. Phase 9 reports no general outbound forwarding proof. | Enforce actual network egress at a trusted proxy/firewall boundary; test redirects, DNS rebinding, private IPs, alternate schemes, non-HTTP egress and direct sockets. |
| MCP-007 | High | Regex-only Phase 12 benchmark is 96 author-curated synthetic cases: TP40/FN8/FP16/TN32. It is not representative deployment evidence. | Independent threat-and-benign fixtures, measure missed attacks, false alarms, latency and workload impact; re-test after changes. |
| MCP-008 | High | `PRODUCTION.md` explicitly leaves identity lifecycle, revocation races, crash/restart recovery, broad protocol interoperability and independent deployment sign-off open. | Run a combined exact-commit acceptance matrix with fault injection and human release approval. |
| MCP-009 | Medium | `.gitleaksignore` contains historical narrowly scoped suppressions and `security-hygiene.yml` implements regex-based tracked-file/history checks. These do not establish a complete secret inventory or actual credential revocation. | Reconcile suppressions, scan Git history, artifacts and deployment secret stores; any confirmed live credential must be disabled at its issuer and reissued outside Git. |
| MCP-010 | Medium | Historical Phase 13 documentation contained the stale claim that PR #150 was unmerged, although GitHub shows a merge on 2026-11-09. | Corrected the two current audit/release documents in the stacked documentation review branch; verify the remaining historical Markdown and release evidence before closure. |

## Claim-to-evidence matrix

| Claim | Supporting evidence | What remains unproved |
|---|---|---|
| Tool-call deny before forwarding | `tests/test_stdio_policy_integration.py` uses `FakeTransport` and checks that denied calls produce no send | Full client/server interoperability and bypass resistance |
| Hardened method deny | `tests/test_phase13_capability_launch.py` tests `resources/read`, `prompts/get` denied when strict mode is on | Production mode enforced at every entry point |
| Malformed downstream data not released | `tests/test_stdio_adversarial_responses.py` uses injectable transports to simulate malicious frames | Every schema and content form, real malicious server |
| Authorized manifest effect | `tests/test_first_party_protected_mcp.py`, Phase 14 evidence | Host containment and real third-party effects |
| Consequence verification | `src/mcp_monitor/protocol/consequence_verifier.py` and Phase 15 tests | Generalized banking/ticketing/medical confirmation |
| Audit evidence | Hash chain and SIEM code, `PRODUCTION.md` limitations | Independent trusted anchoring, failure containment, log privacy |
| No committed provider keys | Latest GitHub Security Hygiene run was green | Full unindexed history, CI artifacts, local/deployment stores, live revocation |

## Devil's advocate / pre-mortem

**Strongest counterargument:** A gateway is irrelevant when the agent still possesses direct filesystem, browser, socket, payment, or downstream MCP access. Do not evaluate only the happy path through `handle_message`; force an adversarial attempt to reach the downstream effect without it.

**Likely failure chain:** permitted discovery response carries deceptive instructions -> detector misses them -> agent chooses an approved-but-overpowered tool -> underlying server makes a request to an unexpected host -> the response claims success -> user sees false assurance. The primary defenses are narrowly scoped capabilities, untrusted-content boundaries, trusted network isolation, independent result verification, and default-deny deployment, rather than another classifier alone.

**Black swan:** a revoked booking operation commits at the provider while the network acknowledgment is lost. The gateway must not claim failure or retry blindly, or it may charge twice. Store and reconcile an `UNKNOWN` outcome, use provider idempotency where available, and require operator action when indeterminate.

**Competing thesis:** security-specific agent adapters with strong host separation can outperform a generic gateway whose only advantage is regex scanning. This must be tested on matched scenarios rather than asserted.

## Test matrix remaining

- PR #169 exact-head lint/format/pytest matrix and scoped Docker tests passed ([run #42962274335](https://github.com/poojakira/mcp-agent-security-gateway/actions/runs/42962274335)); independent red-team testing and merge review remain open.
- Static scanners: secret scanning (including history), Bandit/Semgrep where installed, SBOM, dependency/license and image provenance. Review false positives manually.
- Property-based: JSON-RPC ID preservation, allowlist monotonicity, byte limits, unknown methods, duplicate keys.
- Mutation/fuzz: change deny/allow branches and assert negative tests fail.
- Side-effect fault injection: crash before reserve, after reserve, after dispatch, before ACK, after ACK, journal corruption; restart recovery.
- Authorization adversarial: forged principal, forged operation key, tenant confusion, midflight revocation, direct server access.
- Network adversarial: DNS rebinding, redirects, private-IP traversal, alternate URL casing, nested/encoded destinations, direct sockets.
- Independent prompt-injection and tool-poisoning benchmark, reproducible false-positive/false-negative reports.
- Real client/server and versioned MCP transport/method interoperability matrix.
- Resource and performance profiling, chaos/recovery drills, and release rollback exercises.

## Release decision

**NO-GO** for real customer payment, banking, medical, or ticket-booking operations. **Limited lab evaluation** may continue on non-sensitive disposable data without API keys or external services.

Do not label any finding closed solely because a patch or test exists. A closure requires exact-head passing CI, repeatable exploit/negative regression evidence, independent review of the relevant boundary, and updated documentation.
