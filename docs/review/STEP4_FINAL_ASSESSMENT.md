# Step 4 — Security engineering assessment (scoped prototype validation verified)

> **Evidence boundary (2026-11-09):** The cited prototype checks and attack controls are evidence of a bounded evaluation, not production or third-party certification. [Production release gate](../../docs/review/PHASE13_RELEASE_READINESS.md): **NO-GO**. [Integration candidate](https://github.com/poojakira/mcp-agent-security-gateway/pull/167): draft, unmerged.
**Branch:** `step4/egress-input-validation` (draft PR #149, stacked on draft PR #148).
**Scope:** production-oriented *prototype hardening*, NOT production certification.

## Tested controls introduced in Step 4

1. Fail-closed validation for malformed, recognized outbound destination fields.
2. Bounded nested parsing of recognized `url`, `host`, `endpoint`, `target` and `destination` keys in JSON tool arguments, with explicit nesting/size guards.
3. Optional trusted operator-supplied authoritative permission callback in `ACLGuard`, with deny on errors/ambiguous responses; authorization recheck before protected tool response release.
4. Protocol envelope validation: reject invalid JSON-RPC 2.0 version, malformed `method`/`params`, invalid identifier types, and duplicate request IDs in a batch before forwarding.
5. Downstream response validation for **every request**, including tool discovery, prompts and resources, with per-response detector inspection and request-ID correlation.
6. Bounds for stdio request and response sizes plus a downstream response timeout. These avoid unbounded framing waits but do not undo side effects already performed by an MCP server.
7. Isolated synthetic and disposable local subprocess regressions. No remote targets or customer data are used.

## Required evidence

**Verified GitHub Actions run:** [#42444861042](https://github.com/poojakira/mcp-agent-security-gateway/actions/runs/42444861042) completed successfully at source/workflow commit `706aa40df2eff64e151b5f9f98e66dabdf54e5de`. The subsequent commits only updated documentation.

- Python 3.10: **925 passed, 1 skipped**, **82.72%** coverage.
- Python 3.11: **925 passed, 1 skipped**, **82.69%** coverage.
- Python 3.12: **925 passed, 1 skipped**, **82.69%** coverage.
- Focused Step 4/test regression set: **144 passed** per matrix version.
- Ruff lint/formatter, Bandit scan and focused Pyright: passed.
- This stacked PR did **not** execute the complete main-branch CI workflow (e.g., separate Docker, CodeQL, Windows runners). Previous PR #148 checks do not certify the latest Step 4 modifications.
- No paid hosted service or production target was used. The validation ran on GitHub standard runners in a public repository.

The above constitutes the evidence for bounded source-level prototype hardening, not for the still-open deployment requirements.

## Risk register: production blockers

| ID | Severity | Control gap / acceptance requirement | Status |
|---|---|---|---|
| S4-01 | High | A trusted, authenticated and bound user/tenant identity provider with per-session isolation and tested negative cases | **OPEN** |
| S4-02 | High | Genuine network egress enforcement (container/network namespaces, DNS resolution, redirects, firewalls). JSON field checks alone cannot contain sockets | **OPEN** |
| S4-03 | High | A distributed, authenticated authoritative permission service or durable CDC with rollback-proof sequence, two-node testing, failover and restart recovery | **OPEN** |
| S4-04 | High | Streaming, unsolicited downstream notifications, multiplexed requests and cancellation protocol-state tracking. Current stdio is sequential and assumes one expected response set per request | **OPEN** |
| S4-05 | Medium | Timeout and crash idempotency. A forwarded write may already have executed despite a fail-closed client response; require side-effect ledger or protected compensating operations | **OPEN** |
| S4-06 | Medium | Detector evaluation with independent held-out benign and malicious samples, precision/recall/FPR and adversarial encodings | **OPEN** |
| S4-07 | Medium | Operator-policy coverage for unrecognized/opaque tool schemas; nested known-key scanning is bounded but not an authoritative network boundary | **OPEN** |
| S4-08 | Medium | CI parity and representative deployment performance/availability under concurrency, authorization service latency, abnormal reconnects and backpressure | **OPEN** |

## Verdict rules

- **Prototype implementation and scoped CI validation:** **COMPLETE** for source commit `706aa40d` (three Python versions, full suite and focused static checks). Documentation commits after this source SHA did not alter runtime code.
- **Step 4 production security gate:** **NOT COMPLETE** until S4-01 through S4-08 are independently exercised in an authorized representative environment or explicitly removed from the supported product scope and proven unreachable.
- No merge, deployment, private CI charge, credential sharing or claim of third-party certification is authorized by this document.

The architecture includes optional interfaces and simulated tests, not actual production authorization or network control-plane infrastructure.
