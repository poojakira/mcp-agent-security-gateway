# Phase 1–16 remediation and production acceptance tracker

**Decision: PRODUCTION NO-GO.** This is a tracked engineering backlog, not proof of release acceptance. Audit branch source baseline: `2158ab58e4a07a5c49b70c659996653a92f661c8`. This remediation branch is intentionally not merged to `main`.

## Verified observations

- Historical integrated five-job run [43657894182](https://github.com/poojakira/mcp-agent-security-gateway/actions/runs/43657894182) passed at audit SHA `2158ab58e4a07a5c49b70c659996653a92f661c8`, with 1,245 passed and 6 skipped per Python version. This is **not** a validation of the remediation head.
- Poster provenance workflow [43661291942](https://github.com/poojakira/mcp-agent-security-gateway/actions/runs/43661291942) succeeded at `96ed7d1b61815e40da37103f6bbd3a36721796c9`.
- Correct historical same-source poster and integrated pair: runs 43657370960 and 43657370973 at `a24f92c17f93d5c150eafe4ba7dce507ecb534b6`. The manifest validates run status, workflow identity and SHA; it does not independently establish every numeric claim from the job logs.
- Current remediation head must pass a new five-job integrated matrix, poster rendering, and additional security checks before merge. Six skips require explicit review.

## Critical unresolved engineering controls

| Control | Required independent acceptance evidence | Status |
|---|---|---|
| Non-bypassable routing | Deny same-user direct MCP server invocation, direct process/socket/volume access, and untrusted Docker daemon control in the **actual deployment**; red-team attempts must fail without reliance on cooperative clients | NOT VERIFIED |
| External identity and revocation | Real IdP-bound client identity, tenant authorization, key rotation, revoked token and concurrent in-flight operation tests on all transports | NOT VERIFIED |
| Outbound access | Deny unauthorized IP/DNS/IPv6/redirect/proxy/metadata egress in network-enabled deployment, with packet-level observations | NOT VERIFIED |
| Durable consequences | Real external provider idempotency, reconciliation of timeout/lost acknowledgments, restart and crash cases with independently observed state | NOT VERIFIED |
| MCP interoperability | Frozen protocol/version/transport matrix including unsupported methods, notifications, cancellation and malformed frames | NOT VERIFIED |
| Adversarial benchmarking | Independent blinded cases, source provenance, false-positive cost, attack adaptations and predeclared thresholds | NOT VERIFIED |
| Credential lifecycle | Issuer-side inventory and rotation/revocation records, secret-store and historical exposure assessment | NOT VERIFIED |
| Release authorization | Exact promoted SHA, protected release environment and tags, independent reviewer approval and signed residual-risk acceptance | NOT VERIFIED |

## Merge and branch policy

- Do not delete `integration/phase1-16-verified`, `security/phase1-16-audit` or this remediation branch until PRs and unique commits are reviewed.
- At review time the remediation branch was 417 commits ahead of `main`, 0 behind, and 33 ahead of the integration branch. These are comparison counts, not proof that every commit is appropriate for `main`.
- Prefer reviewable staged integration, branch protection and exact-head CI over an unreviewed 400+ commit merge.
- Generated poster PDFs/PNGs from Actions must be visually inspected; passing automated text/page checks does not certify print readiness.

## Release rule

No production claim, release tag or deletion of provenance branches until every applicable control has independent evidence and accountable human GO. A passing test workflow cannot override this NO-GO.
