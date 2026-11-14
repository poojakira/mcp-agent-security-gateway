# MCP Gateway — production security acceptance register

**Review date:** 2026-11-14 UTC  
**Integration branch:** `integration/phase1-16-remediation-20261109`  
**Release disposition:** **PRODUCTION NO-GO**. The development package workflow is a build/test gate, not a production authorization.

This register distinguishes implemented code, tests on disposable infrastructure, and missing live acceptance proof. **Do not mark a control complete merely because a synthetic test passes.**

| Requirement | What is implemented / tested | Residual acceptance barrier | Status |
|---|---|---|---|
| Git branch consistency | A two-parent reconciliation merge preserves `main`'s credential-retirement and live-stdio tests while retaining reviewed experimental controls; PR #167 is mergeable | Exact merged-tree reviews and maintainer approval; draft is not merged into main | **Candidate reconciled, unreleased** |
| Trusted identity and capability | Config rejects retired public demonstration key; OAuth/JWKS snapshot pilots and per-tool stdio capabilities, including deny-before-forward tests; distinct service-key quotas | End-to-end verified external issuer, tenant/role binding, token audience, least-privilege scopes, credential revocation and cross-host freshness | **OPEN / NO-GO** |
| Mandatory tool routing | Production stdio requires strict MCP methods, a trusted nonempty tool allowlist and offline container isolation; direct Python constructor tested | Prove that every intended agent/tool client is forced through the gate; direct downstream access must be blocked in real target topology | **OPEN / NO-GO** |
| Network egress | Production stdio rejects internal sidecar profile without independently verified egress fencing; offline Docker uses network-none | Real outbound policy, DNS/redirect/CIDR/IP/port controls, proxy attestation, dual stack bypass tests, and operator-root boundary | **OPEN / NO-GO** |
| Durable side effects | SQLite effect journal, local revocation fence, independently observed bounded `package.json` change and explicit uncertain outcomes | Cross-host crash/power-loss/lost-ack/duplicate-operation validation and external side-effect reconciliation | **OPEN / NO-GO** |
| MCP transport/interoperability | JSON-RPC duplicate-key, batch atomicity, strict method gate; real disposable filesystem MCP stdio tests | Full supported MCP method and transport matrix across independently maintained client/server versions, error cases and cancellation semantics | **OPEN / NO-GO** |
| Adversarial efficacy | Red-team regressions, restricted Docker fixture, curated 96-case regex benchmark and malicious-response smoke test | Independent blinded, legally sourced representative benign/adversarial evaluation, including false-positive and bypass costs | **OPEN / NO-GO** |
| Audit and incident response | Production config requires `MCP_AUDIT_HMAC_KEY` at least 32 bytes; hash-chained WAL/audit with local fsync; failed local SIEM writes degrade readiness | Authenticated off-host append-only checkpointing, independent key custody, local disk-loss testing, end-to-end SIEM receipt/replay/alerting and incident drill | **OPEN / NO-GO** |
| Build/supply-chain | Python matrix, Windows checks, Ruff, Pyright, CodeQL, vulnerability scan, SBOM generation, Docker build and poster parity | Release artifact pinned image digests, dependency locks, provenance attestations and signed SBOM/license review on the exact promoted SHA | **OPEN / NO-GO** |
| Release authorization | CI validates source changes and documents residual risk; programmatic workflow intentionally calls itself a *development package gate* | Accountable human decision, deployment risk owner signoff, rollback and incident rehearsal, independent review and exact-SHA release manifest | **NOT APPROVED** |

## Automatic negative tests

- `tests/test_adversarial_release_regressions.py`: unauthenticated rate-budget exhaustion, distinct configured service-key budgets, production direct construction restrictions, strict tool allowlist/method enforcement, internal egress profile refusal, and local SIEM readiness degradation.
- `tests/test_live_stdio_policy_backport.py`: main-branch tool authorization, method restrictions, production refusal and malformed JSON-RPC; malformed methods legitimately return JSON-RPC Invalid Request `-32600` before forwarding.
- `tests/test_http_framing.py`: origin-form request parsing, strict CRLF/header tokens, duplicate security headers, unambiguous numeric Content-Length and malformed input.
- `tests/test_phase16_revocation_safe_commit.py`, `tests/test_phase15_consequence_verification.py` and `tests/test_phase11_effect_journal.py`: bounded local journal, outcome observation and revocation cases.
- `tests/test_live_filesystem_mcp.py`: disposable real MCP filesystem server, authorized and denied writes/reads, malicious response blocking and revocation.

**Benchmark limit:** The 96-case historical regex-only fixture is not an independent blind population benchmark or the gateway's integrated precision/recall.

## Safety of review methodology

Only repo-owned, synthetic or disposable tests are authorized. No provider API keys, paid services, real customer traffic, live external penetration tests, production endpoint scans, or issuer-side secret revocation are claimed. Unverified acceptance barriers require deployment environment details and independent test ownership; they cannot be truthfully closed inside this repository alone.

[Full autopsy](ADVERSARIAL_AUTOPSY_2026-11-14.md) · [Release gate](PHASE13_RELEASE_READINESS.md) · [Draft PR #167](https://github.com/poojakira/mcp-agent-security-gateway/pull/167).
