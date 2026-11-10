# PR #167 — security-code-scanning triage and release boundary

> **Evidence boundary (2026-11-09):** Closed lint or CodeQL jobs do not automatically resolve every security review finding, historical alert, or disputed retired-key fingerprint triage. [Production release gate](../../docs/review/PHASE13_RELEASE_READINESS.md): **NO-GO**. [Integration candidate](https://github.com/poojakira/mcp-agent-security-gateway/pull/167): draft, unmerged.
**Status: DRAFT / NOT APPROVED / PRODUCTION NO-GO.** This document is a code-review record, not an adjudication of live deployed security. Recheck every entry against the final exact-head GitHub checks and review comments before resolving alerts.

## Findings and engineering disposition

| Finding | Code | Disposition |
| --- | --- | --- |
| Missing parent initializer and overwritten container_name | `src/mcp_monitor/proxy/stdio_proxy.py` | Fixed: `InternalDockerTransport` now initializes via `OfflineDockerTransport.__init__`; added constructor identity regression. Verify original review threads and CI. |
| No-effect statements in Protocol declarations | `src/mcp_monitor/protocol/multiplex.py` | Changed four abstract protocol methods to explicit `raise NotImplementedError` bodies, preserving structural typing. Verify CodeQL and typing tests. |
| Empty exception handler on reader cancellation | `src/mcp_monitor/protocol/multiplex.py` | Added explanation for expected `CancelledError` after `task.cancel()`; continue closing the underlying transport. Verify cancellation regression. |
| All-interface listener | `tests/fixtures/phase9_sidecar_fixture.py` | Removed wildcard bind. Synthetic non-forwarding sidecar now binds only to the resolved private Docker IPv4 and fails closed for wildcard/loopback/public addresses. New tests verify address rejection. The fixture is not an online egress policy enforcement proxy. Docker end-to-end test mandatory before signoff. |
| SHA-256 matching retired public key | `src/mcp_monitor/production/config.py` | **Security-review exception requested; not automatically resolved.** SHA-256 is used to fingerprint an already publicly exposed, fixed demonstration API key and block reuse; this is not password storage, KDF derivation, or a new credential verifier. A password-hashing alert should not be addressed by switching a known-value membership check to Argon2/PBKDF2 without a specific threat model. Actual accepted gateway API keys, however, must still be reviewed for secure comparison, storage, entropy, rotation, and revocation. Treat the alert as unresolved until a reviewer validates the distinct purpose. |

## Why the local fixture must not be promoted

The Phase 9 sidecar returns a static health response and does not validate destinations, DNS changes, redirects, CIDR egress policy, TLS identities or HTTP requests. Binding it to a private container address reduces its listener surface but **does not** make it a production-safe egress gateway. The Docker `--internal` network remains a disposable laboratory-only boundary. Production requirement P13-04 remains OPEN.

## Required exact-head validation

1. Check successful lint/format, Python 3.10/3.11/3.12 tests, Phase 9 real Docker networking, CodeQL, Trivy and dependency/SBOM scans on **the same final commit**.
2. Inspect each new CodeQL finding, including unreviewed issues on base or historical branches; do not use the number of closed review comments as a security metric.
3. Test revocation during genuine side-effects and lost acknowledgments after restart in all supported runtimes. The Phase 15/16 local SQLite proof does not supply distributed safety.
4. Reconcile all source and workflow differences against `main`, the merged PR #150 security remediation and divergent PR #147. Check dependencies and the historical credential exposure separately.
5. Do not merge or deploy without real identity enforcement, egress restrictions, production-grade effect reconciliation, protocol compatibility matrix, representative independent adversarial tests, complete supply-chain review and accountable human release approval.

## Decision

**Production release remains blocked.** This triage is scoped engineering progress. It does not close P13-01 through P13-10, nor authorize any production deployment.
