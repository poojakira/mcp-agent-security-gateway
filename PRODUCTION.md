> **Audit status (2026-11-15 UTC):** The most recent independently confirmed **nine-job** integrated run is [43674555508](https://github.com/poojakira/mcp-agent-security-gateway/actions/runs/43674555508) at `39c8566e40d4ab89ceb7fda61999de205cb35604`: **9/9 passed**, including 1,246 passed and 6 skipped per Python version in the general regression matrix, with dedicated live/Docker fixture tests passing. This is **historical relative to this documentation commit**, not current-head certification. Current poster binary parity remains **FAILED** ([run 43675028186](https://github.com/poojakira/mcp-agent-security-gateway/actions/runs/43675028186)); no issuer-side credential revocation, complete history scan, production deployment, or independent adversarial approval is established. **PRODUCTION NO-GO.**

> **Verified regression snapshot (2026-11-15 UTC; commit-specific, not a certification of subsequent edits):** [Phase 1–16 integrated CI run 43667123478](https://github.com/poojakira/mcp-agent-security-gateway/actions/runs/43667123478) passed all 5 jobs on `463a85f85cdb0aa6a6e287ffba56c1b364cfcd31`, with **1,246 passed and 6 skipped per Python 3.10, 3.11 and 3.12**. [Poster parity run 43667123466](https://github.com/poojakira/mcp-agent-security-gateway/actions/runs/43667123466) also passed on that exact commit. The poster evidence manifest intentionally pins an **older historical** same-SHA pair (integrated `43657370973`, poster `43657370960` at `a24f92c17f93d5c150eafe4ba7dce507ecb534b6`) with 1,245 passed and 6 skipped; those numbers are not current-head test counts. The checks do not certify production security or visual parity of committed poster binaries. **PRODUCTION NO-GO.**

> **2026-11-14 release-gate update:** Closed, unmerged audit PR #187 proposed protected read and discovery revocation fixes; these are not certified as merged to main. Direct same-user invocation of the downstream server is still an explicitly demonstrated bypass; mandatory isolation and independent testing are required. Historical CI results do not certify the new head. **PRODUCTION NO-GO.**

> **Evidence reconciliation (2026-11-11; living reference):** Historical results below retain their original dates and denominators. Historical November 11 tested Phase 1–16 development SHA was `43a72c8984bf9a472b9055d4f9e84cc759f61718` ([CI](https://github.com/poojakira/mcp-agent-security-gateway/actions/runs/42971171992): 1,211 passed, 6 skipped per Python version), **not** a merged or production-approved release. Offline research tests require no paid provider or provider-issued API keys; deployed HTTP authentication and unverified real credential revocation remain separate. See [operating restrictions](PRODUCTION.md) and [release evidence](docs/review/PHASE1_16_RELEASE_CANDIDATE_NO_GO_20261110.md).

# Operating Contract and Production Release Restrictions

**Tag release interlock (audit branch):** `.github/workflows/release.yml` now checks `scripts/check_release_authorization.py` for an explicit GO, matching tag, matching full commit SHA and approval reference before publishing. To avoid administrator bypass, enforce protected `release` environment reviewers and restricted release tags in GitHub Settings. This check is not a production authorization by itself. **NO-GO remains mandatory.**

> **Status: PRODUCTION NO-GO.** This is a target operating and acceptance contract, **not evidence that a production service exists**. Current development and experimental results are recorded in [PR #167](https://github.com/poojakira/mcp-agent-security-gateway/pull/167) and the [release-readiness gate](docs/review/PHASE13_RELEASE_READINESS.md).

## System role and boundaries

The MCP Agent Security Gateway evaluates supported JSON-RPC/MCP requests using configured authorization, policy, inspection and audit components. Some paths return inspection decisions for an integrating client to enforce; others proxy a bounded subset of tool calls. The service does not intercept direct OS/network access and does not guarantee that every client reaches the gateway.

The HTTP inspection service, stdio proxy, offline identity pilots and protected first-party server have **different security properties**. No optional pilot should be presented as a universally enabled production control.

## Mandatory release gate

All applicable lint, type checks, regressions, vulnerability scans, dependency provenance checks, container builds and disposable integration smoke tests must pass on the **exact promoted commit**. That is necessary but not sufficient. Promotion also requires documented and independently verified:

1. Trusted client/tenant identity, policy authorization and revocation for every supported entry point, including restarts and concurrent requests.
2. Non-bypassable routing and real outbound host/IP/port/DNS/redirect restrictions in the intended deployment.
3. Crash/timeout/lost-acknowledgment effect reconciliation with durable, trusted operation-key custody and explicit `UNKNOWN` outcomes.
4. A versioned MCP protocol/transport/method matrix with negative and interoperability tests.
5. Representative independent benign/adversarial validation with reported limitations and false-positive costs.
6. Dependency/image provenance, license and SBOM review, secret scans, container and host restrictions, audit failure behavior and incident/rollback exercises.
7. An exact-SHA release manifest, signed-off residual-risk register and **explicit accountable human authorization**.

Until these gates are closed, the decision remains **NO-GO**, even if a workflow named `Production Gate` reports success.

## Configuration and operations

- Require fresh, operator-controlled authentication material. Reject known retired demonstration credentials and missing required production settings.
- Do not put secrets in Git, sample Compose configurations, CI source or runtime logs; use a protected secret facility where deployed. A local lab key is not evidence of trusted identity.
- Bind local development service ports to loopback. This is *not* a production perimeter or authenticated proxy.
- Default to the network socket peer for source attribution; accept forwarded addresses only from explicitly trusted, sanitizing proxies.
- Treat logs, W3C trace context, SIEM exports, WAL and hash-chained audit entries as supporting evidence with bounded trust. Verify durability, access controls and log-failure handling separately.
- Keep immutable artifact identifiers, reproducible builds, reviewable configuration, rollback and documented incident procedures.
- Never claim SLOs, live uptime, SOC effectiveness, global detector precision/recall, exactly-once side effects or broad sandbox isolation without measured deployment evidence.

## Development verification and evidence

See [RUNBOOK.md](RUNBOOK.md) for local exercises, [THREAT_MODEL.md](THREAT_MODEL.md) for attacker assumptions, [VERIFIED_METRICS.md](VERIFIED_METRICS.md) for dated October baseline measurements and [release gate](docs/review/PHASE13_RELEASE_READINESS.md) for outstanding requirements. Draft integration changes are unmerged and must be reviewed against `main`.

No production deployment, real credential revocation, independently audited environment or customer-scale acceptance is established by this document.
