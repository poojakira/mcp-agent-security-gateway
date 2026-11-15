> **Verification update (2026-11-15 UTC; exact source SHA):** Gateway commit `8049ec46e8337ee4eabff9cfa97ffe4663f4febc` passed [nine-job Phase 1–16 integrated security CI](https://github.com/poojakira/mcp-agent-security-gateway/actions/runs/43748347243) and [Poster Artifact Parity](https://github.com/poojakira/mcp-agent-security-gateway/actions/runs/43748347212). The earlier PDF raster mismatch was traced to continuously animated SVG print frames; the print stylesheet now freezes animations, and the three committed poster binaries were regenerated ([reconciliation run](https://github.com/poojakira/mcp-agent-security-gateway/actions/runs/43748301101)). Historical 782/81.93%, 1,245/6 and 1,246/6 figures belong only to their cited dated CI runs; the final nine-job run is **not** a newly measured coverage figure. This note records successful verification of the cited SHA, not automatic certification of later edits. **PRODUCTION NO-GO** remains in force.

> **Audit status (2026-11-15 UTC):** The most recent independently confirmed **nine-job** integrated run is [43674555508](https://github.com/poojakira/mcp-agent-security-gateway/actions/runs/43674555508) at `39c8566e40d4ab89ceb7fda61999de205cb35604`: **9/9 passed**, including 1,246 passed and 6 skipped per Python version in the general regression matrix, with dedicated live/Docker fixture tests passing. This is **historical relative to this documentation commit**, not current-head certification. At that earlier snapshot, poster binary parity was **FAILED** ([run 43675028186](https://github.com/poojakira/mcp-agent-security-gateway/actions/runs/43675028186)); no issuer-side credential revocation, complete history scan, production deployment, or independent adversarial approval is established. **PRODUCTION NO-GO.**

> **Verified regression snapshot (2026-11-15 UTC; commit-specific, not a certification of subsequent edits):** [Phase 1–16 integrated CI run 43667123478](https://github.com/poojakira/mcp-agent-security-gateway/actions/runs/43667123478) passed all 5 jobs on `463a85f85cdb0aa6a6e287ffba56c1b364cfcd31`, with **1,246 passed and 6 skipped per Python 3.10, 3.11 and 3.12**. [Poster parity run 43667123466](https://github.com/poojakira/mcp-agent-security-gateway/actions/runs/43667123466) also passed on that exact commit. The poster evidence manifest intentionally pins an **older historical** same-SHA pair (integrated `43657370973`, poster `43657370960` at `a24f92c17f93d5c150eafe4ba7dce507ecb534b6`) with 1,245 passed and 6 skipped; those numbers are not current-head test counts. The checks do not certify production security or visual parity of committed poster binaries. **PRODUCTION NO-GO.**

# Poster Metrics — Exact-Head CI Evidence, Not Product Effectiveness

> **Pinned historical poster-evidence source commit:** `a24f92c17f93d5c150eafe4ba7dce507ecb534b6`; [CI run 43657370973](https://github.com/poojakira/mcp-agent-security-gateway/actions/runs/43657370973). Historical supply-chain runs use other commits. **PRODUCTION NO-GO.**

| Metric | Snapshot value | Scope |
|---|---:|---|
| Regression tests | **1,245** | Passing tests per Python version, not a sum across versions |
| Skipped tests | **6** | Per Python version; skipped are not verified |
| Python versions | **3** | 3.10 / 3.11 / 3.12 all passed |
| Integrated CI jobs | **5/5** | [Run 43657370973](https://github.com/poojakira/mcp-agent-security-gateway/actions/runs/43657370973) |
| Same-SHA workflows | **2/2** | [Integrated regression](https://github.com/poojakira/mcp-agent-security-gateway/actions/runs/43657370973) and [poster parity](https://github.com/poojakira/mcp-agent-security-gateway/actions/runs/43657370960); other workflows are historical |
| Local process-crash cases | **3** | Before reservation, post-reservation and post-effect/pre-ack |
| Known Python advisories | **0 found** | Installed CI environment, public database at run time; not a promise |
| Production status | **NO-GO** | No external deployment or independent approval established |

## Scoped reproducibility

- Pinned poster-evidence Python matrix: [43657370973](https://github.com/poojakira/mcp-agent-security-gateway/actions/runs/43657370973) on `a24f92c17f93d5c150eafe4ba7dce507ecb534b6`.
- Poster source/render parity: [43657370960](https://github.com/poojakira/mcp-agent-security-gateway/actions/runs/43657370960) on the same SHA.
- Tracked-file/history patterns and high-severity Bandit hygiene: [42971171965](https://github.com/poojakira/mcp-agent-security-gateway/actions/runs/42971171965).
- Installed Python CycloneDX and `pip-audit`: [42971171775](https://github.com/poojakira/mcp-agent-security-gateway/actions/runs/42971171775).
- Actual restricted Docker startup and MCP discovery: [42971171991](https://github.com/poojakira/mcp-agent-security-gateway/actions/runs/42971171991).

## Prior synthetic detection benchmark — NOT a poster headline

The earlier 96-case author-curated regex-only benchmark reported TP=40, FN=8, FP=16, TN=32. It is **not** an independent or representative measurement. Do not infer guaranteed safety or population precision/recall from it.

## Metrics not claimed

- Latest statement coverage percentage: not measured in the cited 1,245-pass workflow.
- Universal agent interception, distributed exactly-once execution, DNS/redirect enforcement for networked deployments, external authentication, booking/payment confirmation.
- Zero vulnerabilities, zero leaked secrets in all history/deployments, confirmed live credential revocation, security certification, cost-free operation of all possible external systems.

## Cost/credential boundary

The cited local workflows use free development tooling and do not require provider-issued API keys for third-party model/payment services. The HTTP production service has a separate operator-authentication configuration; **the repository does not establish that every deployment is keyless**.
