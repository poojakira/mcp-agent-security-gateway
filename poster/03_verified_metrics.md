> **Latest verified development evidence (2026-11-14 Phoenix / 2026-11-15 UTC):** [Integrated run 43657894182](https://github.com/poojakira/mcp-agent-security-gateway/actions/runs/43657894182) on audit commit `2158ab58e4a07a5c49b70c659996653a92f661c8`: **1,245 passed / 6 skipped per Python 3.10, 3.11 and 3.12; 5/5 jobs green**. This run is newer than the pinned poster evidence manifest, which intentionally references the earlier same-SHA pair [integrated 43657370973](https://github.com/poojakira/mcp-agent-security-gateway/actions/runs/43657370973) and [poster 43657370960](https://github.com/poojakira/mcp-agent-security-gateway/actions/runs/43657370960) on `a24f92c17f93d5c150eafe4ba7dce507ecb534b6`. The current documentation-fix commit is not covered by those historical runs. **PRODUCTION NO-GO.**

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
