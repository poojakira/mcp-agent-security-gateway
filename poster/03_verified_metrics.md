> **Latest verified evidence (2026-11-14 Phoenix / November 15 UTC):** [Full five-job integrated regression](https://github.com/poojakira/mcp-agent-security-gateway/actions/runs/43656575066) passed on source `5978d483329c4c3c29e313846172aeb75b2b2fc3`: **1,236 passed / 6 skipped per Python 3.10, 3.11 and 3.12**; isolated Docker and lab-security jobs also passed. [Poster render/parity](https://github.com/poojakira/mcp-agent-security-gateway/actions/runs/43656574988) passed on the same SHA. Earlier 1,211-test figures below are historical and must not be presented as current. Changes after this tested SHA (including release-authorization hardening) require their own exact-head tests. **PRODUCTION NO-GO**; direct downstream bypass and independent release acceptance remain unresolved.

# Poster Metrics — Exact-Head CI Evidence, Not Product Effectiveness

> **Current tested source commit:** `5978d483329c4c3c29e313846172aeb75b2b2fc3`; [CI run 43656575066](https://github.com/poojakira/mcp-agent-security-gateway/actions/runs/43656575066). Historical supply-chain runs use other commits. **PRODUCTION NO-GO.**

| Metric | Snapshot value | Scope |
|---|---:|---|
| Regression tests | **1,236** | Passing tests per Python version, not a sum across versions |
| Skipped tests | **6** | Per Python version; skipped are not verified |
| Python versions | **3** | 3.10 / 3.11 / 3.12 all passed |
| Integrated CI jobs | **5/5** | [Run 43656575066](https://github.com/poojakira/mcp-agent-security-gateway/actions/runs/43656575066) |
| Same-SHA workflows | **2/2** | [Integrated regression](https://github.com/poojakira/mcp-agent-security-gateway/actions/runs/43656575066) and [poster parity](https://github.com/poojakira/mcp-agent-security-gateway/actions/runs/43656574988); other workflows are historical |
| Local process-crash cases | **3** | Before reservation, post-reservation and post-effect/pre-ack |
| Known Python advisories | **0 found** | Installed CI environment, public database at run time; not a promise |
| Production status | **NO-GO** | No external deployment or independent approval established |

## Scoped reproducibility

- Latest Python matrix: [43656575066](https://github.com/poojakira/mcp-agent-security-gateway/actions/runs/43656575066) on `5978d483329c4c3c29e313846172aeb75b2b2fc3`.
- Poster source/render parity: [43656574988](https://github.com/poojakira/mcp-agent-security-gateway/actions/runs/43656574988) on the same SHA.
- Tracked-file/history patterns and high-severity Bandit hygiene: [42971171965](https://github.com/poojakira/mcp-agent-security-gateway/actions/runs/42971171965).
- Installed Python CycloneDX and `pip-audit`: [42971171775](https://github.com/poojakira/mcp-agent-security-gateway/actions/runs/42971171775).
- Actual restricted Docker startup and MCP discovery: [42971171991](https://github.com/poojakira/mcp-agent-security-gateway/actions/runs/42971171991).

## Prior synthetic detection benchmark — NOT a poster headline

The earlier 96-case author-curated regex-only benchmark reported TP=40, FN=8, FP=16, TN=32. It is **not** an independent or representative measurement. Do not infer guaranteed safety or population precision/recall from it.

## Metrics not claimed

- Latest statement coverage percentage: not measured in the cited 1,236-pass workflow.
- Universal agent interception, distributed exactly-once execution, DNS/redirect enforcement for networked deployments, external authentication, booking/payment confirmation.
- Zero vulnerabilities, zero leaked secrets in all history/deployments, confirmed live credential revocation, security certification, cost-free operation of all possible external systems.

## Cost/credential boundary

The cited local workflows use free development tooling and do not require provider-issued API keys for third-party model/payment services. The HTTP production service has a separate operator-authentication configuration; **the repository does not establish that every deployment is keyless**.
