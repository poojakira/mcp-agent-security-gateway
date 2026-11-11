# Poster Metrics — Exact-Head CI Evidence, Not Product Effectiveness

> **Source commit:** `43a72c8984bf9a472b9055d4f9e84cc759f61718` (draft Phase 1–16 stack). **PRODUCTION NO-GO.** All numerical claims are limited to cited workflows and dates; no deployment efficacy or independent security certification is inferred.

| Metric | Snapshot value | Scope |
|---|---:|---|
| Regression tests | **1,211** | Passing tests per Python version, not a sum across versions |
| Skipped tests | **6** | Per Python version; skipped are not verified |
| Python versions | **3** | 3.10 / 3.11 / 3.12 all passed |
| Integrated CI jobs | **5/5** | [Run 42971171992](https://github.com/poojakira/mcp-agent-security-gateway/actions/runs/42971171992) |
| Exact-head workflows | **4/4** | Integrated, hygiene, supply-chain and real protected Docker |
| Local process-crash cases | **3** | Before reservation, post-reservation and post-effect/pre-ack |
| Known Python advisories | **0 found** | Installed CI environment, public database at run time; not a promise |
| Production status | **NO-GO** | No external deployment or independent approval established |

## Scoped reproducibility

- Python matrix: [42971171992](https://github.com/poojakira/mcp-agent-security-gateway/actions/runs/42971171992).
- Tracked-file/history patterns and high-severity Bandit hygiene: [42971171965](https://github.com/poojakira/mcp-agent-security-gateway/actions/runs/42971171965).
- Installed Python CycloneDX and `pip-audit`: [42971171775](https://github.com/poojakira/mcp-agent-security-gateway/actions/runs/42971171775).
- Actual restricted Docker startup and MCP discovery: [42971171991](https://github.com/poojakira/mcp-agent-security-gateway/actions/runs/42971171991).

## Prior synthetic detection benchmark — NOT a poster headline

The earlier 96-case author-curated regex-only benchmark reported TP=40, FN=8, FP=16, TN=32. It is **not** an independent or representative measurement. Do not infer guaranteed safety or population precision/recall from it.

## Metrics not claimed

- Latest statement coverage percentage: not measured in the cited 1,211-pass workflow.
- Universal agent interception, distributed exactly-once execution, DNS/redirect enforcement for networked deployments, external authentication, booking/payment confirmation.
- Zero vulnerabilities, zero leaked secrets in all history/deployments, confirmed live credential revocation, security certification, cost-free operation of all possible external systems.

## Cost/credential boundary

The cited local workflows use free development tooling and do not require provider-issued API keys for third-party model/payment services. The HTTP production service has a separate operator-authentication configuration; **the repository does not establish that every deployment is keyless**.
