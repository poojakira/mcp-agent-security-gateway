> **Evidence reconciliation (2026-11-11; living reference):** Historical results below retain their original dates and denominators. Latest tested Phase 1–16 development SHA is `43a72c8984bf9a472b9055d4f9e84cc759f61718` ([CI](https://github.com/poojakira/mcp-agent-security-gateway/actions/runs/42971171992): 1,211 passed, 6 skipped per Python version), **not** a merged or production-approved release. Offline research tests require no paid provider or provider-issued API keys; deployed HTTP authentication and unverified real credential revocation remain separate. See [operating restrictions](../../PRODUCTION.md) and [release evidence](../../docs/review/PHASE1_16_RELEASE_CANDIDATE_NO_GO_20261110.md).

# Detection Latency Microbenchmark

> **Review context (2026-11-09):** These figures describe a dated local microbenchmark only, not end-to-end MCP latency, service capacity, customer traffic or an SLO. The [integrated release-readiness gate](../../docs/review/PHASE13_RELEASE_READINESS.md) is **PRODUCTION NO-GO**.
> LOCAL SYNTHETIC-LOAD MICROBENCHMARK. Single process, in-memory engine, synthetic events. NOT a production throughput or SLA measurement.

- Generated: `2026-09-28T06:21:47Z`
- Events: **2000**
- Rules loaded: **6**

| Metric | Value (ms) |
|---|---|
| p50 | 0.4730 |
| p95 | 1.1930 |
| p99 | 1.7469 |
| min | 0.0013 |
| max | 4.2820 |
| mean | 0.5367 |

Local throughput (single process): ~1863 events/s.
