> **Evidence reconciliation (2026-11-11; living reference):** Historical results below retain their original dates and denominators. Latest tested Phase 1–16 development SHA is `43a72c8984bf9a472b9055d4f9e84cc759f61718` ([CI](https://github.com/poojakira/mcp-agent-security-gateway/actions/runs/42971171992): 1,211 passed, 6 skipped per Python version), **not** a merged or production-approved release. Offline research tests require no paid provider or provider-issued API keys; deployed HTTP authentication and unverified real credential revocation remain separate. See [operating restrictions](../PRODUCTION.md) and [release evidence](../docs/review/PHASE1_16_RELEASE_CANDIDATE_NO_GO_20261110.md).

# Performance Baseline

> **Review context (2026-11-09):** All performance measurements are environment- and commit-specific. Local latency or single-process throughput is not an independently measured production SLO. The [integrated release-readiness gate](../docs/review/PHASE13_RELEASE_READINESS.md) is **PRODUCTION NO-GO**.
This document records measured performance for `mcp-agent-security-gateway`.
All numbers are produced by [`benchmarks/perf_gate.py`](../benchmarks/perf_gate.py),
which exercises the real `MCPSecurityMonitor.inspect_call()` path (4 detectors +
an on-disk hash-chained audit append) on a single thread.

## How to reproduce

```bash
pip install -e ".[dev]"
python benchmarks/perf_gate.py --iterations 1000 --warmup 50
```

The script prints a JSON report and exits non-zero if a gate fails.

## Measured baseline

Environment: Windows, Python 3.12, single thread, 500 iterations.

| Metric | Measured | Gate |
|--------|----------|------|
| p95 latency (per inspected call) | ~4 ms | must be < 15 ms |
| Throughput (single thread) | ~350 calls/sec | must be > 250 calls/sec |

Notes:
- Throughput is bounded by the synchronous audit-log write on each call. Higher
  throughput is achievable by batching audit writes or using an async log
  shipper; that work is not yet done, so the gate reflects the current
  synchronous implementation.
- These numbers are single-thread. Concurrent throughput has not been measured
  and is intentionally not claimed here.

## Regression policy

- The CI perf gate uses the thresholds above.
- If a change legitimately shifts the baseline, update both the gate defaults in
  `benchmarks/perf_gate.py` and this document in the same PR, and note why.
