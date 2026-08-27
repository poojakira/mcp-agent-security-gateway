# Performance Baseline

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
