"""Measure local stdio security-inspection overhead for a single MCP tool call.

This benchmark compares the stdio proxy's in-process ``inspect_message`` path
against a no-op pass-through function. It measures only local JSON parsing,
MCP tool-call extraction, and the stdlib prompt-injection detector configured
for the stdio proxy. It does not include downstream tool execution, subprocess
I/O, network latency, dashboard broadcasting, HTTP server overhead, or optional
ML detectors.

Run:
    PYTHONPATH=src python3 benchmark/stdio_inspection_overhead.py --iterations 50000
"""

from __future__ import annotations

import argparse
import json
import statistics
import time
from collections.abc import Callable

from mcp_monitor.proxy.stdio_proxy import inspect_message


def percentile(samples_ns: list[int], level: float) -> float:
    """Return a nearest-rank percentile in milliseconds."""
    if not samples_ns:
        return 0.0
    ordered = sorted(samples_ns)
    index = min(len(ordered) - 1, max(0, int((len(ordered) - 1) * level)))
    return round(ordered[index] / 1_000_000, 6)


def pass_through(message: str) -> str:
    """Baseline that represents adding no security inspection at all."""
    return message


def time_function(func: Callable[[str], object], message: str, iterations: int) -> list[int]:
    """Collect per-call runtimes in nanoseconds."""
    samples: list[int] = []
    for _ in range(iterations):
        started = time.perf_counter_ns()
        func(message)
        samples.append(time.perf_counter_ns() - started)
    return samples


def summarize(samples_ns: list[int]) -> dict[str, float]:
    """Summarize nanosecond samples as millisecond metrics."""
    return {
        "mean_ms": round(statistics.fmean(samples_ns) / 1_000_000, 6),
        "p50_ms": percentile(samples_ns, 0.50),
        "p95_ms": percentile(samples_ns, 0.95),
        "p99_ms": percentile(samples_ns, 0.99),
        "max_ms": round(max(samples_ns) / 1_000_000, 6),
    }


def measure(iterations: int, warmup: int) -> dict[str, object]:
    """Measure no-op baseline, inspection latency, and extra overhead."""
    message = json.dumps(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": "calc.add", "arguments": {"left": 4, "right": 7}},
        }
    )

    for _ in range(warmup):
        pass_through(message)
        inspect_message(message)

    baseline_ns = time_function(pass_through, message, iterations)
    inspection_ns = time_function(inspect_message, message, iterations)
    extra_mean_ns = statistics.fmean(inspection_ns) - statistics.fmean(baseline_ns)

    return {
        "iterations": iterations,
        "warmup": warmup,
        "baseline_noop": summarize(baseline_ns),
        "stdio_security_inspection": summarize(inspection_ns),
        "extra_overhead_mean_ms": round(extra_mean_ns / 1_000_000, 6),
        "scope": "local stdio inspect_message only; excludes downstream tool work, I/O, HTTP, dashboard, and optional ML",
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--iterations", type=int, default=50_000, help="number of measured calls")
    parser.add_argument("--warmup", type=int, default=1_000, help="warm-up calls before measuring")
    args = parser.parse_args()
    if args.iterations < 1:
        parser.error("--iterations must be positive")
    if args.warmup < 0:
        parser.error("--warmup must not be negative")
    print(json.dumps(measure(args.iterations, args.warmup), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
