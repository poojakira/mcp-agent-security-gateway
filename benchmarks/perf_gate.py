#!/usr/bin/env python3
"""
Performance benchmark gate for mcp-agent-security-gateway.

Runs inspect_call() through 1000 iterations and asserts:
  - p95 latency < 5ms
  - Throughput > 5000 calls/sec

Outputs JSON results to stdout and optionally to a file.
Designed to run in CI as a regression gate.

Usage:
    python benchmarks/perf_gate.py
    python benchmarks/perf_gate.py --output results.json
    python benchmarks/perf_gate.py --iterations 5000 --warmup 100
"""

from __future__ import annotations

import argparse
import json
import statistics
import sys
import time
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

DEFAULT_ITERATIONS = 1000
DEFAULT_WARMUP = 50
P95_LATENCY_THRESHOLD_MS = 5.0
MIN_THROUGHPUT_CALLS_PER_SEC = 5000


# ---------------------------------------------------------------------------
# Benchmark harness
# ---------------------------------------------------------------------------


def build_sample_call() -> dict[str, Any]:
    """Construct a representative MCP tool-call payload for benchmarking."""
    return {
        "method": "tools/call",
        "params": {
            "name": "read_file",
            "arguments": {
                "path": "/etc/passwd",
            },
        },
        "meta": {
            "caller": "agent-benchmark",
            "session_id": "bench-session-001",
        },
    }


def run_benchmark(
    iterations: int = DEFAULT_ITERATIONS,
    warmup: int = DEFAULT_WARMUP,
) -> dict[str, Any]:
    """
    Execute the performance benchmark.

    Returns a dict with latency percentiles, throughput, and pass/fail status.
    """
    # Late import so module-level errors surface clearly
    try:
        from mcp_gateway import inspect_call  # type: ignore[import]
    except ImportError as exc:
        print(
            f"ERROR: Cannot import inspect_call from mcp_gateway: {exc}\n"
            "Ensure the package is installed: pip install -e .",
            file=sys.stderr,
        )
        sys.exit(2)

    sample_call = build_sample_call()

    # --- Warmup phase (not measured) ---
    for _ in range(warmup):
        inspect_call(sample_call)

    # --- Timed phase ---
    latencies_ns: list[int] = []
    wall_start = time.perf_counter_ns()

    for _ in range(iterations):
        t0 = time.perf_counter_ns()
        inspect_call(sample_call)
        t1 = time.perf_counter_ns()
        latencies_ns.append(t1 - t0)

    wall_end = time.perf_counter_ns()

    # --- Compute statistics ---
    wall_elapsed_s = (wall_end - wall_start) / 1e9
    latencies_ms = [ns / 1e6 for ns in latencies_ns]

    latencies_ms_sorted = sorted(latencies_ms)
    p50 = latencies_ms_sorted[int(iterations * 0.50)]
    p90 = latencies_ms_sorted[int(iterations * 0.90)]
    p95 = latencies_ms_sorted[int(iterations * 0.95)]
    p99 = latencies_ms_sorted[int(iterations * 0.99)]
    mean = statistics.mean(latencies_ms)
    stddev = statistics.stdev(latencies_ms) if iterations > 1 else 0.0
    throughput = iterations / wall_elapsed_s

    # --- Gate checks ---
    p95_pass = p95 < P95_LATENCY_THRESHOLD_MS
    throughput_pass = throughput > MIN_THROUGHPUT_CALLS_PER_SEC
    gate_pass = p95_pass and throughput_pass

    results = {
        "benchmark": "inspect_call",
        "iterations": iterations,
        "warmup": warmup,
        "latency_ms": {
            "mean": round(mean, 4),
            "stddev": round(stddev, 4),
            "p50": round(p50, 4),
            "p90": round(p90, 4),
            "p95": round(p95, 4),
            "p99": round(p99, 4),
            "min": round(min(latencies_ms), 4),
            "max": round(max(latencies_ms), 4),
        },
        "throughput_calls_per_sec": round(throughput, 2),
        "wall_time_sec": round(wall_elapsed_s, 4),
        "thresholds": {
            "p95_latency_ms": P95_LATENCY_THRESHOLD_MS,
            "min_throughput_calls_per_sec": MIN_THROUGHPUT_CALLS_PER_SEC,
        },
        "gate": {
            "p95_latency_pass": p95_pass,
            "throughput_pass": throughput_pass,
            "overall_pass": gate_pass,
        },
    }

    return results


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Performance regression gate for mcp-agent-security-gateway"
    )
    parser.add_argument(
        "--iterations",
        type=int,
        default=DEFAULT_ITERATIONS,
        help=f"Number of timed iterations (default: {DEFAULT_ITERATIONS})",
    )
    parser.add_argument(
        "--warmup",
        type=int,
        default=DEFAULT_WARMUP,
        help=f"Warmup iterations before measurement (default: {DEFAULT_WARMUP})",
    )
    parser.add_argument(
        "--output",
        type=str,
        default=None,
        help="Path to write JSON results (also prints to stdout)",
    )
    parser.add_argument(
        "--threshold-p95-ms",
        type=float,
        default=P95_LATENCY_THRESHOLD_MS,
        help=f"p95 latency threshold in ms (default: {P95_LATENCY_THRESHOLD_MS})",
    )
    parser.add_argument(
        "--threshold-throughput",
        type=float,
        default=MIN_THROUGHPUT_CALLS_PER_SEC,
        help=f"Min throughput calls/sec (default: {MIN_THROUGHPUT_CALLS_PER_SEC})",
    )
    args = parser.parse_args()

    # Allow threshold override from CLI (useful in CI)
    global P95_LATENCY_THRESHOLD_MS, MIN_THROUGHPUT_CALLS_PER_SEC
    P95_LATENCY_THRESHOLD_MS = args.threshold_p95_ms
    MIN_THROUGHPUT_CALLS_PER_SEC = args.threshold_throughput

    print(
        f"Running benchmark: {args.iterations} iterations, "
        f"{args.warmup} warmup...",
        file=sys.stderr,
    )

    results = run_benchmark(iterations=args.iterations, warmup=args.warmup)

    # Output JSON
    results_json = json.dumps(results, indent=2)
    print(results_json)

    if args.output:
        output_path = Path(args.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(results_json + "\n", encoding="utf-8")
        print(f"\nResults written to {output_path}", file=sys.stderr)

    # Summary
    print("\n--- Performance Gate Summary ---", file=sys.stderr)
    print(
        f"  p95 latency:  {results['latency_ms']['p95']:.4f} ms "
        f"(threshold: < {P95_LATENCY_THRESHOLD_MS} ms) "
        f"{'✓ PASS' if results['gate']['p95_latency_pass'] else '✗ FAIL'}",
        file=sys.stderr,
    )
    print(
        f"  throughput:   {results['throughput_calls_per_sec']:.0f} calls/sec "
        f"(threshold: > {MIN_THROUGHPUT_CALLS_PER_SEC:.0f} calls/sec) "
        f"{'✓ PASS' if results['gate']['throughput_pass'] else '✗ FAIL'}",
        file=sys.stderr,
    )
    print(
        f"  overall:      {'✓ GATE PASSED' if results['gate']['overall_pass'] else '✗ GATE FAILED'}",
        file=sys.stderr,
    )

    if not results["gate"]["overall_pass"]:
        sys.exit(1)


if __name__ == "__main__":
    main()
