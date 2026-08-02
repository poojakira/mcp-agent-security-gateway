"""Measure local five-layer tool-call decision latency.

This is a local measurement utility, not a cross-host performance guarantee.
Run after installing the server extra:
    python benchmark/tool_call_latency.py --iterations 200
"""

from __future__ import annotations

import argparse
import json
import statistics
import time
from typing import Any

from mcp_monitor.server.realtime import _build_defense


def percentile(samples: list[float], level: float) -> float:
    """Return a nearest-rank percentile in milliseconds."""
    if not samples:
        return 0.0
    ordered = sorted(samples)
    index = min(len(ordered) - 1, max(0, int((len(ordered) - 1) * level)))
    return round(ordered[index], 3)


def sample_calls() -> list[dict[str, Any]]:
    """Return representative allowed and blocked tool-call fixtures."""
    return [
        {
            "name": "calc.add",
            "server_id": "calc",
            "arguments": {"left": 4, "right": 7},
        },
        {
            "name": "email.send",
            "server_id": "postmark",
            "arguments": {"to": "operator@example.com", "bcc": "attacker@evil.com"},
        },
        {
            "name": "http.get",
            "server_id": "api",
            "arguments": {"url": "http://169.254.169.254/latest/meta-data/"},
        },
    ]


def measure(iterations: int) -> dict[str, float | int]:
    """Run a deterministic fixture mix through the configured five-layer defense."""
    defense = _build_defense()
    fixtures = sample_calls()
    samples: list[float] = []
    blocked = 0

    for index in range(iterations):
        started = time.perf_counter()
        verdict = defense.evaluate_call(fixtures[index % len(fixtures)])
        samples.append((time.perf_counter() - started) * 1000)
        blocked += int(not verdict.allowed)

    return {
        "iterations": iterations,
        "blocked": blocked,
        "allowed": iterations - blocked,
        "mean_ms": round(statistics.fmean(samples), 3),
        "p50_ms": percentile(samples, 0.50),
        "p95_ms": percentile(samples, 0.95),
        "p99_ms": percentile(samples, 0.99),
        "max_ms": round(max(samples), 3),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--iterations", type=int, default=200, help="number of fixture decisions")
    args = parser.parse_args()
    if args.iterations < 3:
        parser.error("--iterations must be at least 3")

    result = measure(args.iterations)
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
