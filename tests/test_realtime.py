"""Focused tests for the control-plane telemetry contract."""

from __future__ import annotations

import asyncio
import copy
import time

from mcp_monitor.server import realtime


def test_realtime_stats_are_source_aware_and_include_latency() -> None:
    """External events expose bounded latency and attribution to dashboard clients."""
    original_stats = copy.deepcopy(realtime.stats)
    original_events = list(realtime.recent_threats)
    original_window = list(realtime._event_window)
    original_demo_mode = realtime._demo_workload_enabled
    try:
        realtime.stats.clear()
        realtime.stats.update(
            {
                "total_events": 0,
                "blocked": 0,
                "allowed": 0,
                "by_layer": {1: 0, 2: 0, 3: 0, 4: 0, 5: 0},
                "by_category": {},
                "by_severity": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0},
                "source_counts": {"external": 0, "demo": 0},
                "by_server": {},
                "by_tool": {},
                "decision_latency_ms": [],
                "start_time": time.time(),
                "events_per_second": 0.0,
                "recent_eps": [],
            }
        )
        realtime.recent_threats.clear()
        realtime._event_window.clear()
        realtime._demo_workload_enabled = False

        realtime._record_event(
            {
                "blocked": True,
                "blocked_by_layer": 4,
                "category": "prompt_injection",
                "severity": "HIGH",
                "source": "external",
                "server_id": "postmark",
                "tool_name": "email.send",
                "decision_latency_ms": 1.25,
            }
        )

        snapshot = asyncio.run(realtime.api_stats())
        assert snapshot["traffic_mode"] == "external"
        assert snapshot["source_counts"] == {"external": 1, "demo": 0}
        assert snapshot["by_server"] == {"postmark": 1}
        assert snapshot["by_tool"] == {"email.send": 1}
        assert snapshot["by_layer"][4] == 1
        assert snapshot["latency_ms"]["samples"] == 1
        assert snapshot["latency_ms"]["p95_ms"] == 1.25
    finally:
        realtime.stats.clear()
        realtime.stats.update(original_stats)
        realtime.recent_threats[:] = original_events
        realtime._event_window[:] = original_window
        realtime._demo_workload_enabled = original_demo_mode


def test_traffic_mode_marks_opt_in_workload_as_demo() -> None:
    """The UI contract never calls the built-in synthetic workload live traffic."""
    original_demo_mode = realtime._demo_workload_enabled
    try:
        realtime._demo_workload_enabled = True
        assert realtime._traffic_mode() == "demo"
    finally:
        realtime._demo_workload_enabled = original_demo_mode
