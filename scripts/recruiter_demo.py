#!/usr/bin/env python3
"""Recording-ready MCP Gateway recruiter demo.

Runs entirely against the repository's real PolicyEngine, AuditLog, and
ECSFormatter. It does not contact external systems or modify pilot/runtime
configuration.
"""

from __future__ import annotations

import argparse
import json
import tempfile
from pathlib import Path

from mcp_monitor.audit.log import AuditLog
from mcp_monitor.policy.policy_engine import PolicyEngine
from mcp_monitor.siem.ecs_formatter import ECSFormatter


def run_demo(*, quiet: bool = False) -> dict:
    engine = PolicyEngine(
        allowed_servers={"search"},
        allowed_egress_hosts={"api.example.com"},
    )

    allowed_call = {
        "name": "http_get",
        "server_id": "search",
        "arguments": {"url": "https://api.example.com/status"},
    }
    blocked_call = {
        "name": "http_get",
        "server_id": "search",
        "arguments": {"url": "http://127.0.0.1:8080/admin"},
    }

    allowed = engine.evaluate(allowed_call)
    blocked = engine.evaluate(blocked_call)

    with tempfile.TemporaryDirectory(prefix="mcp-recruiter-demo-") as tmp:
        audit_path = Path(tmp) / "audit.jsonl"
        audit = AuditLog(str(audit_path), hmac_key="demo-only-not-a-production-secret")
        allow_entry = audit.append(
            "tool_call_decision",
            {
                "tool": allowed_call["name"],
                "server_id": allowed_call["server_id"],
                "allowed": allowed.allowed,
                "reason_code": allowed.reason_code.value,
            },
        )
        block_entry = audit.append(
            "tool_call_decision",
            {
                "tool": blocked_call["name"],
                "server_id": blocked_call["server_id"],
                "allowed": blocked.allowed,
                "reason_code": blocked.reason_code.value,
            },
        )
        chain_ok, broken_at = audit.verify_chain()

        ecs = (
            ECSFormatter(shadow_mode=False)
            .format_decision(
                call_id=block_entry.entry_id,
                trace_id="recruiter-demo-trace",
                tool_name=blocked_call["name"],
                server_id=blocked_call["server_id"],
                agent_id="demo-agent",
                session_id="demo-session",
                allowed=blocked.allowed,
                enforcement_action="block",
                blocked_by_layer=5,
                layer_name="network_egress",
                risk_score=90,
                findings=[blocked.reason_code.value],
                latency_ms=0.0,
            )
            .to_dict()
        )

        result = {
            "allowed_call": {
                "decision": allowed.to_dict(),
                "downstream_execution": "eligible" if allowed.allowed else "blocked",
                "audit_entry": allow_entry.entry_id,
            },
            "blocked_call": {
                "decision": blocked.to_dict(),
                "downstream_execution": "blocked" if not blocked.allowed else "eligible",
                "audit_entry": block_entry.entry_id,
            },
            "audit_chain": {"intact": chain_ok, "broken_at": broken_at},
            "ecs_event": {
                "event.action": ecs["event"]["action"],
                "event.outcome": ecs["event"]["outcome"],
                "event.risk_score": ecs["event"]["risk_score"],
                "mcp.enforcement_action": ecs["mcp"]["enforcement_action"],
                "mcp.findings": ecs["mcp"]["findings"],
            },
        }

    if not quiet:
        print("=== MCP Agent Security Gateway · 60-second recruiter demo ===")
        print()
        print("1) NORMAL TOOL CALL")
        print(json.dumps(result["allowed_call"], indent=2))
        print()
        print("2) SSRF-STYLE LOOPBACK CALL")
        print(json.dumps(result["blocked_call"], indent=2))
        print()
        print("3) TAMPER-EVIDENT AUDIT")
        print(json.dumps(result["audit_chain"], indent=2))
        print()
        print("4) ECS / SIEM EVENT")
        print(json.dumps(result["ecs_event"], indent=2))

    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true", help="Run invariants for CI and exit.")
    args = parser.parse_args()

    result = run_demo(quiet=args.check)

    if not result["allowed_call"]["decision"]["allowed"]:
        raise SystemExit("expected normal call to be allowed")
    if result["blocked_call"]["decision"]["allowed"]:
        raise SystemExit("expected loopback egress call to be blocked")
    if result["blocked_call"]["downstream_execution"] != "blocked":
        raise SystemExit("blocked call must not be eligible for downstream execution")
    if not result["audit_chain"]["intact"]:
        raise SystemExit("audit chain must verify")
    if result["ecs_event"]["mcp.enforcement_action"] != "block":
        raise SystemExit("ECS event must record block enforcement")

    if args.check:
        print("Recruiter demo invariants passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
