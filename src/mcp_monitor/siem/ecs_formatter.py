"""Elastic Common Schema (ECS) formatter for MCP security events.

Transforms internal gateway security decisions into ECS-compliant
JSON documents suitable for ingestion by Elasticsearch, Wazuh,
or any ECS-compatible SIEM.

Reference: https://www.elastic.co/guide/en/ecs/current/index.html
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from typing import Any


@dataclass
class ECSEvent:
    """A security event formatted in Elastic Common Schema.

    Fields follow ECS 8.x field naming conventions.
    """

    # ECS base fields
    timestamp: str = ""
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))

    # event.* fields
    event_kind: str = "alert"  # alert, event, signal
    event_category: list[str] = field(default_factory=lambda: ["intrusion_detection"])
    event_type: list[str] = field(default_factory=lambda: ["denied"])
    event_action: str = ""
    event_outcome: str = ""  # success, failure, unknown
    event_severity: int = 0  # 0-100
    event_risk_score: float = 0.0
    event_duration_ns: int = 0
    event_module: str = "mcp_security_gateway"
    event_dataset: str = "mcp.security"

    # source.* fields (the agent making the tool call)
    source_agent_id: str = ""
    source_session_id: str = ""

    # destination.* fields (the target MCP server/tool)
    destination_server_id: str = ""
    destination_tool_name: str = ""

    # threat.* fields
    threat_framework: str = ""
    threat_tactic_name: str = ""
    threat_tactic_id: str = ""
    threat_technique_name: str = ""
    threat_technique_id: str = ""

    # rule.* fields
    rule_id: str = ""
    rule_name: str = ""
    rule_category: str = ""
    rule_description: str = ""

    # mcp.* custom fields (ECS extension)
    mcp_layer: int = 0
    mcp_layer_name: str = ""
    mcp_enforcement_action: str = ""  # allow, block, redact, quarantine
    mcp_findings: list[str] = field(default_factory=list)
    mcp_call_id: str = ""
    mcp_trace_id: str = ""
    mcp_shadow_mode: bool = False

    def to_dict(self) -> dict[str, Any]:
        """Serialize to ECS-compatible dict for JSON output."""
        doc: dict[str, Any] = {
            "@timestamp": self.timestamp,
            "event": {
                "id": self.event_id,
                "kind": self.event_kind,
                "category": self.event_category,
                "type": self.event_type,
                "action": self.event_action,
                "outcome": self.event_outcome,
                "severity": self.event_severity,
                "risk_score": self.event_risk_score,
                "duration": self.event_duration_ns,
                "module": self.event_module,
                "dataset": self.event_dataset,
            },
            "source": {
                "agent_id": self.source_agent_id,
                "session_id": self.source_session_id,
            },
            "destination": {
                "server_id": self.destination_server_id,
                "tool_name": self.destination_tool_name,
            },
            "rule": {
                "id": self.rule_id,
                "name": self.rule_name,
                "category": self.rule_category,
                "description": self.rule_description,
            },
            "mcp": {
                "layer": self.mcp_layer,
                "layer_name": self.mcp_layer_name,
                "enforcement_action": self.mcp_enforcement_action,
                "findings": self.mcp_findings,
                "call_id": self.mcp_call_id,
                "trace_id": self.mcp_trace_id,
                "shadow_mode": self.mcp_shadow_mode,
            },
        }

        # Add threat fields only if populated
        if self.threat_technique_id:
            doc["threat"] = {
                "framework": self.threat_framework,
                "tactic": {
                    "name": self.threat_tactic_name,
                    "id": self.threat_tactic_id,
                },
                "technique": {
                    "name": self.threat_technique_name,
                    "id": self.threat_technique_id,
                },
            }

        return doc


class ECSFormatter:
    """Transforms MCP gateway security decisions into ECS events.

    Usage:
        formatter = ECSFormatter(shadow_mode=False)
        ecs_event = formatter.format_decision(verdict, tool_call)
        json_doc = ecs_event.to_dict()
    """

    # Mapping from gateway layer names to ECS threat categories
    LAYER_THREAT_MAP: dict[str, dict[str, str]] = {
        "server_trust": {
            "tactic_name": "Initial Access",
            "tactic_id": "TA0001",
            "technique_name": "Trusted Relationship",
            "technique_id": "T1199",
            "framework": "MITRE ATT&CK",
        },
        "tool_policy": {
            "tactic_name": "Execution",
            "tactic_id": "TA0002",
            "technique_name": "Command and Scripting Interpreter",
            "technique_id": "T1059",
            "framework": "MITRE ATT&CK",
        },
        "process_spawn": {
            "tactic_name": "Execution",
            "tactic_id": "TA0002",
            "technique_name": "Command and Scripting Interpreter",
            "technique_id": "T1059",
            "framework": "MITRE ATT&CK",
        },
        "semantic_intent": {
            "tactic_name": "Collection",
            "tactic_id": "TA0009",
            "technique_name": "Data from Information Repositories",
            "technique_id": "T1213",
            "framework": "MITRE ATT&CK",
        },
        "network_egress": {
            "tactic_name": "Exfiltration",
            "tactic_id": "TA0010",
            "technique_name": "Exfiltration Over Web Service",
            "technique_id": "T1567",
            "framework": "MITRE ATT&CK",
        },
    }

    # Map enforcement actions to ECS event outcomes
    ACTION_OUTCOME_MAP: dict[str, str] = {
        "allow": "success",
        "block": "failure",
        "deny": "failure",
        "redact": "success",
        "quarantine": "failure",
    }

    # Severity mapping: gateway risk score (0-100) to ECS severity
    @staticmethod
    def risk_to_severity(risk_score: int) -> int:
        """Map internal risk score to ECS severity (0-100)."""
        if risk_score >= 80:
            return 90  # critical
        elif risk_score >= 60:
            return 70  # high
        elif risk_score >= 40:
            return 50  # medium
        elif risk_score >= 20:
            return 30  # low
        return 10  # informational

    def __init__(self, shadow_mode: bool = False) -> None:
        self.shadow_mode = shadow_mode

    def format_decision(
        self,
        *,
        call_id: str = "",
        trace_id: str = "",
        tool_name: str = "",
        server_id: str = "",
        agent_id: str = "",
        session_id: str = "",
        allowed: bool = True,
        enforcement_action: str = "allow",
        blocked_by_layer: int | None = None,
        layer_name: str = "",
        risk_score: int = 0,
        findings: list[str] | None = None,
        latency_ms: float = 0.0,
    ) -> ECSEvent:
        """Transform a gateway security decision into an ECS event."""
        from datetime import datetime, timezone

        now = datetime.now(timezone.utc)
        findings = findings or []

        # Determine event type based on decision
        if allowed:
            event_type = ["allowed"]
            event_kind = "event"
        else:
            event_type = ["denied"]
            event_kind = "alert"

        # Build the ECS event
        event = ECSEvent(
            timestamp=now.isoformat(),
            event_kind=event_kind,
            event_category=["intrusion_detection"],
            event_type=event_type,
            event_action=f"mcp.tool_call.{enforcement_action}",
            event_outcome=self.ACTION_OUTCOME_MAP.get(enforcement_action, "unknown"),
            event_severity=self.risk_to_severity(risk_score),
            event_risk_score=float(risk_score),
            event_duration_ns=int(latency_ms * 1_000_000),
            source_agent_id=agent_id,
            source_session_id=session_id,
            destination_server_id=server_id,
            destination_tool_name=tool_name,
            rule_id=f"mcp-layer-{blocked_by_layer}" if blocked_by_layer else "",
            rule_name=layer_name,
            rule_category="mcp_security",
            rule_description="; ".join(findings[:3]) if findings else "",
            mcp_layer=blocked_by_layer or 0,
            mcp_layer_name=layer_name,
            mcp_enforcement_action=enforcement_action,
            mcp_findings=findings,
            mcp_call_id=call_id,
            mcp_trace_id=trace_id,
            mcp_shadow_mode=self.shadow_mode,
        )

        # Add threat intelligence mapping based on blocking layer
        threat_info = self.LAYER_THREAT_MAP.get(layer_name, {})
        if threat_info and not allowed:
            event.threat_framework = threat_info.get("framework", "")
            event.threat_tactic_name = threat_info.get("tactic_name", "")
            event.threat_tactic_id = threat_info.get("tactic_id", "")
            event.threat_technique_name = threat_info.get("technique_name", "")
            event.threat_technique_id = threat_info.get("technique_id", "")

        return event

    def format_circuit_breaker_event(
        self,
        *,
        breaker_name: str,
        state: str,
        failure_count: int,
    ) -> ECSEvent:
        """Create an ECS event for circuit breaker state changes."""
        from datetime import datetime, timezone

        return ECSEvent(
            timestamp=datetime.now(timezone.utc).isoformat(),
            event_kind="event",
            event_category=["configuration"],
            event_type=["change"],
            event_action=f"circuit_breaker.{state}",
            event_outcome="success",
            event_severity=70 if state == "open" else 10,
            rule_id=f"cb-{breaker_name}",
            rule_name=f"circuit_breaker_{breaker_name}",
            rule_category="operational",
            rule_description=f"Circuit breaker {breaker_name} transitioned to {state} after {failure_count} failures",
            mcp_findings=[f"failure_count={failure_count}", f"state={state}"],
        )

    def format_rate_limit_event(
        self,
        *,
        client_id: str,
        requests_per_minute: int,
        limit: int,
    ) -> ECSEvent:
        """Create an ECS event for rate limit violations."""
        from datetime import datetime, timezone

        return ECSEvent(
            timestamp=datetime.now(timezone.utc).isoformat(),
            event_kind="alert",
            event_category=["intrusion_detection"],
            event_type=["denied"],
            event_action="rate_limit.exceeded",
            event_outcome="failure",
            event_severity=50,
            source_agent_id=client_id,
            rule_id="rate-limit-001",
            rule_name="request_rate_limit",
            rule_category="availability",
            rule_description=f"Client {client_id} exceeded {limit} req/min (actual: {requests_per_minute})",
            mcp_enforcement_action="deny",
            mcp_findings=[
                f"requests_per_minute={requests_per_minute}",
                f"limit={limit}",
            ],
        )
