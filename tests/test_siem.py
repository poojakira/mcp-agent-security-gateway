"""Tests for SIEM integration module.

Validates ECS formatting, correlation rule matching, and log shipping.
"""

import json
import tempfile
import time
from pathlib import Path

from mcp_monitor.siem.correlation import (
    BUILTIN_RULES,
    INJECTION_THEN_ESCALATION_RULE,
    PERSISTENT_ATTACKER_RULE,
    RECON_TO_EXFIL_RULE,
    CorrelationEngine,
    SecurityEvent,
)
from mcp_monitor.siem.ecs_formatter import ECSFormatter
from mcp_monitor.siem.shipper import FileShipper, StdoutShipper


class TestECSFormatter:
    """Tests for Elastic Common Schema event formatting."""

    def test_format_blocked_decision(self):
        """Blocked decisions produce ECS alert events."""
        formatter = ECSFormatter()
        event = formatter.format_decision(
            call_id="call-123",
            tool_name="email.send",
            server_id="postmark",
            allowed=False,
            enforcement_action="block",
            blocked_by_layer=5,
            layer_name="network_egress",
            risk_score=80,
            findings=["exfiltration_indicator", "hidden_bcc_recipient"],
        )

        assert event.event_kind == "alert"
        assert event.event_type == ["denied"]
        assert event.event_outcome == "failure"
        assert event.event_severity == 90  # risk 80 maps to severity 90
        assert event.mcp_enforcement_action == "block"
        assert event.destination_tool_name == "email.send"
        assert "exfiltration_indicator" in event.mcp_findings

    def test_format_allowed_decision(self):
        """Allowed decisions produce ECS event (not alert)."""
        formatter = ECSFormatter()
        event = formatter.format_decision(
            tool_name="file.read",
            server_id="filesystem",
            allowed=True,
            enforcement_action="allow",
            risk_score=5,
        )

        assert event.event_kind == "event"
        assert event.event_type == ["allowed"]
        assert event.event_outcome == "success"

    def test_threat_mapping_on_block(self):
        """Blocked events include MITRE ATT&CK threat mapping."""
        formatter = ECSFormatter()
        event = formatter.format_decision(
            tool_name="http.post",
            allowed=False,
            enforcement_action="block",
            layer_name="network_egress",
            risk_score=75,
        )

        doc = event.to_dict()
        assert "threat" in doc
        assert doc["threat"]["tactic"]["id"] == "TA0010"
        assert doc["threat"]["technique"]["id"] == "T1567"

    def test_no_threat_mapping_on_allow(self):
        """Allowed events do not include threat mapping."""
        formatter = ECSFormatter()
        event = formatter.format_decision(
            tool_name="file.read",
            allowed=True,
            enforcement_action="allow",
            layer_name="server_trust",
            risk_score=0,
        )

        doc = event.to_dict()
        assert "threat" not in doc

    def test_to_dict_produces_valid_json(self):
        """ECS events serialize to valid JSON."""
        formatter = ECSFormatter()
        event = formatter.format_decision(
            call_id="test-call",
            trace_id="trace-abc",
            tool_name="db.query",
            server_id="postgres",
            agent_id="agent-1",
            session_id="session-xyz",
            allowed=False,
            enforcement_action="quarantine",
            blocked_by_layer=2,
            layer_name="tool_policy",
            risk_score=60,
            findings=["suspicious_query", "bulk_select"],
            latency_ms=0.5,
        )

        doc = event.to_dict()
        # Should be JSON-serializable
        json_str = json.dumps(doc)
        parsed = json.loads(json_str)

        assert parsed["@timestamp"] != ""
        assert parsed["event"]["module"] == "mcp_security_gateway"
        assert parsed["mcp"]["call_id"] == "test-call"
        assert parsed["mcp"]["trace_id"] == "trace-abc"

    def test_shadow_mode_flag(self):
        """Shadow mode flag is included in ECS event."""
        formatter = ECSFormatter(shadow_mode=True)
        event = formatter.format_decision(
            tool_name="test",
            allowed=True,
            enforcement_action="allow",
        )

        assert event.mcp_shadow_mode is True
        doc = event.to_dict()
        assert doc["mcp"]["shadow_mode"] is True

    def test_circuit_breaker_event(self):
        """Circuit breaker state changes produce valid ECS events."""
        formatter = ECSFormatter()
        event = formatter.format_circuit_breaker_event(
            breaker_name="call_inspection",
            state="open",
            failure_count=5,
        )

        assert event.event_kind == "event"
        assert event.event_category == ["configuration"]
        assert "circuit_breaker.open" in event.event_action
        assert event.event_severity == 70

    def test_rate_limit_event(self):
        """Rate limit violations produce alert events."""
        formatter = ECSFormatter()
        event = formatter.format_rate_limit_event(
            client_id="agent-aggressive",
            requests_per_minute=150,
            limit=60,
        )

        assert event.event_kind == "alert"
        assert event.event_outcome == "failure"
        assert event.source_agent_id == "agent-aggressive"

    def test_risk_to_severity_mapping(self):
        """Risk scores map to correct ECS severity levels."""
        assert ECSFormatter.risk_to_severity(0) == 10
        assert ECSFormatter.risk_to_severity(19) == 10
        assert ECSFormatter.risk_to_severity(20) == 30
        assert ECSFormatter.risk_to_severity(40) == 50
        assert ECSFormatter.risk_to_severity(60) == 70
        assert ECSFormatter.risk_to_severity(80) == 90
        assert ECSFormatter.risk_to_severity(100) == 90


class TestCorrelationEngine:
    """Tests for multi-event correlation rules."""

    def _make_event(self, **kwargs) -> SecurityEvent:
        """Helper to create test events."""
        defaults = {
            "timestamp": time.time(),
            "event_type": "block",
            "tool_name": "",
            "server_id": "",
            "agent_id": "agent-1",
            "session_id": "session-1",
            "enforcement_action": "block",
            "layer_name": "",
            "risk_score": 50,
            "findings": [],
        }
        defaults.update(kwargs)
        return SecurityEvent(**defaults)

    def test_recon_to_exfil_correlation(self):
        """Detects recon -> sensitive access -> exfil chain."""
        engine = CorrelationEngine(window_seconds=300)
        engine.add_rule(RECON_TO_EXFIL_RULE)

        now = time.time()

        # Step 1: Recon
        engine.ingest(
            self._make_event(
                timestamp=now,
                tool_name="tools.list",
                findings=["enumerate_tools", "discover"],
                enforcement_action="allow",
            )
        )

        # Step 2: Sensitive access
        engine.ingest(
            self._make_event(
                timestamp=now + 10,
                tool_name="file.read",
                findings=["sensitive_data", "pii_detected"],
            )
        )

        # Step 3: Exfiltration attempt
        matches = engine.ingest(
            self._make_event(
                timestamp=now + 20,
                tool_name="email.send",
                layer_name="network_egress",
                findings=["exfiltration_indicator", "hidden_recipient"],
            )
        )

        assert len(matches) == 1
        assert matches[0].rule_id == "COR-001"
        assert matches[0].severity == "critical"

    def test_injection_then_escalation(self):
        """Detects injection followed by privilege escalation."""
        engine = CorrelationEngine(window_seconds=120)
        engine.add_rule(INJECTION_THEN_ESCALATION_RULE)

        now = time.time()

        # Injection attempt
        engine.ingest(
            self._make_event(
                timestamp=now,
                findings=["prompt_injection_detected", "instruction_override"],
            )
        )

        # Privilege escalation
        matches = engine.ingest(
            self._make_event(
                timestamp=now + 5,
                layer_name="process_spawn",
                findings=["subprocess_detected", "bash"],
            )
        )

        assert len(matches) == 1
        assert matches[0].rule_id == "COR-002"

    def test_no_match_when_conditions_not_met(self):
        """Rules do not fire when conditions are not satisfied."""
        engine = CorrelationEngine(window_seconds=300)
        engine.add_rules(BUILTIN_RULES)

        # Only allowed events, no attack pattern
        matches = engine.ingest(
            self._make_event(
                enforcement_action="allow",
                findings=["normal_operation"],
            )
        )

        assert len(matches) == 0

    def test_window_expiry(self):
        """Events outside the correlation window do not trigger rules."""
        engine = CorrelationEngine(window_seconds=10)
        engine.add_rule(INJECTION_THEN_ESCALATION_RULE)

        now = time.time()

        # Injection 20 seconds ago (outside 10s window)
        engine.ingest(
            self._make_event(
                timestamp=now - 20,
                findings=["prompt_injection_detected"],
            )
        )

        # Escalation now
        matches = engine.ingest(
            self._make_event(
                timestamp=now,
                layer_name="process_spawn",
                findings=["subprocess_detected"],
            )
        )

        # Should NOT match because events are outside window
        assert len(matches) == 0

    def test_persistent_attacker_rule(self):
        """Detects multiple high-risk blocks from same session."""
        engine = CorrelationEngine(window_seconds=60)
        engine.add_rule(PERSISTENT_ATTACKER_RULE)

        now = time.time()

        # Three rapid blocks with high risk scores
        engine.ingest(
            self._make_event(
                timestamp=now,
                enforcement_action="block",
                risk_score=70,
            )
        )
        engine.ingest(
            self._make_event(
                timestamp=now + 1,
                enforcement_action="deny",
                risk_score=80,
            )
        )
        matches = engine.ingest(
            self._make_event(
                timestamp=now + 2,
                enforcement_action="block",
                risk_score=65,
            )
        )

        assert len(matches) == 1
        assert matches[0].rule_id == "COR-004"
        assert matches[0].severity == "high"

    def test_session_isolation(self):
        """Events from different sessions do not correlate."""
        engine = CorrelationEngine(window_seconds=300)
        engine.add_rule(INJECTION_THEN_ESCALATION_RULE)

        now = time.time()

        # Injection from session A
        engine.ingest(
            self._make_event(
                timestamp=now,
                session_id="session-A",
                findings=["prompt_injection_detected"],
            )
        )

        # Escalation from session B (different session)
        matches = engine.ingest(
            self._make_event(
                timestamp=now + 5,
                session_id="session-B",
                layer_name="process_spawn",
                findings=["subprocess_detected"],
            )
        )

        # Should NOT match (different sessions)
        assert len(matches) == 0

    def test_engine_stats(self):
        """Engine reports accurate statistics."""
        engine = CorrelationEngine(window_seconds=300)
        engine.add_rules(BUILTIN_RULES)

        engine.ingest(self._make_event(session_id="s1"))
        engine.ingest(self._make_event(session_id="s1"))
        engine.ingest(self._make_event(session_id="s2"))

        stats = engine.get_stats()
        assert stats["active_sessions"] == 2
        assert stats["total_events"] == 3
        assert stats["rules_loaded"] == len(BUILTIN_RULES)

    def test_max_events_per_session_cap(self):
        """Sessions are capped to prevent memory exhaustion."""
        engine = CorrelationEngine(window_seconds=300, max_events_per_session=5)

        for i in range(10):
            engine.ingest(self._make_event(session_id="flood"))

        events = engine.get_session_events("flood")
        assert len(events) <= 5


class TestFileShipper:
    """Tests for NDJSON file log shipper."""

    def test_ship_writes_ndjson(self):
        """FileShipper writes valid NDJSON to output file."""
        with tempfile.NamedTemporaryFile(suffix=".ndjson", delete=False) as f:
            output_path = f.name

        shipper = FileShipper(output_path=output_path, buffer_size=1)
        formatter = ECSFormatter()

        event = formatter.format_decision(
            tool_name="test.tool",
            allowed=False,
            enforcement_action="block",
            risk_score=50,
        )

        shipper.ship(event)

        # Read and validate
        content = Path(output_path).read_text()
        lines = [line for line in content.strip().split("\n") if line]
        assert len(lines) == 1

        parsed = json.loads(lines[0])
        assert parsed["event"]["module"] == "mcp_security_gateway"
        assert parsed["destination"]["tool_name"] == "test.tool"

        Path(output_path).unlink()

    def test_flush_writes_batch(self):
        """Buffered events are flushed as a batch."""
        with tempfile.NamedTemporaryFile(suffix=".ndjson", delete=False) as f:
            output_path = f.name

        shipper = FileShipper(output_path=output_path, buffer_size=100)
        formatter = ECSFormatter()

        for i in range(5):
            event = formatter.format_decision(
                tool_name=f"tool_{i}",
                allowed=True,
                enforcement_action="allow",
            )
            shipper.ship(event)

        # Manually flush
        shipper.flush()

        content = Path(output_path).read_text()
        lines = [line for line in content.strip().split("\n") if line]
        assert len(lines) == 5

        Path(output_path).unlink()

    def test_stats_tracking(self):
        """Shipper tracks event counts."""
        with tempfile.NamedTemporaryFile(suffix=".ndjson", delete=False) as f:
            output_path = f.name

        shipper = FileShipper(output_path=output_path, buffer_size=1)
        formatter = ECSFormatter()

        event = formatter.format_decision(
            tool_name="test", allowed=True, enforcement_action="allow"
        )
        shipper.ship(event)
        shipper.ship(event)
        shipper.ship(event)

        stats = shipper.get_stats()
        assert stats.events_shipped == 3
        assert stats.events_failed == 0

        Path(output_path).unlink()


class TestStdoutShipper:
    """Tests for stdout shipper."""

    def test_ship_to_stdout(self, capsys):
        """StdoutShipper prints valid JSON to stdout."""
        shipper = StdoutShipper()
        formatter = ECSFormatter()

        event = formatter.format_decision(
            tool_name="test", allowed=False, enforcement_action="block", risk_score=60
        )
        shipper.ship(event)

        captured = capsys.readouterr()
        parsed = json.loads(captured.out.strip())
        assert parsed["event"]["outcome"] == "failure"
