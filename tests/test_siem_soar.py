"""Tests for SIEM/SOAR integration components."""

import datetime
import json

from soar.playbooks.isolate_tool_server import (
    PoisoningEvent,
    ToolServerIsolationPlaybook,
)
from soar.playbooks.quarantine_model import (
    handle_scanner_webhook,
)
from soar.playbooks.revoke_agent_on_exfil import (
    AgentRevocationPlaybook,
    GatewayEvent,
    handle_webhook,
)
from soar.siem_forwarder import (
    SIEMConfig,
    SyslogForwarder,
    verify_hash_chain,
)


class TestSyslogForwarder:
    """Test RFC 5424 syslog formatting."""

    def test_format_block_event(self):
        config = SIEMConfig(transport="syslog_udp", host="127.0.0.1", port=514)
        forwarder = SyslogForwarder(config)

        event = {
            "timestamp": "2026-08-18T14:22:03.441Z",
            "request_id": "a3f7c291-4e8b-4d12-b6a1-9c2e8f3d7a4b",
            "decision": "BLOCK",
            "layer": 4,
            "rule_id": "PI-017",
            "category": "prompt_injection",
            "agent_id": "agent-prod-07",
            "tool_name": "query_knowledge_base",
            "hash_chain": {
                "previous": "e3b0c44298fc1c149afbf4c8996fb924",
                "current": "7d1a54127b222502f5b79b5fb0803061",
            },
        }

        message = forwarder._format_rfc5424(event)

        # Priority: facility 10 * 8 + severity 3 (Error) = 83
        assert message.startswith("<83>1")
        assert "mcp-security-gateway" in message
        assert 'decision="BLOCK"' in message
        assert 'layer="4"' in message
        assert 'rule_id="PI-017"' in message
        assert 'hash_current="7d1a54127b222502f5b79b5fb0803061"' in message

    def test_severity_mapping(self):
        config = SIEMConfig(transport="syslog_udp", host="127.0.0.1")
        forwarder = SyslogForwarder(config)

        # BLOCK = severity 3, facility 10 → priority 83
        assert forwarder.SEVERITY_MAP["BLOCK"] == 3
        # QUARANTINE = severity 4 → priority 84
        assert forwarder.SEVERITY_MAP["QUARANTINE"] == 4
        # ALLOW = severity 6 → priority 86
        assert forwarder.SEVERITY_MAP["ALLOW"] == 6


class TestHashChainVerification:
    """Test hash-chain integrity checking (SIEM-side verification)."""

    def test_intact_chain(self):
        import hashlib

        events = []
        for i in range(5):
            event = {"request_id": f"req-{i}", "decision": "ALLOW", "layer": 1}
            if i > 0:
                prev_hash = hashlib.sha256(
                    json.dumps(events[i - 1], sort_keys=True, separators=(",", ":")).encode()
                ).hexdigest()
                event["hash_chain"] = {"previous": prev_hash}
            else:
                event["hash_chain"] = {"previous": ""}
            events.append(event)

        result = verify_hash_chain(events)
        assert result["integrity"] == "INTACT"
        assert result["gaps_found"] == 0
        assert result["verified_links"] == 4

    def test_broken_chain_detects_tampering(self):
        events = [
            {"request_id": "req-0", "decision": "ALLOW", "hash_chain": {"previous": ""}},
            {"request_id": "req-1", "decision": "BLOCK", "hash_chain": {"previous": "wrong_hash"}},
            {"request_id": "req-2", "decision": "ALLOW", "hash_chain": {"previous": "also_wrong"}},
        ]

        result = verify_hash_chain(events)
        assert result["integrity"] == "BROKEN"
        assert result["gaps_found"] == 2


class TestRevocationPlaybook:
    """Test agent IAM revocation playbook."""

    def test_event_parsing(self):
        event = GatewayEvent(
            request_id="test-req-1",
            agent_id="agent-prod-07",
            tool_name="http_request",
            decision="BLOCK",
            layer=5,
            category="data_exfiltration",
            rule_id="EG-003",
            target_domain="attacker.com",
        )
        assert event.layer == 5
        assert event.category == "data_exfiltration"

    def test_missing_role_mapping(self):
        payload = {
            "request_id": "req-1",
            "agent_id": "unknown-agent",
            "tool_name": "test",
            "decision": "BLOCK",
            "layer": 5,
            "category": "data_exfiltration",
            "rule_id": "EG-003",
        }
        result = handle_webhook(payload, role_mapping={})
        assert result.success is False
        assert "No IAM role mapping" in result.errors[0]

    def test_missing_boto3_raises(self):
        import soar.playbooks.revoke_agent_on_exfil as mod

        original_boto3 = mod.boto3
        mod.boto3 = None
        try:
            import pytest

            with pytest.raises(RuntimeError, match="boto3 required"):
                AgentRevocationPlaybook()
        finally:
            mod.boto3 = original_boto3


class TestToolServerIsolation:
    """Test tool server isolation threshold logic."""

    def test_threshold_not_met(self):
        playbook = ToolServerIsolationPlaybook()
        events = [
            PoisoningEvent(
                request_id="req-1",
                agent_id="agent-01",
                server_id="server-A",
                tool_name="test",
                rule_id="TP-001",
                timestamp=datetime.datetime.utcnow().isoformat(),
            ),
            PoisoningEvent(
                request_id="req-2",
                agent_id="agent-02",
                server_id="server-A",
                tool_name="test",
                rule_id="TP-001",
                timestamp=datetime.datetime.utcnow().isoformat(),
            ),
        ]
        # Only 2 events — threshold is 3
        assert playbook.should_trigger(events, "server-A") is False

    def test_threshold_met(self):
        playbook = ToolServerIsolationPlaybook()
        now = datetime.datetime.utcnow()
        events = [
            PoisoningEvent(
                request_id=f"req-{i}",
                agent_id=f"agent-0{i}",
                server_id="server-A",
                tool_name="test",
                rule_id="TP-001",
                timestamp=(now - datetime.timedelta(minutes=i)).isoformat(),
            )
            for i in range(3)
        ]
        # 3 events within 5 minutes
        assert playbook.should_trigger(events, "server-A") is True

    def test_threshold_not_met_different_servers(self):
        playbook = ToolServerIsolationPlaybook()
        now = datetime.datetime.utcnow()
        events = [
            PoisoningEvent(
                request_id=f"req-{i}",
                agent_id=f"agent-0{i}",
                server_id=f"server-{chr(65+i)}",  # Different servers
                tool_name="test",
                rule_id="TP-001",
                timestamp=now.isoformat(),
            )
            for i in range(3)
        ]
        assert playbook.should_trigger(events, "server-A") is False


class TestModelQuarantine:
    """Test model quarantine playbook."""

    def test_alert_parsing(self):
        payload = {
            "model_repo": "evil-user/bert-base-uncasd",
            "finding_type": "pickle_gadget_chain",
            "severity": "CRITICAL",
            "cve": "CVE-2026-4372",
            "attack_technique": "T1059.006",
        }
        result = handle_scanner_webhook(payload)
        # Playbook runs and produces actions (blocklist write may fail in test env)
        assert result is not None
        assert any("evil-user/bert-base-uncasd" in a for a in result.actions_taken)
