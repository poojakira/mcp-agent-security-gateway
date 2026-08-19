"""
SIEM Log Forwarder  -  ships MCP Gateway audit events to Splunk/Sentinel via syslog.

Implements RFC 5424 structured syslog and HTTP Event Collector (HEC) for Splunk.
Each event includes the hash-chain reference for integrity verification on the SIEM side.
"""

import datetime
import json
import logging
import socket
from dataclasses import dataclass
from typing import Literal
from urllib.error import URLError
from urllib.request import Request, urlopen

logger = logging.getLogger(__name__)


@dataclass
class SIEMConfig:
    """Configuration for SIEM forwarding."""

    transport: Literal["syslog_udp", "syslog_tcp", "splunk_hec", "sentinel_api"]
    host: str
    port: int = 514
    # Splunk HEC
    hec_token: str | None = None
    hec_index: str | None = "mcp_gateway"
    hec_sourcetype: str | None = "mcp:gateway:audit"
    # Sentinel
    workspace_id: str | None = None
    shared_key: str | None = None
    log_type: str | None = "MCPGatewayAudit"


class SyslogForwarder:
    """
    RFC 5424 syslog forwarder for MCP Gateway audit events.

    Maps gateway decisions to syslog severity:
      BLOCK     → severity 3 (Error)
      QUARANTINE → severity 4 (Warning)
      REDACT    → severity 5 (Notice)
      ALLOW     → severity 6 (Informational)
    """

    SEVERITY_MAP = {
        "BLOCK": 3,  # Error
        "QUARANTINE": 4,  # Warning
        "REDACT": 5,  # Notice
        "ALLOW": 6,  # Informational
    }
    FACILITY = 10  # security/auth (facility code 10)

    def __init__(self, config: SIEMConfig):
        self.config = config
        self._socket = None

    def forward(self, audit_event: dict) -> bool:
        """Forward a single audit event via syslog."""
        try:
            message = self._format_rfc5424(audit_event)
            self._send(message)
            return True
        except Exception as e:
            logger.error(f"Syslog forward failed: {e}")
            return False

    def _format_rfc5424(self, event: dict) -> str:
        """Format event as RFC 5424 structured syslog message."""
        decision = event.get("decision", "ALLOW")
        severity = self.SEVERITY_MAP.get(decision, 6)
        priority = self.FACILITY * 8 + severity

        timestamp = event.get("timestamp", datetime.datetime.now(datetime.UTC).isoformat())
        hostname = "mcp-gateway"
        app_name = "mcp-security-gateway"
        proc_id = event.get("request_id", "-")[:8]
        msg_id = event.get("rule_id", "-")

        # Structured data element with gateway-specific fields
        sd_gateway = (
            f'[gateway@49152 '
            f'decision="{decision}" '
            f'layer="{event.get("layer", "-")}" '
            f'rule_id="{event.get("rule_id", "-")}" '
            f'category="{event.get("category", "-")}" '
            f'agent_id="{event.get("agent_id", "-")}" '
            f'tool_name="{event.get("tool_name", "-")}" '
            f'hash_current="{event.get("hash_chain", {}).get("current", "-")}" '
            f'hash_previous="{event.get("hash_chain", {}).get("previous", "-")}"'
            f']'
        )

        # The MSG portion is the full JSON for SIEM parsing
        msg = json.dumps(event, separators=(",", ":"))

        return (
            f"<{priority}>1 {timestamp} {hostname} {app_name} {proc_id} {msg_id} {sd_gateway} {msg}"
        )

    def _send(self, message: str):
        """Send via UDP or TCP syslog."""
        encoded = message.encode("utf-8")
        if self.config.transport == "syslog_udp":
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.sendto(encoded, (self.config.host, self.config.port))
            sock.close()
        elif self.config.transport == "syslog_tcp":
            if self._socket is None:
                self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self._socket.connect((self.config.host, self.config.port))
            # TCP syslog uses newline-delimited messages
            self._socket.sendall(encoded + b"\n")

    def close(self):
        if self._socket:
            self._socket.close()
            self._socket = None


class SplunkHECForwarder:
    """
    Forward audit events to Splunk via HTTP Event Collector.

    Splunk HEC is preferred over syslog for structured data because it
    preserves JSON structure without the syslog parsing overhead.
    """

    def __init__(self, config: SIEMConfig):
        self.config = config
        self.endpoint = f"https://{config.host}:{config.port}/services/collector/event"

    def forward(self, audit_event: dict) -> bool:
        """Forward event to Splunk HEC."""
        hec_payload = {
            "time": self._epoch_time(audit_event.get("timestamp")),
            "host": "mcp-gateway",
            "source": "mcp-security-gateway",
            "sourcetype": self.config.hec_sourcetype,
            "index": self.config.hec_index,
            "event": audit_event,
        }

        try:
            req = Request(
                self.endpoint,
                data=json.dumps(hec_payload).encode("utf-8"),
                headers={
                    "Authorization": f"Splunk {self.config.hec_token}",
                    "Content-Type": "application/json",
                },
                method="POST",
            )
            response = urlopen(req, timeout=5)
            return response.status == 200
        except URLError as e:
            logger.error(f"Splunk HEC forward failed: {e}")
            return False

    def _epoch_time(self, iso_timestamp: str | None) -> float:
        if iso_timestamp:
            dt = datetime.datetime.fromisoformat(iso_timestamp.replace("Z", "+00:00"))
            return dt.timestamp()
        return datetime.datetime.now(datetime.UTC).timestamp()


def create_forwarder(config: SIEMConfig):
    """Factory for SIEM forwarders based on config transport type."""
    if config.transport in ("syslog_udp", "syslog_tcp"):
        return SyslogForwarder(config)
    elif config.transport == "splunk_hec":
        return SplunkHECForwarder(config)
    else:
        raise ValueError(f"Unsupported transport: {config.transport}")


# --- Hash chain integrity verification (SIEM-side) ---


def verify_hash_chain(events: list) -> dict:
    """
    Verify hash-chain integrity on a sequence of audit events.
    Run this on the SIEM side to detect tampering or missing entries.

    Returns dict with verification result and any gaps found.
    """
    import hashlib

    gaps = []
    verified = 0

    for i in range(1, len(events)):
        prev_event = events[i - 1]
        curr_event = events[i]

        expected_previous_hash = hashlib.sha256(
            json.dumps(prev_event, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()

        actual_previous_hash = curr_event.get("hash_chain", {}).get("previous", "")

        if expected_previous_hash == actual_previous_hash:
            verified += 1
        else:
            gaps.append(
                {
                    "position": i,
                    "expected_previous": expected_previous_hash,
                    "actual_previous": actual_previous_hash,
                    "event_request_id": curr_event.get("request_id"),
                    "timestamp": curr_event.get("timestamp"),
                }
            )

    return {
        "total_events": len(events),
        "verified_links": verified,
        "gaps_found": len(gaps),
        "integrity": "INTACT" if len(gaps) == 0 else "BROKEN",
        "gaps": gaps,
    }


if __name__ == "__main__":
    # Demo: format a sample event as RFC 5424 syslog
    sample_event = {
        "timestamp": "2026-08-18T14:22:03.441Z",
        "request_id": "a3f7c291-4e8b-4d12-b6a1-9c2e8f3d7a4b",
        "agent_id": "agent-prod-07",
        "layer": 4,
        "decision": "BLOCK",
        "rule_id": "PI-017",
        "rule_name": "instruction_override_detected",
        "category": "prompt_injection",
        "tool_name": "query_knowledge_base",
        "hash_chain": {
            "previous": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "current": "7d1a54127b222502f5b79b5fb0803061152a44f92b37e23c6527baf665d4da9a",
        },
    }

    config = SIEMConfig(transport="syslog_udp", host="127.0.0.1", port=514)
    forwarder = SyslogForwarder(config)
    formatted = forwarder._format_rfc5424(sample_event)
    print("RFC 5424 formatted syslog message:")
    print(formatted)
    print()
    print("Splunk HEC payload would be:")
    print(json.dumps({"event": sample_event, "sourcetype": "mcp:gateway:audit"}, indent=2))
