"""Tests for the GatewayClient transport boundary."""

from __future__ import annotations

import pytest

from mcp_monitor.client import GatewayClient


def test_gateway_client_accepts_http_and_https_endpoints() -> None:
    """Configured gateway endpoints must use an explicit HTTP transport."""
    assert GatewayClient("http://localhost:8000/").base_url == "http://localhost:8000"
    assert GatewayClient("https://gateway.example.test/api").base_url.endswith("/api")


@pytest.mark.parametrize(
    "endpoint", ["file:///tmp/gateway", "ftp://gateway.example", "localhost:8000"]
)
def test_gateway_client_rejects_non_http_endpoints(endpoint: str) -> None:
    """Reject local-file, custom-scheme, and relative endpoint inputs."""
    with pytest.raises(ValueError, match="HTTP or HTTPS"):
        GatewayClient(endpoint)


# An address in the reserved TEST-NET-1 range (RFC 5737) that is guaranteed not
# to route, with a short timeout so the transport error surfaces quickly.
_UNREACHABLE = "http://192.0.2.1:9"


def test_fail_open_allows_when_gateway_unreachable() -> None:
    """Default policy: an unreachable gateway must not break the agent."""
    client = GatewayClient(_UNREACHABLE, timeout=0.5)
    assert client.fail_closed is False
    verdict = client.scan({"name": "t", "server_id": "s", "arguments": {}})
    assert verdict["allowed"] is True
    assert verdict["enforcement_action"] == "allow"
    assert "transport_error" in verdict


def test_fail_closed_blocks_when_gateway_unreachable() -> None:
    """Security-critical policy: an unreachable gateway must block the call."""
    client = GatewayClient(_UNREACHABLE, timeout=0.5, fail_closed=True)
    assert client.fail_closed is True
    verdict = client.scan({"name": "t", "server_id": "s", "arguments": {}})
    assert verdict["allowed"] is False
    assert verdict["enforcement_action"] == "block"
    assert verdict["blocked_by_layer"] == 0
    assert "transport_error" in verdict


def test_guard_raises_toolblocked_when_fail_closed_and_unreachable() -> None:
    """The guard decorator enforces fail-closed by raising before the tool runs."""
    from mcp_monitor.client import ToolBlocked

    client = GatewayClient(_UNREACHABLE, timeout=0.5, fail_closed=True)
    ran = []

    @client.guard
    def send_email(*, server_id: str, to: str) -> str:
        ran.append(to)
        return "sent"

    with pytest.raises(ToolBlocked):
        send_email(server_id="postmark", to="user@example.com")
    assert ran == []  # tool body must never execute when fail-closed blocks
