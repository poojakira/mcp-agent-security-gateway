"""Tests for the GatewayClient transport and enforcement boundary."""

from __future__ import annotations

from io import BytesIO
from unittest.mock import patch
from urllib.error import HTTPError

import pytest

from mcp_monitor.client import GatewayClient, ToolBlocked


def test_gateway_client_accepts_http_and_https_endpoints() -> None:
    assert GatewayClient("http://localhost:8000/").base_url == "http://localhost:8000"
    assert GatewayClient("https://gateway.example.test/api").base_url.endswith("/api")


@pytest.mark.parametrize(
    "endpoint", ["file:///tmp/gateway", "ftp://gateway.example", "localhost:8000"]
)
def test_gateway_client_rejects_non_http_endpoints(endpoint: str) -> None:
    with pytest.raises(ValueError, match="HTTP or HTTPS"):
        GatewayClient(endpoint)


def test_gateway_client_rejects_non_positive_timeout() -> None:
    with pytest.raises(ValueError, match="timeout"):
        GatewayClient(timeout=0)


def test_gateway_client_sends_api_key() -> None:
    response = type(
        "Response",
        (),
        {
            "read": lambda self: b'{"allowed": true}',
            "__enter__": lambda self: self,
            "__exit__": lambda self, *args: None,
        },
    )()
    with patch("mcp_monitor.client.urllib.request.urlopen", return_value=response) as mocked:
        verdict = GatewayClient("https://gateway.example.test", api_key="secret").scan(
            {"name": "tool", "server_id": "server", "arguments": {}}
        )
    assert verdict["allowed"] is True
    req = mocked.call_args.args[0]
    assert req.get_header("X-api-key") == "secret"


_UNREACHABLE = "http://192.0.2.1:9"


def test_fail_closed_is_default_when_gateway_unreachable() -> None:
    client = GatewayClient(_UNREACHABLE, timeout=0.5)
    assert client.fail_closed is True
    verdict = client.scan({"name": "t", "server_id": "s", "arguments": {}})
    assert verdict["allowed"] is False
    assert verdict["enforcement_action"] == "block"
    assert "transport_error" in verdict


def test_fail_open_can_be_explicitly_selected_for_monitoring() -> None:
    client = GatewayClient(_UNREACHABLE, timeout=0.5, fail_closed=False)
    verdict = client.scan({"name": "t", "server_id": "s", "arguments": {}})
    assert verdict["allowed"] is True
    assert verdict["enforcement_action"] == "allow"


@pytest.mark.parametrize("status", [400, 401, 403, 429])
def test_http_4xx_is_always_blocking_even_in_fail_open_mode(status: int) -> None:
    error = HTTPError(
        _UNREACHABLE,
        status,
        "Gateway denied request",
        hdrs=None,
        fp=BytesIO(b'{"detail":"denied"}'),
    )
    with patch("mcp_monitor.client.urllib.request.urlopen", side_effect=error):
        verdict = GatewayClient(_UNREACHABLE, api_key="wrong", fail_closed=False).scan(
            {"name": "t", "server_id": "s", "arguments": {}}
        )
    assert verdict["allowed"] is False
    assert verdict["enforcement_action"] == "block"
    assert verdict["gateway_denial"] is True
    assert verdict["http_status"] == status


def test_http_5xx_obeys_explicit_fail_open_choice() -> None:
    error = HTTPError(
        _UNREACHABLE,
        503,
        "Service unavailable",
        hdrs=None,
        fp=BytesIO(b'{"detail":"unavailable"}'),
    )
    with patch("mcp_monitor.client.urllib.request.urlopen", side_effect=error):
        verdict = GatewayClient(_UNREACHABLE, fail_closed=False).scan(
            {"name": "t", "server_id": "s", "arguments": {}}
        )
    assert verdict["allowed"] is True
    assert verdict["enforcement_action"] == "allow"
    assert verdict["http_status"] == 503


def test_guard_blocks_before_tool_execution() -> None:
    client = GatewayClient(_UNREACHABLE, timeout=0.5)
    ran: list[str] = []

    @client.guard
    def send_email(*, server_id: str, to: str) -> str:
        ran.append(to)
        return "sent"

    with pytest.raises(ToolBlocked):
        send_email(server_id="postmark", to="user@example.com")
    assert ran == []
