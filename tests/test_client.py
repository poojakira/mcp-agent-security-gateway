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
