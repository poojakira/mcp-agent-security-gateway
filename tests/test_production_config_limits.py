"""Regression coverage for production startup's numeric safety boundary."""

from __future__ import annotations

import os
from unittest.mock import patch

import pytest

from mcp_monitor.production.config import Config


def production_env() -> dict[str, str]:
    return {
        "MCP_ENV": "production",
        "MCP_API_KEY": "test-only-not-a-real-credential-" + "x" * 16,
        "MCP_WAL_PATH": "/tmp/test-gateway-wal",
        "MCP_AUDIT_PATH": "/tmp/test-gateway-audit",
        "MCP_ALLOWED_SERVERS": "filesystem",
    }


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("MCP_MAX_PAYLOAD_KB", "nan"),
        ("MCP_MAX_PAYLOAD_KB", "inf"),
        ("MCP_MAX_PAYLOAD_KB", "-inf"),
        ("MCP_MAX_PAYLOAD_KB", "0"),
        ("MCP_LISTEN_PORT", "0"),
        ("MCP_LISTEN_PORT", "65536"),
        ("MCP_LISTEN_PORT", "-1"),
        ("MCP_CIRCUIT_BREAKER_THRESHOLD", "0"),
        ("MCP_CIRCUIT_BREAKER_THRESHOLD", "-1"),
        ("MCP_CIRCUIT_BREAKER_TIMEOUT", "nan"),
        ("MCP_CIRCUIT_BREAKER_TIMEOUT", "inf"),
        ("MCP_CIRCUIT_BREAKER_TIMEOUT", "-inf"),
        ("MCP_CIRCUIT_BREAKER_TIMEOUT", "0"),
        ("MCP_CIRCUIT_BREAKER_TIMEOUT", "-1"),
    ],
)
def test_production_rejects_invalid_limits(name: str, value: str) -> None:
    with patch.dict(os.environ, {**production_env(), name: value}, clear=True):
        with pytest.raises(ValueError, match=name):
            Config()


def test_valid_production_limits_are_accepted() -> None:
    with patch.dict(os.environ, production_env(), clear=True):
        config = Config()
    assert config.listen_port == 8080
    assert config.circuit_breaker_threshold == 5
    assert config.circuit_breaker_timeout == 30.0
    assert config.max_payload_kb == 100.0
