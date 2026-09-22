"""Comprehensive tests for production infrastructure modules.

Tests cover: config, JSON logging, circuit breaker, rate limiter,
alerting, metrics, tracing, shadow mode, API endpoints, and shutdown.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import threading
import time
from unittest.mock import MagicMock, patch

import pytest

from mcp_monitor.production.alerting import AlertingHook
from mcp_monitor.production.circuit_breaker import (
    CircuitBreaker,
    CircuitOpenError,
    CircuitState,
)
from mcp_monitor.production.config import Config
from mcp_monitor.production.logging import JSONFormatter, get_logger
from mcp_monitor.production.metrics import MetricsCollector
from mcp_monitor.production.rate_limiter import RateLimiter
from mcp_monitor.production.server import ProductionServer
from mcp_monitor.production.shutdown import GracefulShutdown
from mcp_monitor.production.tracing import Tracer

# ============================================================
# Config Tests
# ============================================================


class TestConfig:
    """Tests for Config class."""

    def test_defaults(self):
        """Config uses sensible defaults when no env vars set."""
        with patch.dict(os.environ, {}, clear=True):
            # Clear any MCP_ vars that might be set
            env_copy = {k: v for k, v in os.environ.items() if not k.startswith("MCP_")}
            with patch.dict(os.environ, env_copy, clear=True):
                cfg = Config()
                assert cfg.listen_port == 8080
                assert cfg.shadow_mode is False
                assert cfg.webhook_url is None
                assert cfg.rate_limit_rpm == 1000
                assert cfg.circuit_breaker_threshold == 5
                assert cfg.circuit_breaker_timeout == 30.0
                assert cfg.log_level == "INFO"
                assert cfg.allowed_servers == set()
                assert cfg.max_payload_kb == 100.0
                assert cfg.wal_path is None
                assert cfg.audit_path is None

    def test_from_env(self):
        """Config reads values from environment variables."""
        env = {
            "MCP_LISTEN_PORT": "9090",
            "MCP_SHADOW_MODE": "true",
            "MCP_WEBHOOK_URL": "https://hooks.slack.com/test",
            "MCP_RATE_LIMIT_RPM": "500",
            "MCP_CIRCUIT_BREAKER_THRESHOLD": "3",
            "MCP_CIRCUIT_BREAKER_TIMEOUT": "60",
            "MCP_LOG_LEVEL": "DEBUG",
            "MCP_ALLOWED_SERVERS": "server1,server2,server3",
            "MCP_MAX_PAYLOAD_KB": "200",
            "MCP_WAL_PATH": "/tmp/test.wal",
            "MCP_AUDIT_PATH": "/tmp/test.audit",
        }
        with patch.dict(os.environ, env):
            cfg = Config()
            assert cfg.listen_port == 9090
            assert cfg.shadow_mode is True
            assert cfg.webhook_url == "https://hooks.slack.com/test"
            assert cfg.rate_limit_rpm == 500
            assert cfg.circuit_breaker_threshold == 3
            assert cfg.circuit_breaker_timeout == 60.0
            assert cfg.log_level == "DEBUG"
            assert cfg.allowed_servers == {"server1", "server2", "server3"}
            assert cfg.max_payload_kb == 200.0
            assert cfg.wal_path == "/tmp/test.wal"
            assert cfg.audit_path == "/tmp/test.audit"

    def test_shadow_mode_variants(self):
        """Shadow mode accepts multiple truthy values."""
        for val in ("true", "True", "1", "yes"):
            with patch.dict(os.environ, {"MCP_SHADOW_MODE": val}):
                cfg = Config()
                assert cfg.shadow_mode is True

        for val in ("false", "0", "no", ""):
            with patch.dict(os.environ, {"MCP_SHADOW_MODE": val}):
                cfg = Config()
                assert cfg.shadow_mode is False

    def test_allowed_servers_empty(self):
        """Empty MCP_ALLOWED_SERVERS gives empty set."""
        with patch.dict(os.environ, {"MCP_ALLOWED_SERVERS": ""}):
            cfg = Config()
            assert cfg.allowed_servers == set()

    def test_production_mode_requires_durable_authenticated_configuration(self):
        env = {
            "MCP_ENV": "production",
            "MCP_ALLOW_ANONYMOUS": "false",
        }
        with patch.dict(os.environ, env, clear=True):
            with pytest.raises(ValueError, match="Invalid production configuration"):
                Config()

    def test_production_mode_rejects_shadow_only_operation(self):
        env = {
            "MCP_ENV": "production",
            "MCP_API_KEY": "a" * 32,
            "MCP_WAL_PATH": "/var/lib/mcp/wal.jsonl",
            "MCP_AUDIT_PATH": "/var/lib/mcp/audit.jsonl",
            "MCP_ALLOWED_SERVERS": "github",
            "MCP_ALLOW_ANONYMOUS": "false",
            "MCP_SHADOW_MODE": "true",
        }
        with patch.dict(os.environ, env, clear=True):
            with pytest.raises(ValueError, match="MCP_SHADOW_MODE must be false"):
                Config()

    def test_production_mode_accepts_explicit_security_configuration(self):
        env = {
            "MCP_ENV": "production",
            "MCP_API_KEY": "a" * 32,
            "MCP_WAL_PATH": "/var/lib/mcp/wal.jsonl",
            "MCP_AUDIT_PATH": "/var/lib/mcp/audit.jsonl",
            "MCP_ALLOWED_SERVERS": "github,filesystem",
            "MCP_ALLOW_ANONYMOUS": "false",
            "MCP_RATE_LIMIT_RPM": "600",
            "MCP_MAX_PAYLOAD_KB": "100",
        }
        with patch.dict(os.environ, env, clear=True):
            cfg = Config()
        assert cfg.environment == "production"
        assert cfg.allowed_servers == {"github", "filesystem"}

    def test_repr(self):
        """Config has a useful repr."""
        env = {"MCP_LISTEN_PORT": "8080", "MCP_SHADOW_MODE": "false"}
        with patch.dict(os.environ, env, clear=False):
            cfg = Config()
            r = repr(cfg)
            assert "Config(" in r
            assert "listen_port=" in r


# ============================================================
# Logging Tests
# ============================================================


class TestJSONLogging:
    """Tests for structured JSON logging."""

    def test_json_format(self):
        """Log output is valid JSON with required fields."""
        formatter = JSONFormatter(service="test-service")
        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="test.py",
            lineno=1,
            msg="Test message",
            args=None,
            exc_info=None,
        )
        output = formatter.format(record)
        data = json.loads(output)
        assert data["level"] == "INFO"
        assert data["message"] == "Test message"
        assert data["service"] == "test-service"
        assert "timestamp" in data
        assert data["timestamp"].endswith("Z")

    def test_trace_context_in_log(self):
        """Trace context is included when set."""
        formatter = JSONFormatter()
        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="test.py",
            lineno=1,
            msg="Traced",
            args=None,
            exc_info=None,