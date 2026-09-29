"""Integration tests for Cerberus pilot telemetry on the production gateway."""

from __future__ import annotations

import asyncio
import json
import os
from unittest.mock import patch

from mcp_monitor.production.cerberus import derive_ip_fingerprints
from mcp_monitor.production.config import Config
from mcp_monitor.production.server import ProductionServer


_KEYS = (
    "validation-credential-a-0000000000000001",
    "validation-credential-b-0000000000000002",
    "validation-credential-c-0000000000000003",
)


def _make_server(tmp_path) -> ProductionServer:
    env = {
        "MCP_LISTEN_PORT": "0",
        "MCP_SHADOW_MODE": "false",
        "MCP_RATE_LIMIT_RPM": "1000",
        "MCP_LOG_LEVEL": "WARNING",
        "MCP_ALLOW_ANONYMOUS": "false",
        "MCP_API_KEYS": ",".join(_KEYS),
        "MCP_ALLOWED_SERVERS": "test-server",
        "MCP_WAL_PATH": str(tmp_path / "gateway.wal"),
        "MCP_AUDIT_PATH": str(tmp_path / "gateway.audit"),
        "MCP_TRUSTED_PROXY_CIDRS": "10.0.0.0/8",
        "MCP_CERBERUS_ENABLED": "true",
        "MCP_CERBERUS_TENANT_SALT": "ephemeral-contract-test-salt",
        "MCP_CERBERUS_OUTPUT": str(tmp_path / "cerberus.ndjson"),
    }
    with patch.dict(os.environ, env, clear=True):
        return ProductionServer(config=Config())


def test_each_stable_credential_authenticates(tmp_path) -> None:
    server = _make_server(tmp_path)
    for credential in _KEYS:
        status, body = asyncio.run(
            server._route(
                "GET",
                "/v1/metrics",
                b"",
                {"x-api-key": credential},
                "t" * 32,
                "s" * 16,
            )
        )
        assert status == 200
        assert "mcp_request_total" in body


def test_unconfigured_credential_is_rejected(tmp_path) -> None:
    server = _make_server(tmp_path)
    status, body = asyncio.run(
        server._route(
            "GET",
            "/v1/metrics",
            b"",
            {"x-api-key": "not-one-of-the-configured-credentials"},
            "t" * 32,
            "s" * 16,
        )
    )
    assert status == 401
    assert body["error"] == "Unauthorized"


def test_cerberus_queue_contains_only_fingerprinted_identity_and_source(tmp_path) -> None:
    server = _make_server(tmp_path)
    raw_credential = _KEYS[1]
    raw_source = "203.0.113.5"

    server._write_cerberus_event(
        endpoint="/v1/inspect_call",
        credential=raw_credential,
        headers={"x-forwarded-for": f"for={raw_source}:443, 10.1.2.3"},
        peer_address="10.1.2.3",
        request_started_at=1790725500.0,
        latency_ms=17,
        status=200,
    )

    output_path = tmp_path / "cerberus.ndjson"
    raw_line = output_path.read_text(encoding="utf-8").strip()
    event = json.loads(raw_line)

    assert raw_credential not in raw_line
    assert raw_source not in raw_line
    assert set(event) == {
        "ts",
        "key_fp",
        "endpoint",
        "tokens_in",
        "tokens_out",
        "latency_ms",
        "status",
        "ip_fp",
        "ip_net_fp",
        "ip_block_fp",
        "ip_family",
        "cost",
    }
    assert event["endpoint"] == "/v1/inspect_call"
    assert event["tokens_in"] == 0
    assert event["tokens_out"] == 0
    assert event["status"] == 200
    assert event["ip_family"] == "v4"
    assert event["cost"] is None


def test_spoofed_forwarded_header_is_ignored_for_untrusted_peer(tmp_path) -> None:
    server = _make_server(tmp_path)

    server._write_cerberus_event(
        endpoint="/v1/inspect_output",
        credential=_KEYS[2],
        headers={"x-forwarded-for": "203.0.113.99"},
        peer_address="198.51.100.8",
        request_started_at=1790725500.0,
        latency_ms=9,
        status=200,
    )

    event = json.loads((tmp_path / "cerberus.ndjson").read_text(encoding="utf-8").strip())

    # The event must represent the socket peer, not the untrusted forwarded value.
    expected = derive_ip_fingerprints("198.51.100.8", "ephemeral-contract-test-salt")
    spoofed = derive_ip_fingerprints("203.0.113.99", "ephemeral-contract-test-salt")
    assert event["ip_fp"] == expected["ip_fp"]
    assert event["ip_fp"] != spoofed["ip_fp"]
