"""Offline adversarial regressions for the November 2026 integration candidate.

Only in-memory HTTP, fake routing, and a never-started Docker transport.
No API credentials, live network targets, or paid services.
"""

from __future__ import annotations

import asyncio
from unittest.mock import patch

import pytest

from mcp_monitor.policy.policy_engine import PolicyEngine
from mcp_monitor.production.config import Config
from mcp_monitor.production.rate_limiter import RateLimiter
from mcp_monitor.production.server import ProductionServer
from mcp_monitor.proxy.sandbox import OfflineDockerSandbox
from mcp_monitor.proxy.stdio_proxy import StdioMCPProxy


class _Writer:
    def __init__(self) -> None:
        self.data = bytearray()

    def get_extra_info(self, _name: str, default: object = None) -> tuple[str, int]:
        return ("127.0.0.1", 43000)

    def write(self, data: bytes) -> None:
        self.data.extend(data)

    async def drain(self) -> None:
        return None

    def close(self) -> None:
        return None

    async def wait_closed(self) -> None:
        return None


async def _exercise_http(server: ProductionServer, *, authorized: bool) -> bytes:
    raw = (
        b"POST /v1/inspect_call HTTP/1.1\r\nHost: test.invalid\r\n"
        + (b"X-Test-Authorization: yes\r\n" if authorized else b"")
        + b"Content-Length: 2\r\n\r\n{}"
    )
    reader = asyncio.StreamReader()
    reader.feed_data(raw)
    reader.feed_eof()
    writer = _Writer()
    await server._handle_connection(reader, writer)
    return bytes(writer.data)


def test_unauthenticated_requests_cannot_exhaust_authenticated_quota(tmp_path) -> None:
    """Unauthenticated requests must not spend the protected-client token bucket."""
    env = {
        "MCP_ENV": "development",
        "MCP_WAL_PATH": str(tmp_path / "wal.jsonl"),
        "MCP_AUDIT_PATH": str(tmp_path / "audit.jsonl"),
        "MCP_ALLOWED_SERVERS": "dummy",
        "MCP_RATE_LIMIT_RPM": "1",
    }
    with patch.dict("os.environ", env, clear=True):
        server = ProductionServer(Config())
    server._rate_limiter = RateLimiter(tokens_per_minute=1, burst_size=1)

    async def fake_route(method, path, body, headers, trace_id, span_id, source_event_id=None):
        # This intentionally substitutes for credential checking: no API key exists.
        if headers.get("x-test-authorization") != "yes":
            return 401, {"error": "Unauthorized"}
        return 200, {"allowed": True}

    server._authorize = lambda headers: (
        None if headers.get("x-test-authorization") == "yes" else (401, {"error": "Unauthorized"})
    )
    server._route = fake_route

    async def exercise() -> tuple[bytes, bytes]:
        denied = await _exercise_http(server, authorized=False)
        accepted = await _exercise_http(server, authorized=True)
        return denied, accepted

    denied, accepted = asyncio.run(exercise())
    assert denied.startswith(b"HTTP/1.1 401")
    assert accepted.startswith(b"HTTP/1.1 200"), (
        "Unauthenticated traffic consumed the shared request budget: "
        + accepted[:80].decode("ascii", errors="replace")
    )


def test_production_library_denies_uncontained_stdio(monkeypatch) -> None:
    """An importing Python caller must not evade the hardened CLI's sandbox check."""
    monkeypatch.setenv("MCP_ENV", "production")
    with pytest.raises(ValueError, match="isolat|sandbox|contain"):
        StdioMCPProxy(["local-test-command-never-executed"])


def test_production_library_denies_missing_tool_capabilities(monkeypatch) -> None:
    """A sandbox alone must not turn unrestricted tool access into allow."""
    monkeypatch.setenv("MCP_ENV", "production")
    sandbox = OfflineDockerSandbox("sha256:" + "a" * 64)
    with pytest.raises(ValueError, match="allowlist|allowed_tools|tool"):
        StdioMCPProxy(
            ["local-test-command-never-executed"],
            offline_sandbox=sandbox,
            strict_mcp_methods=True,
            policy_engine=PolicyEngine(allowed_servers={"local"}),
        )


def test_production_library_denies_nonstrict_methods(monkeypatch) -> None:
    """MCP resources and prompts passthrough must not be enabled in production."""
    monkeypatch.setenv("MCP_ENV", "production")
    sandbox = OfflineDockerSandbox("sha256:" + "b" * 64)
    with pytest.raises(ValueError, match="strict|method"):
        StdioMCPProxy(
            ["local-test-command-never-executed"],
            offline_sandbox=sandbox,
            policy_engine=PolicyEngine(allowed_servers={"local"}, allowed_tools={"read_manifest"}),
        )


def test_production_library_accepts_explicit_isolation_and_capabilities(monkeypatch) -> None:
    """No Docker start: approved construction must remain possible."""
    monkeypatch.setenv("MCP_ENV", "production")
    proxy = StdioMCPProxy(
        ["local-test-command-never-executed"],
        offline_sandbox=OfflineDockerSandbox("sha256:" + "c" * 64),
        strict_mcp_methods=True,
        policy_engine=PolicyEngine(allowed_servers={"local"}, allowed_tools={"read_manifest"}),
    )
    assert proxy is not None
