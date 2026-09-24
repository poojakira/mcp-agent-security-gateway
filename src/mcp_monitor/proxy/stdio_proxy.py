"""Real stdio MCP proxy that sits between an MCP client and server.

Inspects every JSON-RPC tool call on the wire in real time, blocking
malicious ones before they reach the downstream MCP server.

Usage (Claude Desktop config):
    {
        "mcpServers": {
            "filesystem": {
                "command": "python",
                "args": ["-m", "mcp_monitor.proxy.stdio_proxy",
                         "--", "npx", "-y",
                         "@modelcontextprotocol/server-filesystem", "/tmp"]
            }
        }
    }
"""

from __future__ import annotations

import asyncio
import json
import logging
import sys
from dataclasses import dataclass
from enum import Enum
from typing import Any, Protocol

from mcp_monitor.detectors.prompt_injection import PromptInjectionDetector
from mcp_monitor.production.rate_limiter import RateLimiter
from mcp_monitor.protocol.jsonrpc import JSONRPCError, MCPJSONRPCAdapter

logger = logging.getLogger(__name__)


def _unique_json_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """Reject ambiguous JSON before security inspection or forwarding."""
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"Duplicate JSON key: {key}")
        result[key] = value
    return result


# ---------------------------------------------------------------------------
# Decision types
# ---------------------------------------------------------------------------


class Decision(str, Enum):
    """Explicit security enforcement decision."""

    ALLOW = "allow"
    BLOCK = "block"
    INDETERMINATE = "indeterminate"


@dataclass
class InspectionResult:
    """Result of inspecting a JSON-RPC message."""

    decision: Decision
    reason: str
    matched_patterns: list[str]
    request_id: int | str | None = None
    detector_errors: list[str] = None

    def __post_init__(self):
        if self.detector_errors is None:
            self.detector_errors = []

    @property
    def action(self) -> str:
        """Backward compatibility: return decision value as string."""
        return self.decision.value


# ---------------------------------------------------------------------------
# Transport protocol (injectable for testing)
# ---------------------------------------------------------------------------


class Transport(Protocol):
    """Protocol for downstream MCP server communication."""

    async def send(self, data: bytes) -> None:
        """Send raw bytes to the downstream server."""
        ...

    async def receive(self) -> bytes:
        """Receive a complete JSON-RPC message from the downstream server."""
        ...

    async def start(self) -> None:
        """Start the transport (e.g., launch subprocess)."""
        ...

    async def stop(self) -> None:
        """Stop the transport (e.g., kill subprocess)."""
        ...


class SubprocessTransport:
    """Real transport that launches a subprocess and communicates via stdio."""

    def __init__(self, command: list[str]) -> None:
        self.command = command
        self._process: asyncio.subprocess.Process | None = None
        self._read_buffer: bytes = b""

    async def start(self) -> None:
        """Launch the downstream MCP server subprocess."""
        self._process = await asyncio.create_subprocess_exec(
            *self.command,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

    async def stop(self) -> None:
        """Terminate the downstream server."""
        if self._process and self._process.returncode is None:
            self._process.terminate()
            try:
                await asyncio.wait_for(self._process.wait(), timeout=5.0)
            except asyncio.TimeoutError:
                self._process.kill()

    async def send(self, data: bytes) -> None:
        """Send raw bytes to the downstream server's stdin."""
        if self._process and self._process.stdin:
            self._process.stdin.write(data)
            await self._process.stdin.drain()

    async def receive(self) -> bytes:
        """Read a complete JSON-RPC message from downstream stdout.

        MCP uses newline-delimited JSON over stdio.
        """
        if not self._process or not self._process.stdout:
            raise RuntimeError("Transport not started")

        while True:
            # Check if we have a complete line in buffer
            newline_pos = self._read_buffer.find(b"\n")
            if newline_pos != -1:
                line = self._read_buffer[:newline_pos]
                self._read_buffer = self._read_buffer[newline_pos + 1 :]
                if line.strip():
                    return line.strip()
                continue

            # Read more data
            chunk = await self._process.stdout.read(8192)
            if not chunk:
                raise RuntimeError("Downstream server closed stdout")
            self._read_buffer += chunk


# ---------------------------------------------------------------------------
# Core inspection function
# ---------------------------------------------------------------------------

# Module-level shared instances for stateless usage
_adapter = MCPJSONRPCAdapter()
_detector = PromptInjectionDetector(enable_ml=False)


def inspect_message(raw_message: str | bytes | dict) -> InspectionResult:
    """Parse a JSON-RPC message, extract tool calls, run detection.

    Returns an allow/block decision with reason.

    Parameters
    ----------
    raw_message : str | bytes | dict
        The raw JSON-RPC message to inspect.

    Returns
    -------
    InspectionResult
        Decision with decision (Decision.ALLOW/Decision.BLOCK/Decision.INDETERMINATE),
        reason, and matched patterns.
    """
    # Parse the message
    if isinstance(raw_message, str | bytes):
        try:
            parsed_data = json.loads(raw_message, object_pairs_hook=_unique_json_pairs)
        except (json.JSONDecodeError, ValueError) as e:
            return InspectionResult(
                decision=Decision.BLOCK,
                reason=f"Invalid JSON: {e}",
                matched_patterns=["malformed_jsonrpc"],
            )
    else:
        parsed_data = raw_message

    if isinstance(parsed_data, list):
        if not parsed_data:
            return InspectionResult(Decision.BLOCK, "Empty JSON-RPC batch", ["malformed_jsonrpc"])
        for item in parsed_data:
            result = inspect_message(item)
            if result.decision != Decision.ALLOW:
                return result
        return InspectionResult(Decision.ALLOW, "Batch passed inspection", [])

    # Check if it's a dict with a method — i.e., a request
    if not isinstance(parsed_data, dict):
        return InspectionResult(
            decision=Decision.BLOCK,
            reason="Not a JSON-RPC request object",
            matched_patterns=["malformed_jsonrpc"],
        )

    method = parsed_data.get("method")
    request_id = parsed_data.get("id")

    # Only inspect tools/call messages
    if method != "tools/call":
        return InspectionResult(
            decision=Decision.ALLOW,
            reason=f"Non-tool-call method: {method}",
            matched_patterns=[],
            request_id=request_id,
        )

    # Extract tool call using the adapter
    try:
        tool_calls = _adapter.parse_message(parsed_data)
    except JSONRPCError as e:
        return InspectionResult(
            decision=Decision.BLOCK,
            reason=f"Malformed tool call: {e.message}",
            matched_patterns=["malformed_jsonrpc"],
            request_id=request_id,
        )

    # Run detection on each tool call
    all_matched: list[str] = []
    detector_errors: list[str] = []
    for tool_call in tool_calls:
        internal = tool_call.to_internal_format()
        try:
            detected, patterns = _detector.detect(internal)
        except Exception as exc:
            detector_errors.append(f"prompt_injection: {exc}")
            return InspectionResult(
                decision=Decision.INDETERMINATE,
                reason=f"Detector failed: {exc}",
                matched_patterns=[],
                request_id=request_id,
                detector_errors=detector_errors,
            )
        if detected:
            all_matched.extend(patterns)

    if all_matched:
        return InspectionResult(
            decision=Decision.BLOCK,
            reason=f"Prompt injection detected: {', '.join(all_matched)}",
            matched_patterns=all_matched,
            request_id=request_id,
        )

    return InspectionResult(
        decision=Decision.ALLOW,
        reason="Tool call passed security inspection",
        matched_patterns=[],
        request_id=request_id,
    )


# ---------------------------------------------------------------------------
# JSON-RPC error response builder
# ---------------------------------------------------------------------------


def _build_error_response(
    request_id: int | str | None,
    code: int,
    message: str,
    data: Any = None,
) -> bytes:
    """Build a JSON-RPC 2.0 error response."""
    response: dict[str, Any] = {
        "jsonrpc": "2.0",
        "id": request_id,
        "error": {
            "code": code,
            "message": message,
        },
    }
    if data is not None:
        response["error"]["data"] = data
    return json.dumps(response).encode("utf-8") + b"\n"


# ---------------------------------------------------------------------------
# StdioMCPProxy
# ---------------------------------------------------------------------------


class StdioMCPProxy:
    """Real-time stdio MCP proxy that inspects and blocks malicious tool calls.

    Sits between an MCP client (e.g., Claude Desktop) and a downstream MCP
    server, reading JSON-RPC messages from stdin, inspecting tools/call
    requests for prompt injection, and either blocking or forwarding them.

    Parameters
    ----------
    command : list[str]
        The downstream MCP server command to launch.
        E.g., ['npx', '-y', '@modelcontextprotocol/server-filesystem', '/tmp']
    transport : Transport | None
        Injectable transport for testing. If None, uses SubprocessTransport.
    detector : PromptInjectionDetector | None
        Injectable detector. If None, uses default regex-only detector.
    """

    # Custom JSON-RPC error code for security blocks
    SECURITY_BLOCK_CODE = -32001

    def __init__(
        self,
        command: list[str],
        *,
        transport: Transport | None = None,
        detector: PromptInjectionDetector | None = None,
        rate_limiter: RateLimiter | None = None,
        tool_calls_per_minute: int = 300,
    ) -> None:
        self.command = command
        self._transport = transport or SubprocessTransport(command)
        self._detector = detector or PromptInjectionDetector(enable_ml=False)
        self._adapter = MCPJSONRPCAdapter()
        # Rate limit tool calls at the proxy layer (separate from production/ server rate limiter).
        # Default: 300 tool calls/minute, burst up to 300. Reduces DoS risk and
        # limits blast radius if an agent is compromised or stuck in a loop.
        self._rate_limiter = rate_limiter or RateLimiter(
            tokens_per_minute=tool_calls_per_minute,
            burst_size=tool_calls_per_minute,
        )
        self._running = False
        self._stats = {"allowed": 0, "blocked": 0, "passthrough": 0, "rate_limited": 0}

    @property
    def stats(self) -> dict[str, int]:
        """Return proxy statistics."""
        return dict(self._stats)

    async def start(self) -> None:
        """Start the proxy: launch downstream server."""
        await self._transport.start()
        self._running = True
        logger.info("MCP proxy started, downstream: %s", self.command)

    async def stop(self) -> None:
        """Stop the proxy and downstream server."""
        self._running = False
        await self._transport.stop()
        logger.info("MCP proxy stopped. Stats: %s", self._stats)

    async def handle_message(self, raw_message: bytes) -> bytes:
        """Process a single JSON-RPC message from the client.

        Parameters
        ----------
        raw_message : bytes
            Raw JSON-RPC message bytes from the client's stdin.

        Returns
        -------
        bytes
            The response bytes to send back to the client.
            Either an error (if blocked) or the real server response.
        """
        try:
            parsed = json.loads(raw_message, object_pairs_hook=_unique_json_pairs)
        except (json.JSONDecodeError, UnicodeDecodeError, ValueError) as exc:
            self._stats["blocked"] += 1
            return _build_error_response(None, -32700, f"Invalid JSON: {exc}").rstrip(b"\n")

        is_batch = isinstance(parsed, list)
        messages = parsed if is_batch else [parsed]
        if not messages or any(not isinstance(message, dict) for message in messages):
            self._stats["blocked"] += 1
            return _build_error_response(None, -32600, "Invalid JSON-RPC request").rstrip(b"\n")

        denial: tuple[int, str, dict[str, Any]] | None = None
        tool_count = 0
        for message in messages:
            if message.get("method") != "tools/call":
                continue
            tool_count += 1
            if not self._rate_limiter.allow():
                self._stats["rate_limited"] += 1
                denial = (-32029, "Security: tool call rate limit exceeded", {})
                break
            result = self._inspect(message)
            if result.decision != Decision.ALLOW:
                self._stats["blocked"] += 1
                reason = (
                    "Security: Detector failure - failing closed"
                    if result.decision == Decision.INDETERMINATE
                    else f"Security: {result.reason}"
                )
                denial = (
                    self.SECURITY_BLOCK_CODE,
                    reason,
                    {"patterns": result.matched_patterns},
                )
                break

        if denial is not None:
            code, reason, data = denial
            # A batch is atomic here: no member is forwarded if any tool call fails.
            # Return one error for each request so clients do not wait for omitted IDs.
            responses = [
                _build_error_response(message["id"], code, reason, data).rstrip(b"\n")
                for message in messages
                if "id" in message
            ]
            if not responses:
                return b""  # Notifications have no JSON-RPC response.
            return b"[" + b",".join(responses) + b"]" if is_batch else responses[0]

        await self._transport.send(raw_message + b"\n")
        self._stats["allowed" if tool_count else "passthrough"] += 1
        if not any("id" in message and "method" in message for message in messages):
            return b""  # Notifications and client responses are one-way.
        return await self._transport.receive()

    def _inspect(self, parsed: dict[str, Any]) -> InspectionResult:
        """Run security inspection on a parsed JSON-RPC tools/call message."""
        request_id = parsed.get("id")
        detector_errors: list[str] = []

        try:
            tool_calls = self._adapter.parse_message(parsed)
        except JSONRPCError as e:
            return InspectionResult(
                decision=Decision.BLOCK,
                reason=f"Malformed tool call: {e.message}",
                matched_patterns=["malformed_jsonrpc"],
                request_id=request_id,
            )

        all_matched: list[str] = []
        for tool_call in tool_calls:
            internal = tool_call.to_internal_format()
            try:
                detected, patterns = self._detector.detect(internal)
            except Exception as exc:
                logger.exception("Prompt injection detector failed")
                detector_errors.append(f"prompt_injection: {exc}")
                # Fail-closed: treat detector failure as INDETERMINATE
                return InspectionResult(
                    decision=Decision.INDETERMINATE,
                    reason=f"Detector failed: {exc}",
                    matched_patterns=[],
                    request_id=request_id,
                    detector_errors=detector_errors,
                )
            if detected:
                all_matched.extend(patterns)

        if all_matched:
            return InspectionResult(
                decision=Decision.BLOCK,
                reason=f"Prompt injection detected: {', '.join(all_matched)}",
                matched_patterns=all_matched,
                request_id=request_id,
            )

        return InspectionResult(
            decision=Decision.ALLOW,
            reason="Tool call passed security inspection",
            matched_patterns=[],
            request_id=request_id,
        )

    async def run(self) -> None:
        """Main event loop: read from stdin, process, write to stdout.

        This is the entry point for running the proxy as a standalone process.
        """
        await self.start()

        try:
            reader = asyncio.StreamReader()
            protocol = asyncio.StreamReaderProtocol(reader)
            await asyncio.get_event_loop().connect_read_pipe(lambda: protocol, sys.stdin.buffer)

            while self._running:
                line = await reader.readline()
                if not line:
                    break  # EOF

                line = line.strip()
                if not line:
                    continue

                response = await self.handle_message(line)
                if response:
                    sys.stdout.buffer.write(response + b"\n")
                    sys.stdout.buffer.flush()

        except (KeyboardInterrupt, asyncio.CancelledError):
            pass
        finally:
            await self.stop()


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------


def main() -> None:
    """Run the proxy from the command line.

    Usage: python -m mcp_monitor.proxy.stdio_proxy -- <server_command> [args...]
    """
    args = sys.argv[1:]

    # Split on -- to get the downstream command
    if "--" in args:
        sep_idx = args.index("--")
        command = args[sep_idx + 1 :]
    else:
        command = args

    if not command:
        print(
            "Usage: python -m mcp_monitor.proxy.stdio_proxy -- <command> [args...]",
            file=sys.stderr,
        )
        sys.exit(1)

    proxy = StdioMCPProxy(command)
    asyncio.run(proxy.run())


if __name__ == "__main__":
    main()
