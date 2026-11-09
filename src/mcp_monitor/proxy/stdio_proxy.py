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
import math
import secrets
import sys
from collections import Counter
from dataclasses import dataclass
from enum import Enum
from typing import Any, Protocol

from mcp_monitor.detectors.prompt_injection import PromptInjectionDetector
from mcp_monitor.policy.acl_guard import AccessDenied, ACLGuard
from mcp_monitor.policy.policy_engine import PolicyEngine
from mcp_monitor.production.rate_limiter import RateLimiter
from mcp_monitor.protocol.jsonrpc import JSONRPCError, MCPJSONRPCAdapter
from mcp_monitor.protocol.multiplex import MultiplexedTransport, ProtocolCancelled
from mcp_monitor.proxy.internal_sandbox import InternalDockerSandbox
from mcp_monitor.proxy.oidc_identity import OIDCSessionBinding
from mcp_monitor.proxy.sandbox import OfflineDockerSandbox
from mcp_monitor.proxy.session_identity import BoundSession, SessionVerificationError

logger = logging.getLogger(__name__)


def _unique_json_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """Reject ambiguous JSON before security inspection or forwarding."""
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"Duplicate JSON key: {key}")
        result[key] = value
    return result


def _reject_json_constant(value: str) -> None:
    """Reject non-standard JSON constants such as NaN and Infinity."""
    raise ValueError(f"Invalid JSON constant: {value}")


def _response_id_key(value: Any) -> tuple[str, str | int | float | None]:
    """Use type-safe, hashable JSON-RPC IDs when matching downstream replies."""
    if value is None:
        return ("null", None)
    if isinstance(value, str):
        return ("string", value)
    if isinstance(value, bool) or not isinstance(value, int | float):
        raise ValueError("Invalid JSON-RPC response ID type")
    if isinstance(value, float) and not math.isfinite(value):
        raise ValueError("Non-finite JSON-RPC response ID")
    return ("number", value)


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

    def __init__(self, command: list[str], *, max_response_bytes: int = 1048576) -> None:
        if isinstance(max_response_bytes, bool) or not isinstance(max_response_bytes, int):
            raise ValueError("max_response_bytes must be a positive integer")
        if max_response_bytes <= 0:
            raise ValueError("max_response_bytes must be positive")
        self.command = command
        self._max_response_bytes = max_response_bytes
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
        """Stop the child and drain its stdio pipes before the event loop closes."""
        process = self._process
        if process is None:
            return
        if process.returncode is None:
            process.terminate()
        try:
            # wait() alone leaves asyncio pipe transports open after child exit.
            await asyncio.wait_for(process.communicate(), timeout=5.0)
        except asyncio.TimeoutError:
            if process.returncode is None:
                process.kill()
            await asyncio.wait_for(process.communicate(), timeout=5.0)
        finally:
            self._process = None
            self._read_buffer = b""

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
                if newline_pos > self._max_response_bytes:
                    raise ValueError("Downstream MCP response exceeds size limit")
                line = self._read_buffer[:newline_pos]
                self._read_buffer = self._read_buffer[newline_pos + 1 :]
                if line.strip():
                    return line.strip()
                continue

            if len(self._read_buffer) > self._max_response_bytes:
                raise ValueError("Downstream MCP response exceeds size limit")
            # Read more data
            chunk = await self._process.stdout.read(8192)
            if not chunk:
                raise RuntimeError("Downstream server closed stdout")
            self._read_buffer += chunk


class OfflineDockerTransport(SubprocessTransport):
    """Track a uniquely named local Docker container and prove cleanup.

    The Docker CLI is a child process, not the actual container process.
    Killing that CLI alone may leave a running container behind. Cleanup
    therefore targets the exact random name on the local Docker daemon.
    """

    def __init__(
        self,
        sandbox: OfflineDockerSandbox,
        server_command: list[str],
        *,
        max_response_bytes: int = 1048576,
    ) -> None:
        self.container_name = "mcp-offline-" + secrets.token_hex(12)
        super().__init__(
            sandbox.build_command(server_command, container_name=self.container_name),
            max_response_bytes=max_response_bytes,
        )

    async def _docker_call(self, *args: str) -> tuple[int, bytes]:
        process = await asyncio.create_subprocess_exec(
            "docker",
            "--host",
            "unix:///var/run/docker.sock",
            *args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        try:
            stdout, _ = await asyncio.wait_for(process.communicate(), timeout=6.0)
        except asyncio.TimeoutError:
            process.kill()
            await process.communicate()
            raise RuntimeError("Offline Docker cleanup timed out") from None
        return process.returncode or 0, stdout

    async def stop(self) -> None:
        """Force-remove and verify the exact sandbox container, then close stdio."""
        cleanup_error: Exception | None = None
        try:
            await self._docker_call("rm", "--force", self.container_name)
            rc, remaining = await self._docker_call(
                "ps",
                "--all",
                "--filter",
                f"name=^/{self.container_name}$",
                "--format",
                "{{.Names}}",
            )
            if rc != 0 or remaining.strip():
                raise RuntimeError("Could not verify removal of offline Docker container")
        except Exception as exc:
            cleanup_error = exc
        finally:
            await super().stop()
        if cleanup_error is not None:
            raise RuntimeError("Offline Docker container cleanup could not be verified") from (
                cleanup_error
            )


class InternalDockerTransport(OfflineDockerTransport):
    """Attest a sole-proxy internal Docker network before any MCP launch.

    Ordinary host execution is never used when this profile was selected.
    The inherited stop() force-removes and verifies the exact container.
    """

    def __init__(
        self,
        sandbox: InternalDockerSandbox,
        server_command: list[str],
        *,
        max_response_bytes: int = 1048576,
    ) -> None:
        self._sandbox = sandbox
        self.container_name = "mcp-offline-" + secrets.token_hex(12)
        SubprocessTransport.__init__(
            self,
            sandbox.build_command(server_command, container_name=self.container_name),
            max_response_bytes=max_response_bytes,
        )

    async def start(self) -> None:
        try:
            rc, raw = await self._docker_call(
                "network",
                "inspect",
                self._sandbox.network_id,
                "--format",
                "{{json .}}",
            )
            if rc != 0 or len(raw) > 131072:
                raise ValueError("Invalid internal network inspection result")
            self._sandbox.validate_network_inspection(json.loads(raw))
        except (ValueError, RuntimeError, OSError, asyncio.TimeoutError) as exc:
            raise RuntimeError("Internal Docker network attestation failed closed") from exc
        await super().start()


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
            parsed_data = json.loads(
                raw_message,
                object_pairs_hook=_unique_json_pairs,
                parse_constant=_reject_json_constant,
            )
        except (json.JSONDecodeError, UnicodeDecodeError, RecursionError, ValueError) as e:
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
        server_id: str = "local",
        allowed_egress_hosts: set[str] | frozenset[str] | None = None,
        policy_engine: PolicyEngine | None = None,
        acl_guard: ACLGuard | None = None,
        authenticated_principal: str | None = None,
        session_binding: BoundSession | OIDCSessionBinding | None = None,
        protected_resource_tools: dict[str, str] | None = None,
        offline_sandbox: OfflineDockerSandbox | None = None,
        internal_sandbox: InternalDockerSandbox | None = None,
        multiplexed: bool = False,
        response_timeout_seconds: float = 120.0,
        max_message_bytes: int = 1048576,
    ) -> None:
        if (
            isinstance(response_timeout_seconds, bool)
            or not isinstance(response_timeout_seconds, int | float)
            or not math.isfinite(response_timeout_seconds)
            or response_timeout_seconds <= 0
        ):
            raise ValueError("response_timeout_seconds must be finite and positive")
        if (
            isinstance(max_message_bytes, bool)
            or not isinstance(max_message_bytes, int)
            or max_message_bytes <= 0
        ):
            raise ValueError("max_message_bytes must be a positive integer")
        self._response_timeout_seconds = float(response_timeout_seconds)
        self._max_message_bytes = max_message_bytes
        if offline_sandbox is not None and internal_sandbox is not None:
            raise ValueError("Offline and internal Docker modes cannot be combined")
        if internal_sandbox is not None:
            if not isinstance(internal_sandbox, InternalDockerSandbox):
                raise ValueError("internal_sandbox must be InternalDockerSandbox")
            if transport is not None:
                raise ValueError("Cannot override the trusted internal Docker transport")
            isolated = InternalDockerTransport(
                internal_sandbox, command, max_response_bytes=max_message_bytes
            )
            command = isolated.command
            transport = isolated
        if offline_sandbox is not None:
            if not isinstance(offline_sandbox, OfflineDockerSandbox):
                raise ValueError("offline_sandbox must be an OfflineDockerSandbox")
            if transport is not None:
                raise ValueError("Cannot override the isolated transport in offline sandbox mode")
            isolated = OfflineDockerTransport(
                offline_sandbox, command, max_response_bytes=max_message_bytes
            )
            command = isolated.command
            transport = isolated
        self._offline_sandbox = offline_sandbox
        self._internal_sandbox = internal_sandbox
        self.command = command
        selected_transport = transport or SubprocessTransport(
            command, max_response_bytes=max_message_bytes
        )
        if type(multiplexed) is not bool:
            raise ValueError("multiplexed must be a boolean")
        self._transport = (
            MultiplexedTransport(selected_transport, max_message_bytes=max_message_bytes)
            if multiplexed
            else selected_transport
        )
        self._detector = detector or PromptInjectionDetector(enable_ml=False)
        self._adapter = MCPJSONRPCAdapter()
        # The gateway operator assigns server identity, not the AI agent.
        # Outbound destinations are denied unless explicitly allowlisted.
        if not isinstance(server_id, str) or not server_id:
            raise ValueError("server_id must be a non-empty string")
        self._server_id = server_id
        self._acl_guard = acl_guard
        if session_binding is not None:
            if not isinstance(session_binding, BoundSession | OIDCSessionBinding):
                raise ValueError("session_binding must be a verified session binding")
            if authenticated_principal is not None:
                raise ValueError("Cannot mix signed session with legacy principal")
            try:
                authenticated_principal = session_binding.verify().principal
            except SessionVerificationError as exc:
                raise ValueError("Signed session verification failed") from exc
        self._session_binding = session_binding
        self._authenticated_principal = authenticated_principal
        self._protected_resource_tools = dict(protected_resource_tools or {})
        if self._protected_resource_tools and self._acl_guard is None:
            raise ValueError("protected resource tools require an ACLGuard")
        self._policy_engine = policy_engine or PolicyEngine(
            allowed_servers={server_id},
            allowed_egress_hosts=allowed_egress_hosts,
        )
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
        logger.info(
            "MCP proxy started, downstream: %s",
            (
                "attested internal Docker sandbox"
                if self._internal_sandbox is not None
                else "offline Docker sandbox"
                if self._offline_sandbox is not None
                else self.command
            ),
        )

    async def stop(self) -> None:
        """Stop the proxy and downstream server."""
        self._running = False
        await self._transport.stop()
        logger.info("MCP proxy stopped. Stats: %s", self._stats)

    def _blocked_requests(
        self,
        messages: list[dict[str, Any]],
        is_batch: bool,
        code: int,
        reason: str,
        data: dict[str, Any] | None = None,
    ) -> bytes:
        """Return a denial for each request ID, never for notifications or responses."""
        errors = [
            _build_error_response(message["id"], code, reason, data).rstrip(b"\n")
            for message in messages
            if "id" in message and "method" in message
        ]
        if not errors:
            return b""
        return b"[" + b",".join(errors) + b"]" if is_batch else errors[0]

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
        if len(raw_message) > self._max_message_bytes:
            self._stats["blocked"] += 1
            return _build_error_response(
                None, self.SECURITY_BLOCK_CODE, "Security: MCP request size limit exceeded"
            ).rstrip(b"\n")
        try:
            parsed = json.loads(
                raw_message,
                object_pairs_hook=_unique_json_pairs,
                parse_constant=_reject_json_constant,
            )
        except (json.JSONDecodeError, UnicodeDecodeError, RecursionError, ValueError) as exc:
            self._stats["blocked"] += 1
            return _build_error_response(None, -32700, f"Invalid JSON: {exc}").rstrip(b"\n")

        is_batch = isinstance(parsed, list)
        messages = parsed if is_batch else [parsed]
        if not messages or any(not isinstance(message, dict) for message in messages):
            self._stats["blocked"] += 1
            return _build_error_response(None, -32600, "Invalid JSON-RPC request").rstrip(b"\n")

        request_ids: list[tuple[str, str | int | float | None]] = []
        try:
            for message in messages:
                if message.get("jsonrpc") != "2.0":
                    raise ValueError("Invalid JSON-RPC version")
                if "method" in message:
                    if not isinstance(message["method"], str) or not message["method"]:
                        raise ValueError("Invalid JSON-RPC method")
                    if "result" in message or "error" in message:
                        raise ValueError("Request cannot contain a result or error")
                    if "params" in message and not isinstance(message["params"], dict | list):
                        raise ValueError("Invalid JSON-RPC params")
                    if "id" in message:
                        request_ids.append(_response_id_key(message["id"]))
                elif "id" not in message or ("result" in message) == ("error" in message):
                    raise ValueError("Invalid JSON-RPC response envelope")
                else:
                    _response_id_key(message["id"])
            if len(request_ids) != len(set(request_ids)):
                raise ValueError("Duplicate JSON-RPC request ID")
        except (TypeError, ValueError):
            self._stats["blocked"] += 1
            return _build_error_response(None, -32600, "Invalid JSON-RPC envelope").rstrip(b"\n")

        # A verified session protects the full request surface, not just
        # tools/call. Otherwise resources/read and prompts/get would bypass it.
        # The entire batch fails closed before forwarding if the session
        # expires, is revoked, or no longer maps to the bound tenant.
        if self._session_binding is not None and any("method" in item for item in messages):
            try:
                current = self._session_binding.verify()
                if current.principal != self._authenticated_principal:
                    raise SessionVerificationError("Session principal changed")
            except SessionVerificationError:
                self._stats["blocked"] += 1
                return self._blocked_requests(
                    messages,
                    is_batch,
                    self.SECURITY_BLOCK_CODE,
                    "Security: signed session invalid before request forwarding",
                    {"patterns": ["DENY_SESSION_AUTH"]},
                )

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
                if result.decision == Decision.INDETERMINATE:
                    failure = (
                        "Policy engine"
                        if "policy_engine_failure" in result.matched_patterns
                        else "Detector"
                    )
                    reason = f"Security: {failure} failure - failing closed"
                else:
                    reason = f"Security: {result.reason}"
                denial = (
                    self.SECURITY_BLOCK_CODE,
                    reason,
                    {"patterns": result.matched_patterns},
                )
                break

        if denial is not None:
            code, reason, data = denial
            # Deny the batch atomically; clients need a reply for each request ID.
            return self._blocked_requests(messages, is_batch, code, reason, data)

        try:
            expects_reply = any("id" in message and "method" in message for message in messages)
            if isinstance(self._transport, MultiplexedTransport):
                if len(messages) == 1 and messages[0].get("method") == "notifications/cancelled":
                    params = messages[0].get("params")
                    if not isinstance(params, dict) or "requestId" not in params:
                        raise ValueError("Invalid cancellation notification")
                    self._transport.cancel(params["requestId"])
                response = await self._transport.exchange(
                    raw_message + b"\n",
                    request_ids=request_ids,
                    timeout=self._response_timeout_seconds,
                    is_batch=is_batch,
                )
            else:
                await self._transport.send(raw_message + b"\n")
                if not expects_reply:
                    self._stats["allowed" if tool_count else "passthrough"] += 1
                    return b""  # Notifications and client responses are one-way.
                response = await asyncio.wait_for(
                    self._transport.receive(), timeout=self._response_timeout_seconds
                )
            if not expects_reply:
                self._stats["allowed" if tool_count else "passthrough"] += 1
                return b""
            if not isinstance(response, bytes) or len(response) > self._max_message_bytes:
                raise ValueError("Invalid or oversized downstream MCP response")
        except Exception:
            logger.exception("Downstream MCP transport failure; suppressing response")
            self._stats["blocked"] += 1
            return self._blocked_requests(
                messages,
                is_batch,
                self.SECURITY_BLOCK_CODE,
                "Security: downstream transport failure - failing closed",
            )
        self._stats["allowed" if tool_count else "passthrough"] += 1
        if request_ids:
            # An already-forwarded call must not release a result if its
            # gateway-bound authentication expires or fails meanwhile.
            if self._session_binding is not None:
                try:
                    session = self._session_binding.verify()
                    if session.principal != self._authenticated_principal:
                        raise SessionVerificationError("Session principal changed")
                except SessionVerificationError:
                    self._stats["blocked"] += 1
                    return self._blocked_requests(
                        messages,
                        is_batch,
                        self.SECURITY_BLOCK_CODE,
                        "Security: signed session invalid before response release",
                        {"patterns": ["DENY_SESSION_AUTH"]},
                    )
            # All server replies are untrusted, including tool discovery,
            # resources/read, prompts/get, and initialization responses.
            # Revocation may occur after a tool request was sent.
            # Check the current trusted ACL again before releasing its response.
            # A denial suppresses the entire batch rather than leaking a
            # previously authorized result alongside a revoked result.
            for message in messages:
                if message.get("method") != "tools/call":
                    continue
                try:
                    tool_calls = self._adapter.parse_message(message)
                    for tool_call in tool_calls:
                        resource_key = self._protected_resource_tools.get(tool_call.name)
                        if resource_key is None:
                            continue
                        resource_id = tool_call.arguments.get(resource_key)
                        if not isinstance(resource_id, str) or self._acl_guard is None:
                            raise AccessDenied("Missing protected resource or ACL guard")
                        self._acl_guard.check(self._authenticated_principal or "", resource_id)
                except Exception:
                    logger.warning("Suppressed downstream response after ACL recheck")
                    self._stats["blocked"] += 1
                    return self._blocked_requests(
                        messages,
                        is_batch,
                        self.SECURITY_BLOCK_CODE,
                        "Security: resource access revoked before response release",
                        {"patterns": ["DENY_RESOURCE_ACL"]},
                    )
            # Every downstream MCP response is untrusted, including tool
            # descriptions, resources, prompts and non-tool protocol results.
            try:
                payload = json.loads(
                    response,
                    object_pairs_hook=_unique_json_pairs,
                    parse_constant=_reject_json_constant,
                )
                results = payload if isinstance(payload, list) else [payload]
                if not results or any(
                    not isinstance(item, dict)
                    or item.get("jsonrpc") != "2.0"
                    or ("result" in item) == ("error" in item)
                    or "method" in item
                    or "id" not in item
                    for item in results
                ):
                    raise ValueError("Invalid downstream JSON-RPC response")
                # Never release data attributed to another request ID. A
                # downstream response can arrive out of order within a batch,
                # but must have exactly the expected unique IDs.
                expected_ids = [
                    _response_id_key(message["id"])
                    for message in messages
                    if "id" in message and "method" in message
                ]
                received_ids = [_response_id_key(item["id"]) for item in results]
                if len(expected_ids) != len(set(expected_ids)) or Counter(received_ids) != Counter(
                    expected_ids
                ):
                    raise ValueError("Downstream response IDs do not match requests")
                for item in results:
                    detected, patterns = self._detector.detect(
                        {
                            "name": "mcp_tool_response",
                            "arguments": {
                                "result": item.get("result"),
                                "error": item.get("error"),
                            },
                        }
                    )
                    if detected:
                        logger.warning("Blocked suspicious downstream MCP result: %s", patterns)
                        self._stats["blocked"] += 1
                        return self._blocked_requests(
                            messages,
                            is_batch,
                            self.SECURITY_BLOCK_CODE,
                            "Security: downstream MCP response failed inspection",
                            {"patterns": patterns},
                        )
            except Exception:
                logger.exception("Downstream MCP result inspection failed closed")
                self._stats["blocked"] += 1
                return self._blocked_requests(
                    messages,
                    is_batch,
                    self.SECURITY_BLOCK_CODE,
                    "Security: downstream MCP response validation failed",
                )
        return response

    def _inspect(self, parsed: dict[str, Any]) -> InspectionResult:
        """Run security inspection on a parsed JSON-RPC tools/call message."""
        request_id = parsed.get("id")
        detector_errors: list[str] = []

        if self._session_binding is not None:
            try:
                session = self._session_binding.verify()
                if session.principal != self._authenticated_principal:
                    raise SessionVerificationError("Session principal changed")
            except SessionVerificationError:
                return InspectionResult(
                    decision=Decision.BLOCK,
                    reason="Signed session expired or invalid",
                    matched_patterns=["DENY_SESSION_AUTH"],
                    request_id=request_id,
                )

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
            # The authenticated principal is supplied by gateway configuration,
            # never by the agent's MCP arguments.
            if tool_call.name in self._protected_resource_tools:
                resource_key = self._protected_resource_tools[tool_call.name]
                try:
                    resource_id = tool_call.arguments.get(resource_key)
                    if not isinstance(resource_id, str):
                        raise AccessDenied("Missing resource identifier")
                    assert self._acl_guard is not None
                    self._acl_guard.check(self._authenticated_principal or "", resource_id)
                except Exception:
                    return InspectionResult(
                        decision=Decision.BLOCK,
                        reason="ACL denied protected resource access",
                        matched_patterns=["DENY_RESOURCE_ACL"],
                        request_id=request_id,
                    )
            # Apply policy before forwarding. Policy errors fail closed.
            try:
                policy_decision = self._policy_engine.evaluate(
                    {
                        "name": tool_call.name,
                        "server_id": self._server_id,
                        "arguments": tool_call.arguments,
                    }
                )
            except Exception as exc:
                logger.exception("Authorization policy engine failed")
                return InspectionResult(
                    decision=Decision.INDETERMINATE,
                    reason="Policy engine failed",
                    matched_patterns=["policy_engine_failure"],
                    request_id=request_id,
                    detector_errors=[f"policy: {exc}"],
                )
            if not policy_decision.allowed:
                return InspectionResult(
                    decision=Decision.BLOCK,
                    reason=f"Policy denied: {policy_decision.reason_code.value}",
                    matched_patterns=[policy_decision.reason_code.value],
                    request_id=request_id,
                )
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

    # Flags before '--' configure this gateway; after '--' is the server.
    import argparse

    if "--" in args:
        sep_idx = args.index("--")
        gateway_args, command = args[:sep_idx], args[sep_idx + 1 :]
    else:
        gateway_args, command = [], args

    parser = argparse.ArgumentParser(description="Inline MCP security gateway")
    parser.add_argument("--server-id", default="local")
    parser.add_argument("--allow-egress-host", action="append", default=[])
    parser.add_argument(
        "--offline-sandbox-image",
        help="Preloaded Docker image digest or ID (sha256:...) for offline network-none isolation",
    )
    parser.add_argument("--internal-sandbox-image")
    parser.add_argument("--internal-network-id")
    parser.add_argument("--internal-proxy-id")
    parser.add_argument("--internal-proxy-name")
    parser.add_argument("--internal-proxy-port", type=int, default=3128)
    options = parser.parse_args(gateway_args)

    if not command:
        print(
            "Usage: python -m mcp_monitor.proxy.stdio_proxy -- <command> [args...]",
            file=sys.stderr,
        )
        sys.exit(1)

    internal_options = (
        options.internal_sandbox_image,
        options.internal_network_id,
        options.internal_proxy_id,
        options.internal_proxy_name,
    )
    if any(item is not None for item in internal_options) and not all(
        item is not None for item in internal_options
    ):
        parser.error("All internal sandbox and trusted proxy identity options are required")
    if options.offline_sandbox_image and options.internal_sandbox_image:
        parser.error("Offline and internal Docker profiles are mutually exclusive")

    proxy = StdioMCPProxy(
        command,
        server_id=options.server_id,
        allowed_egress_hosts=set(options.allow_egress_host),
        offline_sandbox=(
            OfflineDockerSandbox(options.offline_sandbox_image)
            if options.offline_sandbox_image
            else None
        ),
        internal_sandbox=(
            InternalDockerSandbox(
                image=options.internal_sandbox_image,
                network_id=options.internal_network_id,
                proxy_container_id=options.internal_proxy_id,
                proxy_name=options.internal_proxy_name,
                proxy_port=options.internal_proxy_port,
            )
            if options.internal_sandbox_image
            else None
        ),
    )
    asyncio.run(proxy.run())


if __name__ == "__main__":
    main()
