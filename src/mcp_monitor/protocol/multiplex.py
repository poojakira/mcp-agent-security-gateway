"""Opt-in bounded JSON-RPC stdio response broker for a single MCP connection.

The broker routes out-of-order replies to in-flight request IDs. It does not
authorize requests or inspect response content: the enclosing StdioMCPProxy
must continue enforcing its existing pre-send and post-receive security gates.

Unsolicited server requests/notifications are NOT supported; they fail closed.
Late replies after cancellation/timeout are discarded using non-reusable IDs.
The broker requires a restart before tombstone capacity is exhausted.
"""

from __future__ import annotations

import asyncio
import json
import math
from collections.abc import Sequence
from typing import Any, Protocol


class TransportLike(Protocol):
    async def start(self) -> None: ...
    async def stop(self) -> None: ...
    async def send(self, raw: bytes) -> None: ...
    async def receive(self) -> bytes: ...


class ProtocolCancelled(Exception):
    """An in-flight request was cancelled by its authenticated MCP client."""


def _unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for name, value in pairs:
        if name in result:
            raise ValueError("Duplicate downstream JSON key")
        result[name] = value
    return result


def _no_constants(value: str) -> None:
    raise ValueError("Invalid nonstandard JSON number")


def _key(value: object) -> tuple[str, str | int | float | None]:
    if value is None:
        return ("null", None)
    if type(value) is str:
        return ("string", value)
    if type(value) not in (int, float):
        raise ValueError("Invalid JSON-RPC request ID")
    if isinstance(value, float) and not math.isfinite(value):
        raise ValueError("Invalid nonfinite JSON-RPC request ID")
    return ("number", value)


class MultiplexedTransport:
    """Single-reader broker; fail closed on unexpected downstream protocol state."""

    def __init__(
        self,
        transport: TransportLike,
        *,
        max_message_bytes: int = 1048576,
        max_inflight: int = 64,
        max_retired: int = 1024,
    ) -> None:
        if (
            type(max_message_bytes) is not int
            or max_message_bytes <= 0
            or type(max_inflight) is not int
            or not 1 <= max_inflight <= 256
            or type(max_retired) is not int
            or max_retired < max_inflight
        ):
            raise ValueError("Invalid broker capacity")
        self._transport = transport
        self._max_message_bytes = max_message_bytes
        self._max_inflight = max_inflight
        self._max_retired = max_retired
        self._pending: dict[tuple, asyncio.Future[dict]] = {}
        self._retired: set[tuple] = set()
        self._send_lock = asyncio.Lock()
        self._reader: asyncio.Task | None = None
        self._failure: Exception | None = None
        self._started = False

    async def start(self) -> None:
        if self._started or self._failure is not None:
            raise RuntimeError("Broker cannot restart without a fresh session")
        await self._transport.start()
        self._started = True
        self._reader = asyncio.create_task(self._read_loop())

    async def stop(self) -> None:
        self._started = False
        self._poison(RuntimeError("MCP protocol session closed"))
        if self._reader is not None:
            self._reader.cancel()
            try:
                await self._reader
            except asyncio.CancelledError:
                pass
            self._reader = None
        await self._transport.stop()

    def _poison(self, exc: Exception) -> None:
        if self._failure is None:
            self._failure = RuntimeError("Downstream MCP protocol state invalid")
        for future in tuple(self._pending.values()):
            if not future.done():
                future.set_exception(self._failure)
        self._pending.clear()

    def _retire(self, ids: Sequence[tuple]) -> None:
        self._retired.update(ids)
        if len(self._retired) > self._max_retired:
            self._poison(RuntimeError("MCP request-ID quarantine capacity exceeded"))

    async def _read_loop(self) -> None:
        try:
            while self._started:
                raw = await self._transport.receive()
                if not isinstance(raw, bytes) or len(raw) > self._max_message_bytes:
                    raise ValueError("Invalid or oversized downstream frame")
                message = json.loads(
                    raw, object_pairs_hook=_unique_pairs, parse_constant=_no_constants
                )
                items = message if isinstance(message, list) else [message]
                if not items:
                    raise ValueError("Empty downstream batch")
                # Validate the ENTIRE frame before releasing any item.
                # Otherwise an invalid second item could leak a valid first.
                seen: set[tuple] = set()
                staged: list[tuple[tuple, dict[str, Any]]] = []
                for item in items:
                    if (
                        not isinstance(item, dict)
                        or item.get("jsonrpc") != "2.0"
                        or "id" not in item
                        or "method" in item
                        or ("result" in item) == ("error" in item)
                    ):
                        raise ValueError("Unsolicited server message or invalid response")
                    key = _key(item["id"])
                    if key in seen:
                        raise ValueError("Duplicate downstream response ID")
                    seen.add(key)
                    if key not in self._pending and key not in self._retired:
                        raise ValueError("Unknown downstream request ID")
                    staged.append((key, item))
                for key, item in staged:
                    future = self._pending.pop(key, None)
                    if future is not None:
                        self._retire([key])
                        if not future.done():
                            future.set_result(item)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            self._poison(exc)

    def cancel(self, request_id: object) -> None:
        """Quarantine a request ID before forwarding notifications/cancelled."""
        key = _key(request_id)
        future = self._pending.pop(key, None)
        if future is not None:
            self._retire([key])
            if not future.done():
                future.set_exception(ProtocolCancelled("MCP request cancelled"))

    async def exchange(
        self,
        raw: bytes,
        *,
        request_ids: Sequence[tuple],
        timeout: float,
        is_batch: bool,
    ) -> bytes:
        if not self._started or self._failure is not None:
            raise RuntimeError("MCP broker unavailable")
        if len(raw) > self._max_message_bytes:
            raise ValueError("MCP request too large")
        if not request_ids and not raw.endswith(b"\n"):
            raise ValueError("Invalid MCP request framing")
        if len(request_ids) != len(set(request_ids)):
            raise ValueError("Duplicate IDs within request")
        loop = asyncio.get_running_loop()
        pending: list[asyncio.Future[dict]] = []
        async with self._send_lock:
            if self._failure is not None or not self._started:
                raise RuntimeError("MCP broker unavailable")
            if len(self._pending) + len(request_ids) > self._max_inflight:
                raise RuntimeError("MCP in-flight capacity exceeded")
            if any(k in self._pending or k in self._retired for k in request_ids):
                raise RuntimeError("Request ID already active or retired")
            for key in request_ids:
                future: asyncio.Future[dict] = loop.create_future()
                future.add_done_callback(lambda f: f.exception() if not f.cancelled() else None)
                self._pending[key] = future
                pending.append(future)
            try:
                await self._transport.send(raw)
            except Exception:
                for key in request_ids:
                    self._pending.pop(key, None)
                self._retire(request_ids)
                self._poison(RuntimeError("MCP downstream send failed"))
                raise
        if not pending:
            return b""
        try:
            results = await asyncio.wait_for(asyncio.gather(*pending), timeout=timeout)
        finally:
            for key in request_ids:
                self._pending.pop(key, None)
            self._retire(request_ids)
        if is_batch:
            return json.dumps(results, separators=(",", ":")).encode()
        return json.dumps(results[0], separators=(",", ":")).encode()
