"""Phase 10: bounded concurrent MCP JSON-RPC routing and cancellation."""

from __future__ import annotations

import asyncio
import json

import pytest

from mcp_monitor.protocol.multiplex import MultiplexedTransport
from mcp_monitor.proxy.stdio_proxy import StdioMCPProxy


class ControlledTransport:
    def __init__(self) -> None:
        self.sent: asyncio.Queue[bytes] = asyncio.Queue()
        self.responses: asyncio.Queue[bytes] = asyncio.Queue()
        self.stopped = False

    async def start(self) -> None:
        pass

    async def stop(self) -> None:
        self.stopped = True

    async def send(self, raw: bytes) -> None:
        await self.sent.put(raw)

    async def receive(self) -> bytes:
        return await self.responses.get()

    async def reply(self, ident: object, content: str = "SAFE") -> None:
        await self.responses.put(
            json.dumps({"jsonrpc": "2.0", "id": ident, "result": {"content": content}}).encode()
        )


def req(ident: int, method: str = "resources/read") -> bytes:
    return json.dumps({"jsonrpc": "2.0", "id": ident, "method": method, "params": {}}).encode()


def _error(raw: bytes) -> int:
    return json.loads(raw)["error"]["code"]


def test_concurrent_out_of_order_responses_are_correctly_correlated() -> None:
    async def scenario() -> None:
        backend = ControlledTransport()
        proxy = StdioMCPProxy(command=["synthetic"], transport=backend, multiplexed=True)
        await proxy.start()
        try:
            first = asyncio.create_task(proxy.handle_message(req(11)))
            second = asyncio.create_task(proxy.handle_message(req(12)))
            assert await asyncio.wait_for(backend.sent.get(), 2)
            assert await asyncio.wait_for(backend.sent.get(), 2)
            await backend.reply(12, "SECOND")
            await backend.reply(11, "FIRST")
            assert json.loads(await first)["result"]["content"] == "FIRST"
            assert json.loads(await second)["result"]["content"] == "SECOND"
        finally:
            await proxy.stop()

    asyncio.run(scenario())


def test_batch_responses_correlate_when_pieces_arrive_separately() -> None:
    async def scenario() -> None:
        backend = ControlledTransport()
        proxy = StdioMCPProxy(command=["synthetic"], transport=backend, multiplexed=True)
        await proxy.start()
        try:
            batch = json.dumps([json.loads(req(21)), json.loads(req(22))]).encode()
            call = asyncio.create_task(proxy.handle_message(batch))
            await asyncio.wait_for(backend.sent.get(), 2)
            await backend.reply(22, "SECOND")
            await backend.reply(21, "FIRST")
            responses = json.loads(await call)
            assert [r["id"] for r in responses] == [21, 22]
            assert [r["result"]["content"] for r in responses] == ["FIRST", "SECOND"]
        finally:
            await proxy.stop()

    asyncio.run(scenario())


def test_unknown_id_poison_fails_closed_and_does_not_leak() -> None:
    async def scenario() -> None:
        backend = ControlledTransport()
        proxy = StdioMCPProxy(command=["synthetic"], transport=backend, multiplexed=True)
        await proxy.start()
        try:
            call = asyncio.create_task(proxy.handle_message(req(31)))
            await backend.sent.get()
            await backend.reply(999, "PRIVATE_UNEXPECTED_DATA")
            raw = await asyncio.wait_for(call, 2)
            assert _error(raw) == StdioMCPProxy.SECURITY_BLOCK_CODE
            assert b"PRIVATE_UNEXPECTED_DATA" not in raw
            again = await proxy.handle_message(req(32))
            assert _error(again) == StdioMCPProxy.SECURITY_BLOCK_CODE
        finally:
            await proxy.stop()

    asyncio.run(scenario())


def test_notification_without_id_has_no_waiter() -> None:
    async def scenario() -> None:
        backend = ControlledTransport()
        proxy = StdioMCPProxy(command=["synthetic"], transport=backend, multiplexed=True)
        await proxy.start()
        try:
            message = b'{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}'
            assert await proxy.handle_message(message) == b""
            assert await backend.sent.get() == message + b"\n"
        finally:
            await proxy.stop()

    asyncio.run(scenario())


def test_cancel_pending_request_quarantines_late_result() -> None:
    async def scenario() -> None:
        backend = ControlledTransport()
        proxy = StdioMCPProxy(command=["synthetic"], transport=backend, multiplexed=True)
        await proxy.start()
        try:
            active = asyncio.create_task(proxy.handle_message(req(41)))
            await backend.sent.get()
            cancel = (
                b'{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":41}}'
            )
            assert await proxy.handle_message(cancel) == b""
            await backend.sent.get()
            assert _error(await asyncio.wait_for(active, 2)) == StdioMCPProxy.SECURITY_BLOCK_CODE
            await backend.reply(41, "LATE_PRIVATE_VALUE")
            later = asyncio.create_task(proxy.handle_message(req(42)))
            await backend.sent.get()
            await backend.reply(42, "VALID_RESULT")
            assert json.loads(await later)["result"]["content"] == "VALID_RESULT"
            assert _error(await proxy.handle_message(req(41))) == StdioMCPProxy.SECURITY_BLOCK_CODE
        finally:
            await proxy.stop()

    asyncio.run(scenario())


def test_timeout_quarantines_late_reply() -> None:
    async def scenario() -> None:
        backend = ControlledTransport()
        proxy = StdioMCPProxy(
            command=["synthetic"],
            transport=backend,
            multiplexed=True,
            response_timeout_seconds=0.01,
        )
        await proxy.start()
        try:
            expired = await proxy.handle_message(req(51))
            assert _error(expired) == StdioMCPProxy.SECURITY_BLOCK_CODE
            await backend.sent.get()
            await backend.reply(51, "LATE_PRIVATE")
            request = asyncio.create_task(proxy.handle_message(req(52)))
            await backend.sent.get()
            await backend.reply(52, "NEW_SAFE")
            assert json.loads(await request)["result"]["content"] == "NEW_SAFE"
        finally:
            await proxy.stop()

    asyncio.run(scenario())


def test_malicious_server_notification_fails_closed() -> None:
    async def scenario() -> None:
        backend = ControlledTransport()
        proxy = StdioMCPProxy(command=["synthetic"], transport=backend, multiplexed=True)
        await proxy.start()
        try:
            waiting = asyncio.create_task(proxy.handle_message(req(61)))
            await backend.sent.get()
            await backend.responses.put(
                b'{"jsonrpc":"2.0","method":"sampling/createMessage","params":{"data":"PRIVATE"}}'
            )
            result = await asyncio.wait_for(waiting, 2)
            assert _error(result) == StdioMCPProxy.SECURITY_BLOCK_CODE
            assert b"PRIVATE" not in result
        finally:
            await proxy.stop()

    asyncio.run(scenario())


def test_bounded_pending_capacity_denies_excess_without_forwarding() -> None:
    async def scenario() -> None:
        backend = ControlledTransport()
        broker = MultiplexedTransport(backend, max_inflight=1)
        await broker.start()
        try:
            first = asyncio.create_task(
                broker.exchange(
                    req(71) + b"\n", request_ids=[("number", 71)], timeout=2, is_batch=False
                )
            )
            await backend.sent.get()
            with pytest.raises(RuntimeError, match="capacity"):
                await broker.exchange(
                    req(72) + b"\n", request_ids=[("number", 72)], timeout=1, is_batch=False
                )
            assert backend.sent.empty()
            await backend.reply(71)
            assert json.loads(await first)["id"] == 71
        finally:
            await broker.stop()

    asyncio.run(scenario())


def test_duplicate_response_fails_closed() -> None:
    async def scenario() -> None:
        backend = ControlledTransport()
        broker = MultiplexedTransport(backend)
        await broker.start()
        try:
            future = asyncio.create_task(
                broker.exchange(
                    req(81) + b"\n", request_ids=[("number", 81)], timeout=2, is_batch=False
                )
            )
            await backend.sent.get()
            duplicate = [
                {"jsonrpc": "2.0", "id": 81, "result": {}},
                {"jsonrpc": "2.0", "id": 81, "result": {}},
            ]
            await backend.responses.put(json.dumps(duplicate).encode())
            with pytest.raises(RuntimeError):
                await asyncio.wait_for(future, 2)
        finally:
            await broker.stop()

    asyncio.run(scenario())


@pytest.mark.parametrize("max_inflight", [0, -1, 257, True, "8"])
def test_invalid_inflight_limits_rejected(max_inflight) -> None:
    with pytest.raises(ValueError):
        MultiplexedTransport(ControlledTransport(), max_inflight=max_inflight)
