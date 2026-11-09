"""Phase 11 synthetic side-effect deduplication and ambiguous-outcome tests."""

from __future__ import annotations

import asyncio
import json
import sqlite3

import pytest

from mcp_monitor.protocol.effect_journal import DurableEffectJournal, EffectJournalError
from mcp_monitor.proxy.stdio_proxy import StdioMCPProxy

PRINCIPAL = "tenantA:alice"
TOOL = "write_file"
ARGS = {"path": "/sandbox/synthetic.txt", "content": "SAFE"}


def make_request(key: str = "operation-01", *, arguments=None, ident: int = 7) -> bytes:
    return json.dumps(
        {
            "jsonrpc": "2.0",
            "id": ident,
            "method": "tools/call",
            "params": {
                "name": TOOL,
                "_gateway_operation_key": key,
                "arguments": ARGS if arguments is None else arguments,
            },
        }
    ).encode()


@pytest.fixture
def journal(tmp_path):
    return DurableEffectJournal.bootstrap(tmp_path / "effects.sqlite3")


class ControlledTransport:
    def __init__(self, reply=None, delay: float = 0.0):
        self.sent = []
        self.reply = reply or b'{"jsonrpc":"2.0","id":7,"result":{"ok":true}}'
        self.delay = delay

    async def send(self, raw):
        self.sent.append(raw)

    async def receive(self):
        if self.delay:
            await asyncio.sleep(self.delay)
        return self.reply

    async def start(self):
        pass

    async def stop(self):
        pass


def proxy(journal, transport, **options):
    return StdioMCPProxy(
        command=["synthetic"],
        transport=transport,
        authenticated_principal=PRINCIPAL,
        effect_journal=journal,
        effect_tools={TOOL},
        **options,
    )


def status(journal, key="operation-01"):
    return journal.status(principal=PRINCIPAL, server="local", tool=TOOL, operation_key=key)


def test_success_reserved_before_dispatch_and_exactly_one_forward(journal):
    async def scenario():
        transport = ControlledTransport()
        gateway = proxy(journal, transport)
        raw = await gateway.handle_message(make_request())
        assert json.loads(raw)["result"] == {"ok": True}
        assert status(journal) == "COMPLETED"
        forwarded = json.loads(transport.sent[0])
        assert "_gateway_operation_key" not in forwarded["params"]
        assert len(transport.sent) == 1
        duplicate = await gateway.handle_message(make_request(ident=8))
        assert json.loads(duplicate)["error"]["code"] == gateway.SECURITY_BLOCK_CODE
        assert len(transport.sent) == 1

    asyncio.run(scenario())


def test_restart_with_uncertain_intent_denies_duplicate(tmp_path):
    path = tmp_path / "effects.sqlite3"
    journal = DurableEffectJournal.bootstrap(path)
    journal.reserve(
        principal=PRINCIPAL,
        server="local",
        tool=TOOL,
        operation_key="op-restart",
        arguments=ARGS,
    )
    restarted = DurableEffectJournal(path)
    transport = ControlledTransport()

    async def scenario():
        gateway = proxy(restarted, transport)
        response = await gateway.handle_message(make_request("op-restart"))
        assert json.loads(response)["error"]["code"] == gateway.SECURITY_BLOCK_CODE
        assert transport.sent == []
    asyncio.run(scenario())
    assert status(restarted, "op-restart") == "UNCERTAIN"


def test_same_key_different_payload_denied(journal):
    journal.reserve(
        principal=PRINCIPAL,
        server="local",
        tool=TOOL,
        operation_key="operation-01",
        arguments=ARGS,
    )
    with pytest.raises(EffectJournalError):
        journal.reserve(
            principal=PRINCIPAL,
            server="local",
            tool=TOOL,
            operation_key="operation-01",
            arguments={"unexpected": "new"},
        )


def test_missing_key_and_unauthenticated_principal_block_before_send(journal):
    async def scenario():
        transport = ControlledTransport()
        gateway = proxy(journal, transport)
        raw = json.loads(make_request())
        del raw["params"]["_gateway_operation_key"]
        blocked = await gateway.handle_message(json.dumps(raw).encode())
        assert json.loads(blocked)["error"]["code"] == gateway.SECURITY_BLOCK_CODE
        assert transport.sent == []
        no_identity = StdioMCPProxy(
            command=["synthetic"],
            transport=transport,
            effect_journal=journal,
            effect_tools={TOOL},
        )
        result = await no_identity.handle_message(make_request())
        assert json.loads(result)["error"]["code"] == gateway.SECURITY_BLOCK_CODE
        assert transport.sent == []

    asyncio.run(scenario())


def test_timeout_leaves_uncertain_and_denies_retry(journal):
    async def scenario():
        transport = ControlledTransport(delay=0.04)
        gateway = proxy(journal, transport, response_timeout_seconds=0.001)
        result = await gateway.handle_message(make_request())
        assert json.loads(result)["error"]["code"] == gateway.SECURITY_BLOCK_CODE
        assert len(transport.sent) == 1
        assert status(journal) == "UNCERTAIN"
        again = await gateway.handle_message(make_request(ident=8))
        assert json.loads(again)["error"]["code"] == gateway.SECURITY_BLOCK_CODE
        assert len(transport.sent) == 1

    asyncio.run(scenario())


def test_downstream_error_is_uncertain_not_replay_safe(journal):
    async def scenario():
        transport = ControlledTransport(
            reply=b'{"jsonrpc":"2.0","id":7,"error":{"code":-32001,"message":"maybe applied"}}'
        )
        gateway = proxy(journal, transport)
        raw = await gateway.handle_message(make_request())
        assert json.loads(raw)["error"]["code"] == gateway.SECURITY_BLOCK_CODE
        assert status(journal) == "UNCERTAIN"

    asyncio.run(scenario())


def test_missing_database_never_forwards(journal):
    path = journal._path
    path.unlink()

    async def scenario():
        transport = ControlledTransport()
        gateway = proxy(journal, transport)
        raw = await gateway.handle_message(make_request())
        assert json.loads(raw)["error"]["code"] == gateway.SECURITY_BLOCK_CODE
        assert transport.sent == []

    asyncio.run(scenario())


def test_atomic_duplicate_reservation_from_two_instances(tmp_path):
    path = tmp_path / "shared.sqlite3"
    first = DurableEffectJournal.bootstrap(path)
    second = DurableEffectJournal(path)
    first.reserve(
        principal=PRINCIPAL,
        server="local",
        tool=TOOL,
        operation_key="duplicate",
        arguments=ARGS,
    )
    with pytest.raises(EffectJournalError):
        second.reserve(
            principal=PRINCIPAL,
            server="local",
            tool=TOOL,
            operation_key="duplicate",
            arguments=ARGS,
        )


def test_batch_containing_effect_is_denied(journal):
    async def scenario():
        transport = ControlledTransport()
        gateway = proxy(journal, transport)
        batch = json.dumps(
            [
                json.loads(make_request()),
                {
                    "jsonrpc": "2.0",
                    "id": 8,
                    "method": "tools/list",
                    "params": {},
                },
            ]
        ).encode()
        reply = json.loads(await gateway.handle_message(batch))
        assert len(reply) == 2
        assert all(x["error"]["code"] == gateway.SECURITY_BLOCK_CODE for x in reply)
        assert transport.sent == []

    asyncio.run(scenario())


def test_non_effect_read_keeps_existing_behavior(journal):
    async def scenario():
        transport = ControlledTransport()
        gateway = proxy(journal, transport)
        read = b'{"jsonrpc":"2.0","id":7,"method":"tools/list","params":{}}'
        reply = await gateway.handle_message(read)
        assert json.loads(reply)["result"]["ok"] is True
        assert status(journal) is None
        assert len(transport.sent) == 1

    asyncio.run(scenario())


@pytest.mark.parametrize("value", ["", "a space", None, 7, "a" * 129])
def test_invalid_operation_keys_fail_closed(journal, value):
    with pytest.raises(EffectJournalError):
        journal.reserve(
            principal=PRINCIPAL, server="local", tool=TOOL, operation_key=value, arguments=ARGS
        )


def test_corrupt_completion_state_fails_closed(journal):
    with sqlite3.connect(journal._path) as db:
        db.execute("PRAGMA ignore_check_constraints = ON")
        db.execute(
            "INSERT INTO effects VALUES (?, ?, ?, ?, ?, ?)",
            (PRINCIPAL, "local", TOOL, "corrupt", "abc", "UNSAFE"),
        )
    with pytest.raises(EffectJournalError):
        journal.status(principal=PRINCIPAL, server="local", tool=TOOL, operation_key="corrupt")
