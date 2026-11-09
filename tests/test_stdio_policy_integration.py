"""End-to-end policy enforcement at the actual stdio proxy boundary.

These tests use the production StdioMCPProxy.handle_message code path, with
a fake downstream transport. They prove no forwarding occurs on policy deny.
"""

import asyncio
import json

from mcp_monitor.policy.policy_engine import PolicyEngine
from mcp_monitor.proxy.stdio_proxy import StdioMCPProxy


class FakeTransport:
    def __init__(self):
        self.sent = []

    async def send(self, message):
        self.sent.append(message)

    async def receive(self):
        return b'{"jsonrpc":"2.0","id":1,"result":{"ok":true}}'

    async def start(self):
        pass

    async def stop(self):
        pass


def tool_call(name, arguments=None):
    return json.dumps(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": name, "arguments": arguments or {}},
        }
    ).encode()


def run_case(message, **kwargs):
    transport = FakeTransport()
    proxy = StdioMCPProxy(command=["fake"], transport=transport, **kwargs)
    response = json.loads(asyncio.run(proxy.handle_message(message)))
    return response, transport.sent


def test_dangerous_tool_with_clean_arguments_never_reaches_server():
    response, sent = run_case(tool_call("delete_file", {"path": "/tmp/report"}))
    assert response["error"]["code"] == StdioMCPProxy.SECURITY_BLOCK_CODE
    assert "DENY_DANGEROUS_TOOL" in response["error"]["message"]
    assert sent == []


def test_unapproved_network_destination_never_reaches_server():
    response, sent = run_case(tool_call("http_get", {"url": "https://untrusted.example/data"}))
    assert "DENY_EGRESS_NOT_ALLOWED" in response["error"]["message"]
    assert sent == []


def test_private_network_destination_never_reaches_server():
    response, sent = run_case(tool_call("http_get", {"url": "http://127.0.0.1:8080/admin"}))
    assert "DENY_EGRESS_NOT_ALLOWED" in response["error"]["message"]
    assert sent == []


def test_safe_tool_reaches_server():
    message = tool_call("read_file", {"path": "/tmp/report"})
    response, sent = run_case(message)
    assert response["result"]["ok"] is True
    assert sent == [message + b"\n"]


def test_allowlisted_network_destination_reaches_server():
    message = tool_call("http_get", {"url": "https://api.example.com/data"})
    response, sent = run_case(message, allowed_egress_hosts={"api.example.com"})
    assert response["result"]["ok"] is True
    assert sent == [message + b"\n"]


def test_unknown_server_denied_without_forwarding():
    engine = PolicyEngine(allowed_servers={"authorized-server"})
    response, sent = run_case(
        tool_call("read_file", {"path": "/tmp/report"}),
        server_id="unexpected-server",
        policy_engine=engine,
    )
    assert "DENY_SERVER_NOT_ALLOWED" in response["error"]["message"]
    assert sent == []


def test_policy_evaluation_crash_fails_closed():
    class BrokenPolicy:
        def evaluate(self, call):
            raise RuntimeError("policy unavailable")

    response, sent = run_case(
        tool_call("read_file", {"path": "/tmp/report"}), policy_engine=BrokenPolicy()
    )
    assert response["error"]["code"] == StdioMCPProxy.SECURITY_BLOCK_CODE
    assert response["error"]["message"] == "Security: Policy engine failure - failing closed"
    assert sent == []


def test_mixed_batch_with_policy_denial_never_forwards_any_request():
    batch = json.dumps(
        [
            json.loads(tool_call("read_file", {"path": "/tmp/report"})),
            dict(json.loads(tool_call("delete_file", {"path": "/tmp/report"})), id=2),
        ]
    ).encode()
    response, sent = run_case(batch)
    assert isinstance(response, list)
    assert all(r["error"]["code"] == StdioMCPProxy.SECURITY_BLOCK_CODE for r in response)
    assert sent == []


def test_client_claimed_server_id_does_not_grant_access():
    """A request cannot claim an approved server to override the trusted subprocess identity."""
    payload = json.loads(tool_call("read_file", {"path": "/tmp/report"}))
    payload["params"]["server_id"] = "authorized-server"
    response, sent = run_case(
        json.dumps(payload).encode(),
        server_id="unapproved-server",
        policy_engine=PolicyEngine(allowed_servers={"authorized-server"}),
    )
    assert response["error"]["code"] == StdioMCPProxy.SECURITY_BLOCK_CODE
    assert "DENY_SERVER_NOT_ALLOWED" in response["error"]["message"]
    assert sent == []


def test_client_claimed_server_id_does_not_replace_trusted_server():
    """A rogue client field cannot replace the identity bound to the allowed subprocess."""
    payload = json.loads(tool_call("read_file", {"path": "/tmp/report"}))
    payload["params"]["server_id"] = "rogue-server"
    message = json.dumps(payload).encode()
    response, sent = run_case(
        message,
        server_id="authorized-server",
        policy_engine=PolicyEngine(allowed_servers={"authorized-server"}),
    )
    assert response["result"]["ok"] is True
    assert sent == [message + b"\\n"]
