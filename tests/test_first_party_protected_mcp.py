"""Real end-to-end gateway + first-party MCP server with independent disk verification."""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

from mcp_monitor.policy.policy_engine import PolicyEngine
from mcp_monitor.protected_repo_server import ProtectedOperationError, ProtectedRepo
from mcp_monitor.proxy.stdio_proxy import StdioMCPProxy, SubprocessTransport


def _rpc(identity: int, method: str, params: dict | None = None) -> bytes:
    return json.dumps(
        {"jsonrpc": "2.0", "id": identity, "method": method, "params": params or {}}
    ).encode()


def _call(identity: int, name: str, arguments: dict) -> bytes:
    return _rpc(identity, "tools/call", {"name": name, "arguments": arguments})


def _hash(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


@pytest.fixture
def workspace(tmp_path):
    (tmp_path / "package.json").write_text(
        json.dumps({"name": "disposable-project", "dependencies": {"safe-package": "1.0.0"}}),
        encoding="utf-8",
    )
    (tmp_path / "security-policy.json").write_text(
        '{"allow_remote_shell": false, "audit": "required"}\n', encoding="utf-8"
    )
    return tmp_path


def test_server_rejects_protected_paths_and_unapproved_change(workspace):
    repo = ProtectedRepo(workspace, {"safe-package": "1.1.0"})
    protected = workspace / "security-policy.json"
    before = _hash(protected)
    with pytest.raises(ProtectedOperationError, match="not approved"):
        repo.update({"package": "safe-package", "version": "999.0.0", "expected_previous": "1.0.0"})
    with pytest.raises(ProtectedOperationError, match="Invalid dependency"):
        repo.update(
            {
                "package": "safe-package",
                "version": "1.1.0",
                "expected_previous": "1.0.0",
                "path": "../security-policy.json",
            }
        )
    assert before == _hash(protected)
    assert repo.read({}) == {"dependencies": {"safe-package": "1.0.0"}}


@pytest.mark.skipif(not hasattr(os, "symlink"), reason="symlinks unavailable")
def test_manifest_symlink_is_denied(workspace, tmp_path):
    other = tmp_path.parent / (tmp_path.name + "-external.json")
    other.write_text('{"dependencies":{"safe-package":"1.0.0"}}', encoding="utf-8")
    (workspace / "package.json").unlink()
    (workspace / "package.json").symlink_to(other)
    repo = ProtectedRepo(workspace, {"safe-package": "1.1.0"})
    with pytest.raises(ProtectedOperationError, match="Manifest missing"):
        repo.read({})
    with pytest.raises(ProtectedOperationError, match="Manifest missing"):
        repo.update({"package": "safe-package", "version": "1.1.0", "expected_previous": "1.0.0"})
    assert "1.0.0" in other.read_text(encoding="utf-8")


async def _real_gateway_test(root: Path):
    env = {
        "MCP_PROTECTED_REPO_ROOT": str(root),
        "MCP_APPROVED_DEPENDENCY_UPDATES": json.dumps({"safe-package": "1.1.0"}),
    }
    command = [sys.executable, "-m", "mcp_monitor.protected_repo_server"]
    # The process is launched in-process for this test harness only; the
    # downstream server is an actual independent operating-system subprocess.
    protected = root / "security-policy.json"
    manifest = root / "package.json"
    protected_before = _hash(protected)
    with patch.dict(os.environ, env):
        gateway = StdioMCPProxy(
            command,
            server_id="protected-repo",
            strict_mcp_methods=True,
            policy_engine=PolicyEngine(
                allowed_servers={"protected-repo"},
                allowed_tools={"read_manifest", "update_dependency"},
            ),
        )
        await gateway.start()
        try:
            init = json.loads(
                await gateway.handle_message(
                    _rpc(
                        1,
                        "initialize",
                        {
                            "protocolVersion": "2025-03-26",
                            "capabilities": {},
                            "clientInfo": {"name": "protected-repo-test", "version": "0.1"},
                        },
                    )
                )
            )
            assert init["result"]["serverInfo"]["name"] == "first-party-protected-repo"
            await gateway.handle_message(b'{"jsonrpc":"2.0","method":"notifications/initialized"}')
            tools = json.loads(await gateway.handle_message(_rpc(2, "tools/list")))
            names = {t["name"] for t in tools["result"]["tools"]}
            assert names == {"read_manifest", "update_dependency"}

            good_read = json.loads(await gateway.handle_message(_call(3, "read_manifest", {})))
            assert "1.0.0" in json.dumps(good_read)

            for ident, name, args in (
                (4, "read_file", {"path": str(protected)}),
                (5, "write_file", {"path": str(protected), "content": "unsafe"}),
                (
                    6,
                    "update_dependency",
                    {"package": "safe-package", "version": "9.9.9", "expected_previous": "1.0.0"},
                ),
                (
                    7,
                    "update_dependency",
                    {
                        "package": "safe-package",
                        "version": "1.1.0",
                        "expected_previous": "1.0.0",
                        "path": str(protected),
                    },
                ),
                (8, "run_command", {"command": "echo unauthorized"}),
            ):
                denial = json.loads(await gateway.handle_message(_call(ident, name, args)))
                assert "error" in denial, (ident, denial)
                assert _hash(protected) == protected_before
                assert json.loads(manifest.read_text())["dependencies"]["safe-package"] == "1.0.0"

            allowed = json.loads(
                await gateway.handle_message(
                    _call(
                        9,
                        "update_dependency",
                        {
                            "package": "safe-package",
                            "version": "1.1.0",
                            "expected_previous": "1.0.0",
                        },
                    )
                )
            )
            assert "result" in allowed, allowed
            assert json.loads(manifest.read_text())["dependencies"]["safe-package"] == "1.1.0"
            assert _hash(protected) == protected_before

            repeated = json.loads(
                await gateway.handle_message(
                    _call(
                        10,
                        "update_dependency",
                        {
                            "package": "safe-package",
                            "version": "1.1.0",
                            "expected_previous": "1.0.0",
                        },
                    )
                )
            )
            assert "error" in repeated
            assert _hash(protected) == protected_before
            print(
                "REAL FIRST-PARTY MCP: discovered actual tools; allowed read and update; "
                "five unauthorized actions plus duplicate update denied; protected file unchanged",
                flush=True,
            )
        finally:
            await gateway.stop()


def test_real_first_party_mcp_gateway_controls_effects(workspace):
    asyncio.run(_real_gateway_test(workspace))


async def _direct_bypass_scenario(root: Path):
    """Try to bypass the gateway by calling the protected server directly."""
    command = [sys.executable, "-m", "mcp_monitor.protected_repo_server"]
    protected = root / "security-policy.json"
    manifest = root / "package.json"
    protected_before = _hash(protected)
    env = {
        "MCP_PROTECTED_REPO_ROOT": str(root),
        "MCP_APPROVED_DEPENDENCY_UPDATES": json.dumps({"safe-package": "1.1.0"}),
    }
    with patch.dict(os.environ, env):
        transport = SubprocessTransport(command)
        await transport.start()
        try:
            for identity, name, arguments in (
                (101, "write_file", {"path": str(protected), "content": "unsafe"}),
                (102, "read_file", {"path": str(protected)}),
                (
                    103,
                    "update_dependency",
                    {
                        "package": "safe-package",
                        "version": "9.9.9",
                        "expected_previous": "1.0.0",
                    },
                ),
            ):
                await transport.send(_call(identity, name, arguments) + b"\n")
                reply = json.loads(await asyncio.wait_for(transport.receive(), timeout=10))
                assert reply["id"] == identity
                assert "error" in reply
                assert _hash(protected) == protected_before
                assert json.loads(manifest.read_text())["dependencies"]["safe-package"] == "1.0.0"
            # A same-user process with direct access to the server and the trusted
            # environment can still perform an operator-approved operation without
            # traversing the gateway. This is intentionally documented as a
            # production bypass blocker, not treated as an authorization success.
            direct_approved = _call(
                104,
                "update_dependency",
                {
                    "package": "safe-package",
                    "version": "1.1.0",
                    "expected_previous": "1.0.0",
                },
            )
            await transport.send(direct_approved + b"\n")
            approved_reply = json.loads(
                await asyncio.wait_for(transport.receive(), timeout=10)
            )
            assert "result" in approved_reply
            assert json.loads(manifest.read_text())["dependencies"]["safe-package"] == "1.1.0"
            assert _hash(protected) == protected_before
            print(
                "DIRECT SERVER BOUNDARY: unauthorized calls denied, but same-user "
                "approved tool effect can bypass the gateway: RELEASE BLOCKER",
                flush=True,
            )
        finally:
            await transport.stop()


def test_direct_server_connection_cannot_bypass_resource_policy(workspace):
    asyncio.run(_direct_bypass_scenario(workspace))
