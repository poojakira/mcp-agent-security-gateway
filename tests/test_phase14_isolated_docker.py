"""Phase 14 actual isolated Docker MCP effects, never production secrets.

Run only with MCP_PHASE14_DOCKER_IMAGE=<locally built sha256 image ID>.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import re
from pathlib import Path

import pytest

from mcp_monitor.policy.policy_engine import PolicyEngine
from mcp_monitor.proxy.protected_repo_sandbox import ProtectedRepoDockerSandbox
from mcp_monitor.proxy.stdio_proxy import StdioMCPProxy

_IMAGE = os.environ.get("MCP_PHASE14_DOCKER_IMAGE", "")
pytestmark = pytest.mark.skipif(
    not re.fullmatch(r"sha256:[0-9a-f]{64}", _IMAGE),
    reason="Run with locally built, content-addressed Phase 14 Docker image",
)


def _rpc(identity: int, name: str, arguments: dict) -> bytes:
    return json.dumps(
        {
            "jsonrpc": "2.0",
            "id": identity,
            "method": "tools/call",
            "params": {"name": name, "arguments": arguments},
        }
    ).encode()


def _digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


async def _scenario(tmp_path: Path) -> None:
    root = tmp_path / "manifest-only"
    root.mkdir()
    manifest = root / "package.json"
    manifest.write_text('{"dependencies":{"safe-package":"1.0.0"}}\n', encoding="utf-8")
    protected = tmp_path / "security-policy.json"
    protected.write_text('{"allow_remote_shell":false}\n', encoding="utf-8")
    before = _digest(protected)
    sandbox = ProtectedRepoDockerSandbox(
        image=_IMAGE,
        workspace=root,
        approved_updates={"safe-package": "1.1.0"},
        host_uid=os.getuid(),
        host_gid=os.getgid(),
    )
    command = ["python", "-m", "mcp_monitor.protected_repo_server"]
    gateway = StdioMCPProxy(
        command,
        offline_sandbox=sandbox,
        server_id="protected-repo",
        strict_mcp_methods=True,
        policy_engine=PolicyEngine(
            allowed_servers={"protected-repo"},
            allowed_tools={"read_manifest", "update_dependency"},
        ),
    )
    await asyncio.wait_for(gateway.start(), timeout=20.0)
    try:
        for index, (name, arguments) in enumerate(
            [
                ("write_file", {"path": str(protected), "content": "forbidden"}),
                (
                    "update_dependency",
                    {
                        "package": "safe-package",
                        "version": "99.0.0",
                        "expected_previous": "1.0.0",
                    },
                ),
                ("read_file", {"path": str(protected)}),
            ],
            start=1,
        ):
            reply = await asyncio.wait_for(
                gateway.handle_message(_rpc(index, name, arguments)), timeout=12.0
            )
            assert "error" in json.loads(reply), name
            assert _digest(protected) == before
            assert json.loads(manifest.read_text())["dependencies"]["safe-package"] == "1.0.0"

        response = await asyncio.wait_for(
            gateway.handle_message(
                _rpc(
                    10,
                    "update_dependency",
                    {
                        "package": "safe-package",
                        "version": "1.1.0",
                        "expected_previous": "1.0.0",
                    },
                )
            ),
            timeout=12.0,
        )
        assert "result" in json.loads(response), response
        assert json.loads(manifest.read_text())["dependencies"]["safe-package"] == "1.1.0"
        assert _digest(protected) == before
    finally:
        await asyncio.wait_for(gateway.stop(), timeout=20.0)


def test_real_docker_mcp_denies_unapproved_effects(tmp_path: Path) -> None:
    asyncio.run(_scenario(tmp_path))


def test_sandbox_rejects_unapproved_mounts_and_commands(tmp_path: Path) -> None:
    root = tmp_path / "manifest-only"
    root.mkdir()
    (root / "package.json").write_text('{"dependencies":{}}\n', encoding="utf-8")
    sandbox = ProtectedRepoDockerSandbox(
        image=_IMAGE,
        workspace=root,
        approved_updates={"safe-package": "1.1.0"},
        host_uid=os.getuid(),
        host_gid=os.getgid(),
    )
    with pytest.raises(ValueError, match="only runs"):
        sandbox.build_command(["sh", "-c", "echo forbidden"])
    args = sandbox.build_command(["python", "-m", "mcp_monitor.protected_repo_server"])
    assert "--network=none" in args
    assert "--read-only" in args
    assert "--cap-drop=ALL" in args
    assert "--security-opt=no-new-privileges" in args
    assert args.count("--mount") == 1
    assert all(str(tmp_path / "security-policy.json") not in part for part in args)
