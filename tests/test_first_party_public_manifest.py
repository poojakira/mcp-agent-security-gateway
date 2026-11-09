"""Real public MCP repository dependency manifest, tested in a disposable copy.

Source: modelcontextprotocol/servers, pinned commit
36380287ed3b15d115b55f546617d723072b1296, package.json blob
34557784d197891ed31204127a76fde5eee240da.

The workflow downloads and verifies this public source before setting the
test fixture path. No real upstream repository is modified. This is authentic
open-source dependency data, NOT a collected malicious attack dataset.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import shutil
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

from mcp_monitor.proxy.stdio_proxy import StdioMCPProxy

PACKAGE = "@modelcontextprotocol/server-filesystem"
NEW_VERSION = "2.0.1"


async def _public_manifest_test(root: Path) -> None:
    manifest = root / "package.json"
    original = json.loads(manifest.read_text(encoding="utf-8"))
    old = original["dependencies"][PACKAGE]
    protected = root / "security-policy.json"
    protected_hash = hashlib.sha256(protected.read_bytes()).hexdigest()
    command = [sys.executable, "-m", "mcp_monitor.protected_repo_server"]
    with patch.dict(
        os.environ,
        {
            "MCP_PROTECTED_REPO_ROOT": str(root),
            "MCP_APPROVED_DEPENDENCY_UPDATES": json.dumps({PACKAGE: NEW_VERSION}),
        },
    ):
        gateway = StdioMCPProxy(command, server_id="protected-repo")
        await gateway.start()
        try:
            request = {
                "jsonrpc": "2.0",
                "id": 10,
                "method": "tools/call",
                "params": {
                    "name": "update_dependency",
                    "arguments": {
                        "package": PACKAGE,
                        "version": NEW_VERSION,
                        "expected_previous": old,
                    },
                },
            }
            response = json.loads(
                await asyncio.wait_for(
                    gateway.handle_message(json.dumps(request).encode()), timeout=15
                )
            )
            assert "result" in response, response
            updated = json.loads(manifest.read_text(encoding="utf-8"))
            assert updated["dependencies"][PACKAGE] == NEW_VERSION
            original["dependencies"][PACKAGE] = NEW_VERSION
            assert updated == original
            assert hashlib.sha256(protected.read_bytes()).hexdigest() == protected_hash
            print(
                "PINNED PUBLIC MCP MANIFEST: approved dependency actually updated; "
                "all unrelated original fields preserved; security configuration unchanged",
                flush=True,
            )
        finally:
            await gateway.stop()


@pytest.mark.skipif(
    not os.environ.get("MCP_PUBLIC_MANIFEST_PATH"),
    reason="Download and verify pinned public manifest before running",
)
def test_genuine_public_mcp_manifest_through_first_party_gateway(tmp_path):
    source = Path(os.environ["MCP_PUBLIC_MANIFEST_PATH"])
    data = json.loads(source.read_text(encoding="utf-8"))
    assert data["name"] == "@modelcontextprotocol/servers"
    assert data["dependencies"][PACKAGE] == "*"
    shutil.copyfile(source, tmp_path / "package.json")
    (tmp_path / "security-policy.json").write_text('{"audit":"required"}\n', encoding="utf-8")
    asyncio.run(_public_manifest_test(tmp_path))
