"""Disposable keyless MCP gateway demo. No paid APIs, tokens, or network.

Run from the repository after installation:
    python scripts/demo_zero_key_mcp.py

Research/development profile ONLY. This does not demonstrate production OIDC,
OS-user containment, or external effect reconciliation.
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
import tempfile
from pathlib import Path

from mcp_monitor.policy.policy_engine import PolicyEngine
from mcp_monitor.proxy.stdio_proxy import StdioMCPProxy


async def run() -> None:
    if os.environ.get("MCP_ENV", "").strip().lower() == "production":
        raise SystemExit("This disposable demo must not run in production mode.")
    with tempfile.TemporaryDirectory(prefix="mcp-keyless-demo-") as directory:
        root = Path(directory)
        manifest = root / "package.json"
        initial = {"name": "offline-demo", "dependencies": {"safe-package": "1.0.0"}}
        manifest.write_text(json.dumps(initial), encoding="utf-8")
        child_env_keys = ("MCP_PROTECTED_REPO_ROOT", "MCP_APPROVED_DEPENDENCY_UPDATES")
        old_env = {key: os.environ.get(key) for key in child_env_keys}
        os.environ["MCP_PROTECTED_REPO_ROOT"] = str(root)
        os.environ["MCP_APPROVED_DEPENDENCY_UPDATES"] = json.dumps(
            {"safe-package": "1.1.0"}
        )
        proxy = StdioMCPProxy(
            [sys.executable, "-m", "mcp_monitor.protected_repo_server"],
            server_id="protected-repo",
            strict_mcp_methods=True,
            policy_engine=PolicyEngine(
                allowed_servers={"protected-repo"},
                allowed_tools={"read_manifest"},
            ),
        )
        def call(request_id: int, tool: str, arguments: dict) -> bytes:
            return json.dumps(
                {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "method": "tools/call",
                    "params": {"name": tool, "arguments": arguments},
                }
            ).encode("utf-8")

        try:
            await proxy.start()
            allowed = json.loads(await proxy.handle_message(call(1, "read_manifest", {})))
            denied = json.loads(
                await proxy.handle_message(
                    call(
                        2,
                        "update_dependency",
                        {
                            "package": "safe-package",
                            "version": "1.1.0",
                            "expected_previous": "1.0.0",
                        },
                    )
                )
            )
        finally:
            await proxy.stop()
            for key, value in old_env.items():
                if value is None:
                    os.environ.pop(key, None)
                else:
                    os.environ[key] = value

        assert "result" in allowed, allowed
        assert "error" in denied, denied
        assert json.loads(manifest.read_text(encoding="utf-8")) == initial
        print("AUTHORIZED read_manifest: ALLOWED through live stdio MCP server")
        print("UNAUTHORIZED update_dependency: BLOCKED by gateway policy")
        print("INDEPENDENT FILE CHECK: package.json remained unchanged")
        print("NETWORK: none required; API KEYS: none; PAID SERVICES: none")
        print("PROFILE: disposable development demo, not production certification")


if __name__ == "__main__":
    asyncio.run(run())
