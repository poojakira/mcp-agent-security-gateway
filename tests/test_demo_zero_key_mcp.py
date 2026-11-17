"""Keyless demo smoke test (real stdio child, disposable workspace)."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path


def test_keyless_gateway_demo_blocks_write_and_preserves_manifest():
    root = Path(__file__).resolve().parents[1]
    environment = os.environ.copy()
    environment["MCP_ENV"] = "development"
    environment.pop("MCP_REVOCATION_AUTHORITY_DB", None)
    environment.pop("MCP_TRUSTED_OPERATOR_PRINCIPAL", None)
    environment.pop("MCP_REQUIRE_REVOCATION_FENCE", None)
    run = subprocess.run(
        [sys.executable, str(root / "scripts" / "demo_zero_key_mcp.py")],
        cwd=root,
        env=environment,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=25,
        check=False,
    )
    assert run.returncode == 0, run.stderr[-1500:]
    assert "AUTHORIZED read_manifest: ALLOWED" in run.stdout
    assert "UNAUTHORIZED update_dependency: BLOCKED" in run.stdout
    assert "package.json remained unchanged" in run.stdout
