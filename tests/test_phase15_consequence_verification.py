"""Phase 15 independent effect tests using disposable files and a real MCP process.

The observer reads filesystem state, not the MCP result. No keys or paid APIs.
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

from mcp_monitor.protocol.consequence_verifier import (
    Consequence,
    ManifestConsequenceVerifier,
    capture_manifest,
)
from mcp_monitor.protocol.effect_journal import DurableEffectJournal, EffectJournalError
from mcp_monitor.proxy.stdio_proxy import SubprocessTransport


@pytest.fixture
def workspace(tmp_path: Path) -> Path:
    root = tmp_path / "authorized"
    root.mkdir()
    (root / "package.json").write_text(
        '{"name":"harmless-fixture","dependencies":{"safe-package":"1.0.0","other":"3.0.0"}}\n',
        encoding="utf-8",
    )
    return root


def _observer(root: Path) -> ManifestConsequenceVerifier:
    return ManifestConsequenceVerifier(
        root,
        capture_manifest(root),
        package="safe-package",
        expected_previous="1.0.0",
        approved_version="1.1.0",
    )


def _approved_call() -> bytes:
    return json.dumps(
        {
            "jsonrpc": "2.0",
            "id": 9,
            "method": "tools/call",
            "params": {
                "name": "update_dependency",
                "arguments": {
                    "package": "safe-package",
                    "version": "1.1.0",
                    "expected_previous": "1.0.0",
                },
            },
        }
    ).encode()


def test_no_operation_independently_reports_no_effect(workspace: Path) -> None:
    assert _observer(workspace).inspect().state is Consequence.VERIFIED_NO_EFFECT


def test_only_exact_approved_state_is_verified(workspace: Path) -> None:
    observer = _observer(workspace)
    manifest = workspace / "package.json"
    data = json.loads(manifest.read_text())
    data["dependencies"]["safe-package"] = "1.1.0"
    manifest.write_text(json.dumps(data), encoding="utf-8")
    assert observer.inspect().state is Consequence.VERIFIED_EFFECT


def test_unrelated_change_detected_even_if_approved_effect_present(workspace: Path) -> None:
    observer = _observer(workspace)
    manifest = workspace / "package.json"
    data = json.loads(manifest.read_text())
    data["dependencies"]["safe-package"] = "1.1.0"
    data["dependencies"]["other"] = "999.0.0"
    manifest.write_text(json.dumps(data), encoding="utf-8")
    assert observer.inspect().state is Consequence.UNEXPECTED_EFFECT


def test_duplicate_json_after_effect_is_not_accepted(workspace: Path) -> None:
    observer = _observer(workspace)
    (workspace / "package.json").write_text(
        '{"dependencies":{"safe-package":"1.1.0","safe-package":"1.0.0"}}',
        encoding="utf-8",
    )
    assert observer.inspect().state is Consequence.INDETERMINATE


def test_unavailable_file_is_indeterminate_not_no_effect(workspace: Path) -> None:
    observer = _observer(workspace)
    (workspace / "package.json").unlink()
    assert observer.inspect().state is Consequence.INDETERMINATE


def test_replaced_manifest_symlink_is_indeterminate(workspace: Path, tmp_path: Path) -> None:
    observer = _observer(workspace)
    target = tmp_path / "outside.json"
    target.write_text('{"dependencies":{"safe-package":"1.1.0"}}', encoding="utf-8")
    (workspace / "package.json").unlink()
    (workspace / "package.json").symlink_to(target)
    assert observer.inspect().state is Consequence.INDETERMINATE


def test_snapshot_rejects_untrusted_preflight_version(workspace: Path) -> None:
    with pytest.raises(ValueError, match="preflight"):
        ManifestConsequenceVerifier(
            workspace,
            capture_manifest(workspace),
            package="safe-package",
            expected_previous="0.0.0",
            approved_version="1.1.0",
        )


async def _lost_ack_scenario(workspace: Path, tmp_path: Path) -> None:
    """Execute through real MCP stdio, discard ACK, then check independent effect."""
    journal_path = tmp_path / "effects.sqlite"
    journal = DurableEffectJournal.bootstrap(journal_path)
    arguments = {
        "package": "safe-package",
        "version": "1.1.0",
        "expected_previous": "1.0.0",
    }
    identity = {
        "principal": "operator-test",
        "server": "protected-repo",
        "tool": "update_dependency",
        "operation_key": "bounded-effect-1",
    }
    journal.reserve(**identity, arguments=arguments)
    observer = _observer(workspace)
    assert observer.inspect().state is Consequence.VERIFIED_NO_EFFECT

    command = [sys.executable, "-m", "mcp_monitor.protected_repo_server"]
    settings = {
        "MCP_PROTECTED_REPO_ROOT": str(workspace),
        "MCP_APPROVED_DEPENDENCY_UPDATES": json.dumps({"safe-package": "1.1.0"}),
    }
    with patch.dict(os.environ, settings):
        transport = SubprocessTransport(command)
        await transport.start()
        try:
            await transport.send(_approved_call() + b"\n")
            # Deliberately read then discard the complete server acknowledgment,
            # simulating a lost gateway-to-client acknowledgement.
            _ = await asyncio.wait_for(transport.receive(), timeout=10)
        finally:
            await transport.stop()

    independent = observer.inspect()
    assert independent.state is Consequence.VERIFIED_EFFECT
    assert journal.status(**identity) == "UNCERTAIN"
    restarted = DurableEffectJournal(journal_path)
    assert restarted.status(**identity) == "UNCERTAIN"
    with pytest.raises(EffectJournalError, match="Duplicate or unresolved"):
        restarted.reserve(**identity, arguments=arguments)
    # No automatic retry or misleading "COMPLETED" write after lost ACK.
    assert (
        json.loads((workspace / "package.json").read_text())["dependencies"]["safe-package"]
        == "1.1.0"
    )


def test_real_mcp_lost_ack_does_not_falsify_consequence_or_retry(
    workspace: Path, tmp_path: Path
) -> None:
    asyncio.run(_lost_ack_scenario(workspace, tmp_path))
