"""Phase 14 harmless bypass matrix against the actual protected repository adapter.

All paths are disposable. No cloud services or API keys are needed.
"""

from __future__ import annotations

import hashlib
import json

import pytest

from mcp_monitor.protected_repo_server import ProtectedRepo, handle


@pytest.fixture
def workspace(tmp_path):
    (tmp_path / "package.json").write_text(
        '{"dependencies":{"safe-package":"1.0.0"}}\n', encoding="utf-8"
    )
    (tmp_path / "security-policy.json").write_text(
        '{"audit":"required","allow_remote_shell":false}\n', encoding="utf-8"
    )
    return tmp_path


def _digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


_APPROVED_UPDATE = {
    "package": "safe-package",
    "version": "1.1.0",
    "expected_previous": "1.0.0",
}


@pytest.mark.parametrize(
    "method,name,arguments",
    [
        ("tools/call", "write_file", {"path": "security-policy.json", "content": "{}"}),
        ("tools/call", "run_command", {"command": "echo harmless"}),
        ("resources/read", None, {"uri": "file:///security-policy.json"}),
        ("prompts/get", None, {"name": "override"}),
        ("tools/call", "update_dependency", {**_APPROVED_UPDATE, "version": "2.0.0"}),
        ("tools/call", "update_dependency", {**_APPROVED_UPDATE, "server_id": "admin"}),
        (
            "tools/call",
            "update_dependency",
            {**_APPROVED_UPDATE, "path": "../security-policy.json"},
        ),
        (
            "tools/call",
            "update_dependency",
            {**_APPROVED_UPDATE, "nested": {"path": "security-policy.json"}},
        ),
        ("tools/call", "update_dependency", {**_APPROVED_UPDATE, "expected_previous": "0.0.0"}),
        ("tools/call", "read_file", {"path": "%2e%2e/security-policy.json"}),
    ],
)
def test_unapproved_operations_leave_independent_state_unchanged(
    workspace, method, name, arguments
):
    repo = ProtectedRepo(workspace, {"safe-package": "1.1.0"})
    protected = workspace / "security-policy.json"
    manifest = workspace / "package.json"
    before = (_digest(protected), _digest(manifest))
    params = {"name": name, "arguments": arguments} if method == "tools/call" else arguments
    result = handle(
        {"jsonrpc": "2.0", "id": 7, "method": method, "params": params},
        repo,
    )
    assert result is not None and "error" in result, result
    assert (_digest(protected), _digest(manifest)) == before


def test_duplicate_json_request_key_is_rejected_by_server_decoder(workspace):
    from mcp_monitor.protected_repo_server import ProtectedOperationError, _load_json

    with pytest.raises(ProtectedOperationError, match="Duplicate JSON key"):
        _load_json('{"jsonrpc":"2.0","id":1,"method":"tools/call","method":"tools/list"}')
    assert json.loads((workspace / "package.json").read_text())["dependencies"] == {
        "safe-package": "1.0.0"
    }


def test_same_operator_approval_cannot_be_extended_by_client_arguments(workspace):
    repo = ProtectedRepo(workspace, {"safe-package": "1.1.0"})
    protected = workspace / "security-policy.json"
    old_digest = _digest(protected)
    result = handle(
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
                    "principal": "system",
                    "role": "admin",
                },
            },
        },
        repo,
    )
    assert "error" in result
    assert _digest(protected) == old_digest
