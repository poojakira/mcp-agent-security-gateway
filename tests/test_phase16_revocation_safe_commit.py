"""Phase 16: cooperative revocation serialized with actual protected MCP file effects.

All files and identity records are disposable, no provider keys or paid services.
This only verifies a single-host cooperating adapter, NOT arbitrary MCP servers.
"""

from __future__ import annotations

import json
import threading
from pathlib import Path

import pytest

from mcp_monitor.protected_repo_server import ProtectedOperationError, ProtectedRepo, main
from mcp_monitor.protocol.revocation_fence import RevocationFence


@pytest.fixture
def protected(tmp_path: Path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "package.json").write_text(
        json.dumps({"name": "fixture", "dependencies": {"safe-package": "1.0.0"}})
    )
    authority = RevocationFence.bootstrap(tmp_path / "authority.sqlite", principal="operator")
    repo = ProtectedRepo(
        workspace,
        {"safe-package": "1.1.0"},
        revocation_fence=authority,
        operator_principal="operator",
    )
    return repo, authority, workspace


def call(repo: ProtectedRepo):
    return repo.update(
        {"package": "safe-package", "version": "1.1.0", "expected_previous": "1.0.0"}
    )


def version(workspace: Path):
    return json.loads((workspace / "package.json").read_text())["dependencies"]["safe-package"]


def test_revocation_before_effect_denies_and_does_not_change_file(protected):
    repo, authority, workspace = protected
    assert authority.revoke(principal="operator") == 1
    with pytest.raises(ProtectedOperationError, match="Revocation authority denied"):
        call(repo)
    assert version(workspace) == "1.0.0"


def test_restart_does_not_restore_revoked_principal(protected):
    repo, authority, workspace = protected
    authority.revoke(principal="operator")
    restarted = RevocationFence(authority._path)
    after_restart = ProtectedRepo(
        workspace,
        {"safe-package": "1.1.0"},
        revocation_fence=restarted,
        operator_principal="operator",
    )
    with pytest.raises(ProtectedOperationError):
        call(after_restart)
    assert version(workspace) == "1.0.0"


def test_revocation_cannot_complete_in_middle_of_protected_commit(protected, monkeypatch):
    repo, authority, workspace = protected
    entered = threading.Event()
    continue_commit = threading.Event()
    revoke_done = threading.Event()
    errors = []
    original = repo._manifest

    def slow_manifest():
        entered.set()
        assert continue_commit.wait(timeout=5)
        return original()

    monkeypatch.setattr(repo, "_manifest", slow_manifest)

    def writer():
        try:
            call(repo)
        except Exception as exc:
            errors.append(exc)

    def revoker():
        try:
            authority.revoke(principal="operator")
        except Exception as exc:
            errors.append(exc)
        finally:
            revoke_done.set()

    writer_thread = threading.Thread(target=writer)
    revoke_thread = threading.Thread(target=revoker)
    writer_thread.start()
    try:
        assert entered.wait(timeout=5)
        revoke_thread.start()
        # Another SQLite writer cannot acknowledge revocation while an effect
        # already holds the transaction lock. Avoid relying on a precise race.
        assert not revoke_done.wait(timeout=0.1)
        continue_commit.set()
        writer_thread.join(timeout=5)
        revoke_thread.join(timeout=5)
        assert not writer_thread.is_alive()
        assert not revoke_thread.is_alive()
        assert errors == []
        assert version(workspace) == "1.1.0"
        assert authority.status(principal="operator") == (False, 1)
    finally:
        continue_commit.set()
        writer_thread.join(timeout=5)
        if revoke_thread.ident is not None:
            revoke_thread.join(timeout=5)


def test_corrupt_or_absent_authority_denies_even_with_approved_manifest(protected):
    repo, authority, workspace = protected
    authority._path.unlink()
    with pytest.raises(ProtectedOperationError, match="Revocation authority denied"):
        call(repo)
    assert version(workspace) == "1.0.0"


def test_unprovisioned_identity_cannot_write(protected):
    _, authority, workspace = protected
    stranger = ProtectedRepo(
        workspace,
        {"safe-package": "1.1.0"},
        revocation_fence=authority,
        operator_principal="unknown",
    )
    with pytest.raises(ProtectedOperationError):
        call(stranger)
    assert version(workspace) == "1.0.0"


def test_protected_repo_rejects_partial_fence_config(protected):
    _, authority, workspace = protected
    with pytest.raises(ValueError):
        ProtectedRepo(workspace, {"safe-package": "1.1.0"}, revocation_fence=authority)


def test_enforced_launch_rejects_missing_authority_even_when_legacy_approval_exists(
    protected, monkeypatch
):
    _, _, workspace = protected
    monkeypatch.setenv("MCP_PROTECTED_REPO_ROOT", str(workspace))
    monkeypatch.setenv("MCP_APPROVED_DEPENDENCY_UPDATES", '{"safe-package":"1.1.0"}')
    monkeypatch.setenv("MCP_REQUIRE_REVOCATION_FENCE", "1")
    monkeypatch.delenv("MCP_REVOCATION_AUTHORITY_DB", raising=False)
    monkeypatch.delenv("MCP_TRUSTED_OPERATOR_PRINCIPAL", raising=False)
    with pytest.raises(SystemExit, match="Invalid protected workspace configuration"):
        main()
    assert version(workspace) == "1.0.0"


def test_enforced_launch_rejects_incomplete_fence_configuration(protected, monkeypatch):
    _, authority, workspace = protected
    monkeypatch.setenv("MCP_PROTECTED_REPO_ROOT", str(workspace))
    monkeypatch.setenv("MCP_APPROVED_DEPENDENCY_UPDATES", '{"safe-package":"1.1.0"}')
    monkeypatch.setenv("MCP_REQUIRE_REVOCATION_FENCE", "1")
    monkeypatch.setenv("MCP_REVOCATION_AUTHORITY_DB", str(authority._path))
    monkeypatch.delenv("MCP_TRUSTED_OPERATOR_PRINCIPAL", raising=False)
    with pytest.raises(SystemExit, match="Invalid protected workspace configuration"):
        main()
    assert version(workspace) == "1.0.0"
