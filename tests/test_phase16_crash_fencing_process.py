"""Crash-after-reservation fault injection using a disposable child process.

Actual process termination is tested. Physical power loss, multi-host commits,
filesystem guarantees and external providers are explicitly out of scope.
No API keys, external network, or paid infrastructure are used.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from mcp_monitor.protocol.effect_journal import DurableEffectJournal, EffectJournalError

PRINCIPAL = "lab:operator"
SERVER = "local"
TOOL = "update_dependency"
KEY = "crash-fixture-01"
ARGUMENTS = {"package": "safe-package", "version": "1.1.0", "expected_previous": "1.0.0"}


@pytest.mark.parametrize("apply_effect", [False, True])
def test_process_kill_after_journal_reserve_keeps_uncertain_outcome(
    tmp_path: Path, apply_effect: bool
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    manifest = workspace / "package.json"
    manifest.write_text('{"dependencies":{"safe-package":"1.0.0"}}\n', encoding="utf-8")
    db_path = tmp_path / "effects.sqlite3"

    child_code = """
import json
import os
import sys
from pathlib import Path
from mcp_monitor.protocol.effect_journal import DurableEffectJournal
from mcp_monitor.protected_repo_server import ProtectedRepo

workspace = Path(sys.argv[1])
db_path = Path(sys.argv[2])
apply_effect = sys.argv[3] == "true"
arguments = {
    "package": "safe-package",
    "version": "1.1.0",
    "expected_previous": "1.0.0",
}
journal = DurableEffectJournal.bootstrap(db_path)
journal.reserve(
    principal="lab:operator",
    server="local",
    tool="update_dependency",
    operation_key="crash-fixture-01",
    arguments=arguments,
)
if apply_effect:
    repo = ProtectedRepo(workspace, {"safe-package": "1.1.0"})
    repo.update(arguments)
os._exit(83)
"""
    result = subprocess.run(
        [sys.executable, "-c", child_code, str(workspace), str(db_path), str(apply_effect).lower()],
        capture_output=True,
        text=True,
        check=False,
        timeout=20,
    )
    assert result.returncode == 83, result.stderr
    journal = DurableEffectJournal(db_path)
    assert (
        journal.status(principal=PRINCIPAL, server=SERVER, tool=TOOL, operation_key=KEY)
        == "UNCERTAIN"
    )
    actual = json.loads(manifest.read_text(encoding="utf-8"))["dependencies"]["safe-package"]
    assert actual == ("1.1.0" if apply_effect else "1.0.0")
    # The caller must reconcile the independent effect, not auto-replay
    # simply because the original child died without acknowledging.
    with pytest.raises(EffectJournalError, match="Duplicate or unresolved"):
        journal.reserve(
            principal=PRINCIPAL,
            server=SERVER,
            tool=TOOL,
            operation_key=KEY,
            arguments=ARGUMENTS,
        )
    assert (
        json.loads(manifest.read_text(encoding="utf-8"))["dependencies"]["safe-package"]
        == actual
    )


def test_process_kill_before_journal_reservation_has_no_effect(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    manifest = workspace / "package.json"
    manifest.write_text('{"dependencies":{"safe-package":"1.0.0"}}\n', encoding="utf-8")
    db_path = tmp_path / "effects.sqlite3"
    DurableEffectJournal.bootstrap(db_path)

    child = subprocess.run(
        [sys.executable, "-c", "import os; os._exit(84)"],
        capture_output=True,
        check=False,
        timeout=20,
    )
    assert child.returncode == 84
    journal = DurableEffectJournal(db_path)
    assert journal.status(principal=PRINCIPAL, server=SERVER, tool=TOOL, operation_key=KEY) is None
    assert json.loads(manifest.read_text(encoding="utf-8"))["dependencies"] == {
        "safe-package": "1.0.0"
    }
