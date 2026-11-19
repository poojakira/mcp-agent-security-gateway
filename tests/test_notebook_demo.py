"""Actual guided fixtures and isolated runner, not a mock backend."""

import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from demo.adapter import SPEC, run  # noqa: E402


@pytest.mark.parametrize("scenario", [item["id"] for item in SPEC["scenarios"]])
def test_canonical_guided_fixture(scenario):
    value = run(scenario)
    assert value["summary"]
    r = value["engine_report"]
    if scenario == "deny":
        assert r["outcome"] == "NOT_INVOKED" and not r["tool_state"]["receipts"]
    else:
        assert r["outcome"] == "CONFIRMED_SUCCEEDED" and r["tool_state"]["receipts"]
    if scenario == "allow":
        assert r["tool_state"]["note"] == "Synthetic notebook demo note"


def test_unknown_fixture_rejected():
    with pytest.raises(ValueError):
        run("arbitrary-user-input")


def test_isolated_runner_uses_own_source(tmp_path):
    result = subprocess.run(
        [
            sys.executable,
            "-I",
            str(ROOT / "demo" / "notebook_runner.py"),
            SPEC["scenarios"][0]["id"],
        ],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        check=True,
        timeout=60,
    )
    value = json.loads(result.stdout)
    assert value["report"]["mode"] == "GUIDED_SYNTHETIC_ONLY"
    git = shutil.which("git")
    expected = None
    if git is not None:
        probe = subprocess.run(
            [git, "rev-parse", "--show-toplevel", "HEAD"],
            cwd=ROOT,
            text=True,
            capture_output=True,
        )
        lines = probe.stdout.splitlines()
        if probe.returncode == 0 and len(lines) == 2 and Path(lines[0]).resolve() == ROOT:
            expected = lines[1]
    if expected is None:
        # Builder/wheel contexts deliberately omit Git metadata; inventing a SHA is forbidden.
        assert value["report"]["source"] == {"commit": "UNKNOWN", "state": "UNKNOWN"}
    else:
        assert value["report"]["source"]["commit"] == expected
    assert len(value["report_sha256"]) == 64
