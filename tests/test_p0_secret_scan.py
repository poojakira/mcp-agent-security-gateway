"""A caller-controlled placeholder comment must never suppress a credential finding."""

import runpy
from pathlib import Path

scan = runpy.run_path(str(Path(__file__).resolve().parents[1] / "scripts/p0_secret_scan.py"))[
    "scan_bytes"
]


def test_placeholder_comment_does_not_hide_token():
    synthetic = b"ghp_" + b"z" * 35
    assert scan(b"# PLACEHOLDER REDACTED EXAMPLE\n" + synthetic) == ["github"]


def test_nonsecret_example_text_is_allowed():
    assert scan(b"token is supplied by the operator; do not log it") == []
