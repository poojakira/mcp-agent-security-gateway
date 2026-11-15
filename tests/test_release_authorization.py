"""Regression checks for the tag-release authorization gate."""

from __future__ import annotations

import runpy
from pathlib import Path

import pytest

_GATE = Path(__file__).resolve().parents[1] / "scripts" / "check_release_authorization.py"
check_release_authorization = runpy.run_path(str(_GATE))["check_release_authorization"]
_SHA = "a" * 40


def _approved() -> dict[str, str]:
    return {
        "GITHUB_REF_TYPE": "tag",
        "GITHUB_REF_NAME": "v0.1.0",
        "GITHUB_SHA": _SHA,
        "MCP_RELEASE_GO": "true",
        "MCP_RELEASE_APPROVED_TAG": "v0.1.0",
        "MCP_RELEASE_APPROVED_SHA": _SHA,
        "MCP_RELEASE_APPROVAL_REFERENCE": "signed-release-review-123",
    }


def test_approved_release_metadata_passes() -> None:
    check_release_authorization(_approved())


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("GITHUB_REF_TYPE", "branch"),
        ("MCP_RELEASE_GO", ""),
        ("MCP_RELEASE_APPROVED_TAG", "v9.9.9"),
        ("MCP_RELEASE_APPROVED_SHA", "b" * 40),
        ("MCP_RELEASE_APPROVAL_REFERENCE", ""),
        ("GITHUB_SHA", "not-a-sha"),
        ("GITHUB_REF_NAME", "v bad"),
    ],
)
def test_release_gate_fails_closed_on_invalid_metadata(field: str, value: str) -> None:
    values = _approved()
    values[field] = value
    with pytest.raises(ValueError, match="Release"):
        check_release_authorization(values)


def test_missing_release_approval_is_denied() -> None:
    values = _approved()
    values.pop("MCP_RELEASE_GO")
    with pytest.raises(ValueError, match="Release denied"):
        check_release_authorization(values)
