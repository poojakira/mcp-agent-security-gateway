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
    # Synthetic complete acceptance exercises the positive gate only.
    check_release_authorization(
        _approved(),
        acceptance={
            "decision": "GO",
            "findings": {
                f"P0-{i:02d}": {
                    "status": "VERIFIED FIXED",
                    "verified_sha": _SHA,
                    "evidence": "synthetic-test-evidence",
                }
                for i in range(1, 20)
            },
        },
    )


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


def test_environment_approval_cannot_override_open_p0_findings():
    with pytest.raises(ValueError, match="P0 acceptance"):
        check_release_authorization(_approved())


@pytest.mark.parametrize("attack", ["missing", "stale", "unverified", "empty-evidence"])
def test_p0_acceptance_rejects_forged_incomplete_records(attack):
    document = {
        "decision": "GO",
        "findings": {
            f"P0-{i:02d}": {
                "status": "VERIFIED FIXED",
                "verified_sha": _SHA,
                "evidence": "synthetic",
            }
            for i in range(1, 20)
        },
    }
    if attack == "missing":
        document["findings"].pop("P0-01")
    else:
        field, value = {
            "stale": ("verified_sha", "b" * 40),
            "unverified": ("status", "PARTIAL"),
            "empty-evidence": ("evidence", ""),
        }[attack]
        document["findings"]["P0-01"][field] = value
    with pytest.raises(ValueError, match="Release denied"):
        check_release_authorization(_approved(), acceptance=document)
