"""Fail-closed, operator-controlled tag release authorization check.

This protects against accidental release tags, not against a compromised repo
administrator. Configure required reviewers on the GitHub release environment.
"""

from __future__ import annotations

import json
import os
import re
from collections.abc import Mapping
from pathlib import Path


def check_p0_acceptance(document: object, sha: str) -> None:
    if not isinstance(document, dict) or document.get("decision") != "GO":
        raise ValueError("Release denied: P0 acceptance remains NO-GO")
    findings = document.get("findings")
    expected = {f"P0-{index:02d}" for index in range(1, 20)}
    if not isinstance(findings, dict) or set(findings) != expected:
        raise ValueError("Release denied: complete P0 register required")
    for item in findings.values():
        if (
            not isinstance(item, dict)
            or item.get("status") != "VERIFIED FIXED"
            or item.get("verified_sha") != sha
            or not isinstance(item.get("evidence"), str)
            or not item["evidence"].strip()
        ):
            raise ValueError("Release denied: unverified P0 acceptance")


def check_release_authorization(env: Mapping[str, str], *, acceptance: object = None) -> None:
    if env.get("GITHUB_REF_TYPE") != "tag":
        raise ValueError("Release must run on an explicit tag")
    if env.get("MCP_RELEASE_GO") != "true":
        raise ValueError("Release denied: MCP_RELEASE_GO is not true")

    tag = env.get("GITHUB_REF_NAME", "")
    sha = env.get("GITHUB_SHA", "")
    if not re.fullmatch(r"v[A-Za-z0-9][A-Za-z0-9._-]*", tag):
        raise ValueError("Release denied: invalid tag")
    if not re.fullmatch(r"[0-9a-f]{40}", sha):
        raise ValueError("Release denied: invalid source commit SHA")
    if env.get("MCP_RELEASE_APPROVED_TAG") != tag:
        raise ValueError("Release denied: approved tag differs from current tag")
    if env.get("MCP_RELEASE_APPROVED_SHA") != sha:
        raise ValueError("Release denied: approved SHA differs from current source")
    if not env.get("MCP_RELEASE_APPROVAL_REFERENCE", "").strip():
        raise ValueError("Release denied: accountable approval reference required")
    if acceptance is None:
        try:
            path = Path(__file__).resolve().parents[1] / "docs/security/P0_ACCEPTANCE.json"
            acceptance = json.loads(path.read_text())
        except (OSError, ValueError) as exc:
            raise ValueError("Release denied: P0 acceptance unavailable") from exc
    check_p0_acceptance(acceptance, sha)


if __name__ == "__main__":
    try:
        check_release_authorization(os.environ)
    except ValueError as exc:
        raise SystemExit(str(exc)) from exc
    print("Tag and SHA-matched authorization present; environment review still required")
