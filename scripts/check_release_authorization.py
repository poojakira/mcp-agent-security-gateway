"""Fail-closed, operator-controlled tag release authorization check.

This protects against accidental release tags, not against a compromised repo
administrator. Configure required reviewers on the GitHub release environment.
"""

from __future__ import annotations

import os
import re
from collections.abc import Mapping


def check_release_authorization(env: Mapping[str, str]) -> None:
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


if __name__ == "__main__":
    try:
        check_release_authorization(os.environ)
    except ValueError as exc:
        raise SystemExit(str(exc)) from exc
    print("Tag and SHA-matched authorization present; environment review still required")
