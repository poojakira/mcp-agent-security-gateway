"""Read-only parity gate for tracked, deterministically rendered PDF and PNG."""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

GIT = shutil.which("git")


def verify(root: Path) -> bool:
    if GIT is None:
        return False
    paths = ["poster/poster.png", "poster/poster_36x48.pdf"]
    manifest = json.loads((root / "poster/verified_claims.json").read_text())
    if manifest["repository"] == "mcp-agent-security-gateway":
        paths.append("MCP_Gateway_Poster.pdf")
    for path in paths:
        if not (root / path).is_file():
            return False
        tracked = subprocess.run(  # noqa: S603 - resolved git with fixed read-only commands
            [GIT, "ls-files", "--error-unmatch", "--", path],
            cwd=root,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
        if tracked.returncode:
            return False
    result = subprocess.run(  # noqa: S603 - resolved git with fixed artifact paths
        [GIT, "diff", "--exit-code", "--", *paths],
        cwd=root,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    return result.returncode == 0


if __name__ == "__main__":
    root = Path(__file__).resolve().parents[1]
    if not verify(root):
        raise SystemExit(
            "Rendered PDF/PNG differs from tracked artifacts; "
            "regenerate and review both before committing."
        )
    print("Tracked PDF/PNG artifact parity passed")
