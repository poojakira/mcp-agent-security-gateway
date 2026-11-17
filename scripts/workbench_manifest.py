"""Generate out-of-tree CI evidence for the dynamically identified source commit."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from xml.etree import ElementTree


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True)
    parser.add_argument("--job-status", required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    output = Path(args.output).resolve()
    if output == root or root in output.parents:
        raise ValueError("Evidence must be written outside the source checkout")
    output.mkdir(parents=True, exist_ok=True)

    def git(*arguments):
        return subprocess.check_output(["git", *arguments], cwd=root, text=True).strip()

    def checksum(path):
        return hashlib.sha256(path.read_bytes()).hexdigest()

    data = {
        "repository": "poojakira/mcp-agent-security-gateway",
        "source_commit": git("rev-parse", "HEAD"),
        "branch": git("branch", "--show-current"),
        "source_clean": not bool(git("status", "--porcelain")),
        "generated_utc": datetime.now(timezone.utc).isoformat(),
        "python": platform.python_version(),
        "platform": platform.platform(),
        "run_id": os.environ.get("GITHUB_RUN_ID"),
        "job_status": args.job_status,
        "release_decision": "PARTIAL; full master-contract acceptance remains outstanding",
        "workflow": ".github/workflows/local-workbench.yml",
        "direct_tool_pins_sha256": checksum(root / "requirements-workbench-test.txt"),
        "lock_limit": "Direct tools pinned; transitive dependency snapshot is run-specific",
    }
    if (output / "junit.xml").exists():
        suites = list(ElementTree.parse(output / "junit.xml").getroot().iter("testsuite"))
        data["tests"] = {
            key: sum(int(suite.get(key, "0")) for suite in suites)
            for key in ("tests", "failures", "errors", "skipped")
        }
    snapshot = subprocess.check_output([sys.executable, "-m", "pip", "freeze", "--all"], text=True)
    (output / "dependencies.txt").write_text(snapshot, encoding="utf-8")
    data["artifact_sha256"] = {
        str(path.relative_to(output)): checksum(path)
        for path in output.rglob("*")
        if path.is_file() and path.name != "ci-manifest.json"
    }
    (output / "ci-manifest.json").write_text(json.dumps(data, indent=2), encoding="utf-8")


if __name__ == "__main__":
    main()
