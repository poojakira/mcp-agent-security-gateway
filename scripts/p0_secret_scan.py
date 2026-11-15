"""Redacted high-confidence scan of tracked files and every reachable Git blob.

No context-based placeholder exemption: a nearby comment must not hide a token.
This is a bounded detector, not proof that credentials do not exist.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
from pathlib import Path

PATTERNS = {
    "github": re.compile(rb"(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,})"),
    "aws": re.compile(rb"(?:AKIA|ASIA)[A-Z0-9]{16}"),
    "provider": re.compile(
        rb"(?:sk-[A-Za-z0-9_-]{30,}|xox[baprs]-[A-Za-z0-9-]{20,}|glpat-[A-Za-z0-9_-]{20,}|npm_[A-Za-z0-9]{30,})"
    ),
    "private-key": re.compile(rb"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----[\r\n]"),
}


# Published AWS documentation example, triaged in P0_CI_EVIDENCE.md.
# Exemption binds exact bytes, never a caller-controlled nearby comment.
SYNTHETIC_SHA256 = frozenset(
    {
        "1a5d44a2dca19669d72edf4c4f1c27c4c1ca4b4408fbb17f6ce4ad452d78ddb3",
    }
)


def scan_bytes(data: bytes) -> list[str]:
    return [
        label
        for label, pattern in PATTERNS.items()
        if any(
            hashlib.sha256(m.group()).hexdigest() not in SYNTHETIC_SHA256
            for m in pattern.finditer(data)
        )
    ]


def scan(history: bool = False) -> dict:
    findings = []
    scanned = 0
    if history:
        objects = subprocess.check_output(["git", "rev-list", "--objects", "--all"], text=True)
        with subprocess.Popen(
            ["git", "cat-file", "--batch"], stdin=subprocess.PIPE, stdout=subprocess.PIPE
        ) as proc:
            assert proc.stdin is not None and proc.stdout is not None
            for line in objects.splitlines():
                oid = line.split(" ", 1)[0]
                proc.stdin.write((oid + "\n").encode())
                proc.stdin.flush()
                header = proc.stdout.readline().split()
                if len(header) != 3:
                    raise RuntimeError("Git object read failed")
                data = proc.stdout.read(int(header[2]))
                if proc.stdout.read(1) != b"\n":
                    raise RuntimeError("Git object framing failed")
                if header[1] != b"blob":
                    continue
                scanned += 1
                for label in scan_bytes(data):
                    findings.append({"object": oid, "kind": label})
            proc.stdin.close()
            if proc.wait() != 0:
                raise RuntimeError("Git history scan failed")
    else:
        paths = subprocess.check_output(["git", "ls-files", "-z"]).decode().split("\0")
        for raw in filter(None, paths):
            path = Path(raw)
            if path.is_symlink():
                continue
            data = path.read_bytes()
            scanned += 1
            for label in scan_bytes(data):
                findings.append({"path": raw, "kind": label})
    return {
        "scope": "reachable blobs" if history else "tracked working tree",
        "scanned": scanned,
        "findings": findings,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--history", action="store_true")
    args = parser.parse_args()
    report = scan(args.history)
    print(json.dumps(report, indent=2))
    return bool(report["findings"])


if __name__ == "__main__":
    raise SystemExit(main())
