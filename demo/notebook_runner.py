"""Run one fixed synthetic fixture from this checkout; no hosted service or credentials."""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

GIT = shutil.which("git")
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src") if (ROOT / "src").is_dir() else str(ROOT))
sys.path.insert(0, str(ROOT / "demo"))
from adapter import SPEC, run  # noqa: E402


def source():
    try:
        if GIT is None:
            raise ValueError("Git unavailable")
        top = (
            subprocess.check_output(
                [GIT, "rev-parse", "--show-toplevel"],
                cwd=ROOT,
                stderr=subprocess.DEVNULL,
                timeout=3,
            )
            .decode()
            .strip()
        )
        if Path(top).resolve() != ROOT:
            raise ValueError("Not this checkout")
        commit = (
            subprocess.check_output([GIT, "rev-parse", "HEAD"], cwd=ROOT, timeout=3)
            .decode()
            .strip()
        )
        status = (
            subprocess.check_output([GIT, "status", "--porcelain"], cwd=ROOT, timeout=3)
            .decode()
            .strip()
        )
        return {"commit": commit, "state": "DIRTY" if status else "CLEAN"}
    except (OSError, subprocess.SubprocessError, ValueError):
        return {"commit": "UNKNOWN", "state": "UNKNOWN"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("scenario", choices=[item["id"] for item in SPEC["scenarios"]])
    args = parser.parse_args()
    started = datetime.now(timezone.utc).isoformat()
    report = {
        "product": SPEC["title"],
        "software_version": SPEC["version"],
        "mode": "GUIDED_SYNTHETIC_ONLY",
        "scenario": args.scenario,
        "source": source(),
        "started_utc": started,
        "evidence": run(args.scenario),
        "finished_utc": datetime.now(timezone.utc).isoformat(),
        "limitations": SPEC["limitations"],
    }
    data = json.dumps(report, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    print(
        json.dumps(
            {
                "report": report,
                "report_sha256": hashlib.sha256(data).hexdigest(),
                "checksum_encoding": (
                    "UTF-8 JSON; sorted keys; compact separators; " "ensure_ascii=true; no NaN"
                ),
            },
            allow_nan=False,
        )
    )


if __name__ == "__main__":
    main()
