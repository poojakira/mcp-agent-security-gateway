"""Calculate observed incident acknowledgment and containment improvements.

CSV columns: incident_id, cohort (before|after), scenario_id,
occurred_at, acknowledged_at, contained_at, source, synthetic (true|false).
Real-world claims require actual timestamped records; sample fixture results
must never be reported as observed operational outcomes.
"""

from __future__ import annotations

import argparse
import csv
import json
import statistics
from datetime import datetime
from pathlib import Path


def timestamp(value: str) -> datetime:
    ts = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if ts.tzinfo is None or ts.utcoffset() is None:
        raise ValueError("Timestamps must contain a UTC offset")
    return ts


def measure(path: Path, *, allow_synthetic: bool = False) -> dict:
    with path.open(encoding="utf-8-sig", newline="") as handle:
        rows = list(csv.DictReader(handle))
    if not rows:
        raise ValueError("No incident records")
    seen = set()
    grouped: dict[str, dict[str, dict]] = {"before": {}, "after": {}}
    for row in rows:
        incident = row["incident_id"].strip()
        cohort = row["cohort"].strip().lower()
        scenario = row["scenario_id"].strip()
        if not incident or not scenario or cohort not in grouped or incident in seen:
            raise ValueError("Missing identifier, invalid cohort, or duplicate incident")
        seen.add(incident)
        synthetic = row["synthetic"].strip().lower() in {"true", "1", "yes"}
        if synthetic and not allow_synthetic:
            raise ValueError("Synthetic data cannot be used for operational claims")
        if not row["source"].strip():
            raise ValueError("Every incident requires a source reference")
        t0 = timestamp(row["occurred_at"])
        ack = timestamp(row["acknowledged_at"])
        end = timestamp(row["contained_at"])
        if not (t0 <= ack <= end):
            raise ValueError("Invalid incident timestamp sequence")
        if scenario in grouped[cohort]:
            raise ValueError("One case per scenario per cohort required")
        grouped[cohort][scenario] = {
            "ack_minutes": (ack - t0).total_seconds() / 60,
            "contain_minutes": (end - t0).total_seconds() / 60,
            "synthetic": synthetic,
        }
    if set(grouped["before"]) != set(grouped["after"]) or not grouped["before"]:
        raise ValueError("Before/after must contain matching scenario IDs")
    result = {"source_file": str(path), "matched_scenarios": len(grouped["before"])}
    for metric in ("ack_minutes", "contain_minutes"):
        before = statistics.median(x[metric] for x in grouped["before"].values())
        after = statistics.median(x[metric] for x in grouped["after"].values())
        if before <= 0:
            raise ValueError("Baseline median must be positive")
        result[metric] = {
            "baseline_median": round(before, 6),
            "after_median": round(after, 6),
            "reduction_percent": round((before - after) / before * 100, 4),
        }
    result["evidence_type"] = (
        "synthetic_demo"
        if any(x["synthetic"] for v in grouped.values() for x in v.values())
        else "timestamped_observational_comparison"
    )
    result["caveat"] = (
        "Matched scenario identifiers do not prove causality; control for severity, staffing and incident complexity."
    )
    return result


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("csv_file", type=Path)
    parser.add_argument("--allow-synthetic", action="store_true")
    args = parser.parse_args()
    print(json.dumps(measure(args.csv_file, allow_synthetic=args.allow_synthetic), indent=2))


if __name__ == "__main__":
    main()
