"""Evidence boundaries for observed incident-response measurements."""

from __future__ import annotations

import csv
import importlib.util
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

_path = Path(__file__).resolve().parents[1] / "scripts" / "measure_incident_response.py"
_spec = importlib.util.spec_from_file_location("measure_incident_response", _path)
assert _spec is not None and _spec.loader is not None
_module = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_module)
measure = _module.measure


def fixture(tmp_path, *, synthetic=False):
    path = tmp_path / "incidents.csv"
    start = datetime(2026, 10, 1, tzinfo=timezone.utc)
    rows = []
    for scenario in ("a", "b", "c"):
        for cohort, ack, contained in (("before", 10, 40), ("after", 5, 20)):
            rows.append(
                {
                    "incident_id": f"{scenario}-{cohort}",
                    "cohort": cohort,
                    "scenario_id": scenario,
                    "occurred_at": start.isoformat(),
                    "acknowledged_at": (start + timedelta(minutes=ack)).isoformat(),
                    "contained_at": (start + timedelta(minutes=contained)).isoformat(),
                    "source": "synthetic-fixture" if synthetic else "audit-record-ref",
                    "synthetic": str(synthetic).lower(),
                }
            )
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    return path


def test_matched_timestamped_comparison(tmp_path):
    report = measure(fixture(tmp_path))
    assert report["matched_scenarios"] == 3
    assert report["ack_minutes"]["reduction_percent"] == 50
    assert report["contain_minutes"]["reduction_percent"] == 50


def test_synthetic_rejected_for_operational_claims(tmp_path):
    with pytest.raises(ValueError, match="Synthetic"):
        measure(fixture(tmp_path, synthetic=True))
    report = measure(fixture(tmp_path, synthetic=True), allow_synthetic=True)
    assert report["evidence_type"] == "synthetic_demo"


def test_unpaired_scenarios_rejected(tmp_path):
    p = fixture(tmp_path)
    data = p.read_text().splitlines()
    p.write_text("\n".join(data[:-1]) + "\n")
    with pytest.raises(ValueError, match="matching scenario"):
        measure(p)
