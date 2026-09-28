"""Tests for the detection-engineering lifecycle utilities.

Covers the coverage matrix generator, the precision/recall harness over the
synthetic labeled fixtures, and the latency microbenchmark.

Note: the datasets exercised here are explicitly SYNTHETIC FIXTURES, not
real-world traffic. These tests validate that the lifecycle tooling *runs* and
produces well-formed, finite metrics — not that the rules are effective in
production.
"""

from __future__ import annotations

import json
import math
from pathlib import Path

from mcp_monitor.siem.correlation import BUILTIN_RULES
from mcp_monitor.siem.lifecycle import (
    build_coverage_matrix,
    build_synthetic_dataset,
    coverage_matrix_to_markdown,
    latency_bench_to_markdown,
    precision_recall_to_markdown,
    run_latency_bench,
    run_precision_recall,
    write_artifacts,
)


class TestCoverageMatrix:
    def test_matrix_generates(self):
        matrix = build_coverage_matrix()
        assert "entries" in matrix
        assert matrix["_meta"]["correlation_rule_count"] == len(BUILTIN_RULES)
        # Elastic file has multiple committed rules.
        assert matrix["_meta"]["elastic_rule_count"] >= 1

    def test_every_correlation_rule_maps_to_a_technique(self):
        """Each COR-xxx rule must map to a MITRE technique id."""
        matrix = build_coverage_matrix()
        corr = [e for e in matrix["entries"] if e["source"] == "correlation"]
        assert len(corr) == len(BUILTIN_RULES)
        for e in corr:
            assert e["technique_id"], f"{e['rule_id']} has no technique mapping"
            assert e["technique_id"].startswith("T")
            assert e["tactic_id"].startswith("TA")

    def test_all_builtin_rule_ids_present(self):
        matrix = build_coverage_matrix()
        ids = {e["rule_id"] for e in matrix["entries"] if e["source"] == "correlation"}
        for rid in ("COR-001", "COR-002", "COR-003", "COR-004", "COR-005", "COR-006"):
            assert rid in ids

    def test_coverage_summary_lists_referenced_techniques(self):
        matrix = build_coverage_matrix()
        assert matrix["techniques_referenced"]
        # Everything referenced is covered by at least one active rule here.
        assert matrix["techniques_not_covered"] == []

    def test_atlas_crossref_present_for_exfil(self):
        matrix = build_coverage_matrix()
        exfil = [e for e in matrix["entries"] if e["technique_id"] == "T1567"]
        assert exfil
        assert all("AML." in e["atlas"] for e in exfil)

    def test_matrix_markdown_renders(self):
        md = coverage_matrix_to_markdown(build_coverage_matrix())
        assert "# Detection Coverage Matrix" in md
        assert "COR-001" in md
        assert "|" in md  # has a table


class TestPrecisionRecall:
    def test_harness_runs_and_metrics_finite(self):
        pr = run_precision_recall()
        assert "per_rule" in pr
        assert "micro_average" in pr
        for rid, m in pr["per_rule"].items():
            for key in ("precision", "recall", "f1"):
                assert math.isfinite(m[key]), f"{rid}.{key} not finite"
                assert 0.0 <= m[key] <= 1.0

    def test_micro_average_finite_and_bounded(self):
        pr = run_precision_recall()
        micro = pr["micro_average"]
        for key in ("precision", "recall", "f1"):
            assert math.isfinite(micro[key])
            assert 0.0 <= micro[key] <= 1.0

    def test_confusion_counts_are_integers(self):
        pr = run_precision_recall()
        for m in pr["per_rule"].values():
            for key in ("tp", "fp", "fn", "tn"):
                assert isinstance(m[key], int)

    def test_dataset_is_labeled_and_balanced(self):
        ds = build_synthetic_dataset()
        assert any(s.label == "malicious" for s in ds)
        assert any(s.label == "benign" for s in ds)
        # Every sequence carries an explicit expected_rules ground truth.
        for s in ds:
            assert isinstance(s.expected_rules, set)

    def test_each_malicious_fixture_fires_its_expected_rule(self):
        """On these synthetic fixtures every malicious seq fires its expected rule."""
        pr = run_precision_recall()
        for row in pr["per_sequence"]:
            if row["label"] == "malicious":
                for rid in row["expected_rules"]:
                    assert rid in row["fired_rules"], row

    def test_benign_fixtures_fire_nothing(self):
        pr = run_precision_recall()
        for row in pr["per_sequence"]:
            if row["label"] == "benign":
                assert row["fired_rules"] == [], row

    def test_markdown_renders(self):
        md = precision_recall_to_markdown(run_precision_recall())
        assert "Precision" in md
        assert "SYNTHETIC" in md.upper()


class TestLatencyBench:
    def test_bench_runs(self):
        bench = run_latency_bench(n_events=200)
        lat = bench["latency_ms"]
        assert lat["p50"] >= 0.0
        assert lat["p95"] >= lat["p50"]
        assert lat["p99"] >= lat["p50"]
        assert math.isfinite(lat["p99"])
        assert bench["_meta"]["n_events"] == 200

    def test_bench_reports_percentiles_finite(self):
        bench = run_latency_bench(n_events=100)
        for key in ("p50", "p95", "p99", "min", "max", "mean"):
            assert math.isfinite(bench["latency_ms"][key])

    def test_markdown_renders(self):
        md = latency_bench_to_markdown(run_latency_bench(n_events=50))
        assert "Microbenchmark" in md
        assert "p99" in md


class TestArtifacts:
    def test_write_artifacts_creates_all_files(self, tmp_path: Path):
        paths = write_artifacts(artifact_dir=tmp_path, n_latency_events=100)
        expected_keys = {
            "coverage_matrix_json",
            "coverage_matrix_md",
            "fixtures_json",
            "precision_recall_json",
            "precision_recall_md",
            "latency_bench_json",
            "latency_bench_md",
        }
        assert expected_keys.issubset(paths.keys())
        for p in paths.values():
            assert Path(p).exists(), p

    def test_written_json_is_valid(self, tmp_path: Path):
        paths = write_artifacts(artifact_dir=tmp_path, n_latency_events=50)
        for key in (
            "coverage_matrix_json",
            "precision_recall_json",
            "latency_bench_json",
            "fixtures_json",
        ):
            data = json.loads(Path(paths[key]).read_text(encoding="utf-8"))
            assert isinstance(data, dict)

    def test_fixtures_labeled_synthetic(self, tmp_path: Path):
        paths = write_artifacts(artifact_dir=tmp_path, n_latency_events=50)
        fixtures = json.loads(Path(paths["fixtures_json"]).read_text(encoding="utf-8"))
        assert "SYNTHETIC" in fixtures["_meta"]["disclaimer"].upper()
