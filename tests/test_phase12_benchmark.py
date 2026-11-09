"""Verify the frozen benchmark's accounting, not a desired detector score."""
from __future__ import annotations

import pytest

from benchmark.phase12_eval import CORPUS, evaluate, load_cases, safe_ratio, score


def test_frozen_corpus_integrity():
    records, digest = load_cases()
    assert len(records) == 96
    assert len(digest) == 64
    assert sum(r["label"] == "malicious" for r in records) == 48


def test_actual_detector_metrics_account_for_every_case():
    report = evaluate()
    assert report["count"] == 96
    assert len(report["families"]) == 12
    assert report["metrics"]["tp"] + report["metrics"]["fn"] == 48
    assert report["metrics"]["fp"] + report["metrics"]["tn"] == 48
    assert len(report["false_positive_ids"]) == report["metrics"]["fp"]
    assert len(report["false_negative_ids"]) == report["metrics"]["fn"]


def test_detector_never_receives_labels(monkeypatch):
    from mcp_monitor.detectors.prompt_injection import PromptInjectionDetector

    calls = []

    def capture(self, call):
        calls.append(call)
        return False, []

    monkeypatch.setattr(PromptInjectionDetector, "detect", capture)
    assert evaluate()["metrics"]["fn"] == 48
    assert len(calls) == 96
    assert all("label" not in str(c) and "family" not in str(c) for c in calls)


def test_metrics_and_zero_denominator():
    rows = [
        {"label": "malicious", "detected": True},
        {"label": "malicious", "detected": False},
        {"label": "benign", "detected": True},
        {"label": "benign", "detected": False},
    ]
    result = score(rows)
    assert (result["tp"], result["fp"], result["fn"], result["tn"]) == (1, 1, 1, 1)
    assert result["f1"] == 0.5
    assert safe_ratio(0, 0) is None


@pytest.mark.parametrize("extra", ['{}', '{"label":"malicious"}', '{"id":"x"}'])
def test_corrupt_corpus_rejected(tmp_path, extra):
    path = tmp_path / "bad.jsonl"
    path.write_text(CORPUS.read_text() + extra + "\n")
    with pytest.raises(ValueError):
        load_cases(path)
