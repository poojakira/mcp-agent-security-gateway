"""Measure regex-only detection on a separately authored, pinned public corpus.

The benchmark is a diagnostic, not a model training set or a demonstration of
real-world prevention. No network access occurs in this module or its tests.
The CI workflow downloads one static file from a public GitHub commit with no
provider API keys, and verifies the Git blob hash BEFORE evaluation.
"""

from __future__ import annotations

import argparse
import csv
import json
from collections import Counter, defaultdict
from pathlib import Path

from mcp_monitor.detectors.prompt_injection import PromptInjectionDetector


def score(records: list[dict[str, object]]) -> dict[str, float | int | None]:
    tp = sum(x["label"] == "injection" and x["detected"] for x in records)
    fn = sum(x["label"] == "injection" and not x["detected"] for x in records)
    fp = sum(x["label"] == "benign" and x["detected"] for x in records)
    tn = sum(x["label"] == "benign" and not x["detected"] for x in records)
    def ratio(numerator: int, denominator: int) -> float | None:
        return numerator / denominator if denominator else None
    return {
        "tp": tp, "fn": fn, "fp": fp, "tn": tn,
        "precision": ratio(tp, tp + fp),
        "recall": ratio(tp, tp + fn),
        "false_positive_rate": ratio(fp, fp + tn),
        "false_negative_rate": ratio(fn, tp + fn),
        "f1": ratio(2 * tp, 2 * tp + fp + fn),
    }


def evaluate(csv_path: Path) -> dict[str, object]:
    if not isinstance(csv_path, Path) or not csv_path.is_file() or csv_path.stat().st_size > 1_000_000:
        raise ValueError("Benchmark must be a local, bounded, pinned CSV file")
    with csv_path.open("r", encoding="utf-8", newline="") as stream:
        reader = csv.DictReader(stream)
        if reader.fieldnames != ["text", "label", "category", "severity"]:
            raise ValueError("Unexpected external corpus header")
        cases = list(reader)
    if not cases or len(cases) > 1000:
        raise ValueError("Invalid external corpus size")
    if any(
        not isinstance(c["text"], str) or not c["text"]
        or c["label"] not in {"benign", "injection"}
        or not c["category"] or not c["severity"]
        for c in cases
    ):
        raise ValueError("Invalid external corpus case")
    detector = PromptInjectionDetector(enable_ml=False)
    cases_out: list[dict[str, object]] = []
    for index, case in enumerate(cases):
        detected, patterns = detector.detect(
            {"name": "read_document", "arguments": {"content": case["text"]}}
        )
        cases_out.append(
            {
                "index": index,
                "label": case["label"],
                "category": case["category"],
                "severity": case["severity"],
                "detected": bool(detected),
                "patterns": list(patterns),
            }
        )
    grouped: defaultdict[str, list[dict[str, object]]] = defaultdict(list)
    for case in cases_out:
        grouped[str(case["category"])].append(case)
    label_counts = Counter(str(c["label"]) for c in cases_out)
    return {
        "mode": "regex_only_public_external_corpus",
        "source": "stef41/prompt-injection-benchmark",
        "source_commit": "dc0072ad6af8d1be049cdb60959e3ff51df4bcae",
        "source_blob_sha1": "17d2c521a6b7a5ebd7f68e768fd334cd97897a4e",
        "license_claim": "MIT per upstream README",
        "count": len(cases_out),
        "labels": dict(label_counts),
        "metrics": score(cases_out),
        "categories": {k: score(v) for k, v in sorted(grouped.items())},
        "false_positive_indices": [
            x["index"] for x in cases_out if x["label"] == "benign" and x["detected"]
        ],
        "false_negative_indices": [
            x["index"] for x in cases_out if x["label"] == "injection" and not x["detected"]
        ],
        "limitations": [
            "External dataset is independently authored, not an independent penetration test",
            "Contains curated prompts, not necessarily MCP tool-response injection in the wild",
            "Regex-only verdicts are not authorization or actual attack-success rates",
            "Never use this corpus as both tuning data and an untouched test set",
        ],
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("corpus", type=Path)
    parser.add_argument("--output", type=Path)
    options = parser.parse_args()
    result = evaluate(options.corpus)
    output = json.dumps(result, sort_keys=True, indent=2)
    if options.output is None:
        print(output)
    else:
        options.output.write_text(output + "\n", encoding="utf-8")
        print("External corpus evaluated:", result["count"])
        print("Confusion matrix:", json.dumps(result["metrics"], sort_keys=True))


if __name__ == "__main__":
    main()
