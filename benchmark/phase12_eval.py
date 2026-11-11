"""Reproducible, author-curated synthetic prompt-injection benchmark.

Regex-only baseline. Not representative of live attacks or real users.
"""

from __future__ import annotations

import hashlib
import json
from collections import Counter, defaultdict
from pathlib import Path

from mcp_monitor.detectors.prompt_injection import PromptInjectionDetector

CORPUS = Path(__file__).with_name("phase12_holdout.jsonl")


def load_cases(path: Path = CORPUS) -> tuple[list[dict], str]:
    raw = path.read_bytes()
    if not raw or len(raw) > 250_000:
        raise ValueError("Invalid corpus size")
    cases = [json.loads(line) for line in raw.decode("utf-8").splitlines()]
    if len(cases) != 96 or any(
        not isinstance(c, dict) or set(c) != {"id", "label", "family", "text"} for c in cases
    ):
        raise ValueError("Unexpected benchmark schema")
    if any(
        not all(isinstance(v, str) and v for v in c.values())
        or c["label"] not in ("malicious", "benign")
        for c in cases
    ):
        raise ValueError("Malformed case")
    if len({c["id"] for c in cases}) != 96 or len({c["text"] for c in cases}) != 96:
        raise ValueError("Duplicate case")
    families = Counter((c["label"], c["family"]) for c in cases)
    if len(families) != 12 or any(n != 8 for n in families.values()):
        raise ValueError("Unexpected family balance")
    return cases, hashlib.sha256(raw).hexdigest()


def safe_ratio(n: int, d: int) -> float | None:
    return n / d if d else None


def score(results: list[dict]) -> dict:
    tp = sum(x["label"] == "malicious" and x["detected"] for x in results)
    fn = sum(x["label"] == "malicious" and not x["detected"] for x in results)
    fp = sum(x["label"] == "benign" and x["detected"] for x in results)
    tn = sum(x["label"] == "benign" and not x["detected"] for x in results)
    return {
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "tn": tn,
        "precision": safe_ratio(tp, tp + fp),
        "recall": safe_ratio(tp, tp + fn),
        "false_positive_rate": safe_ratio(fp, fp + tn),
        "false_negative_rate": safe_ratio(fn, fn + tp),
        "f1": safe_ratio(2 * tp, 2 * tp + fp + fn),
    }


def evaluate() -> dict:
    cases, digest = load_cases()
    detector = PromptInjectionDetector(enable_ml=False)
    results = []
    for case in cases:
        call = {"name": "read_document", "arguments": {"content": case["text"]}}
        detected, patterns = detector.detect(call)
        results.append(
            {
                "id": case["id"],
                "label": case["label"],
                "family": case["family"],
                "detected": detected,
                "patterns": patterns,
            }
        )
    families = defaultdict(list)
    for item in results:
        families[item["label"] + "/" + item["family"]].append(item)
    return {
        "mode": "regex_only_enable_ml_false",
        "corpus_sha256": digest,
        "count": len(results),
        "metrics": score(results),
        "families": {name: score(records) for name, records in sorted(families.items())},
        "false_positive_ids": [
            r["id"] for r in results if r["label"] == "benign" and r["detected"]
        ],
        "false_negative_ids": [
            r["id"] for r in results if r["label"] == "malicious" and not r["detected"]
        ],
        "per_case": results,
    }


if __name__ == "__main__":
    print(json.dumps(evaluate(), indent=2, sort_keys=True))
