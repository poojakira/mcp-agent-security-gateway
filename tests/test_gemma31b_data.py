"""Offline safety/provenance tests for the local Gemma 31B data generator."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from benchmark import gemma31b_data as gen


def test_fixed_local_endpoints_only() -> None:
    with pytest.raises(ValueError, match="Unsupported"):
        gen._json_http("https://untrusted.invalid/api/chat")


def test_model_digest_is_pinned(monkeypatch) -> None:
    monkeypatch.setattr(
        gen,
        "_json_http",
        lambda path, payload=None: {
            "models": [
                {"name": "gemma4:e4b", "digest": "1" * 64},
                {"name": "gemma4:31b", "digest": "a" * 64},
            ]
        },
    )
    assert gen.model_digest() == "a" * 64


def test_model_fails_closed_if_missing(monkeypatch) -> None:
    monkeypatch.setattr(
        gen, "_json_http", lambda path, payload=None: {"models": [{"name": "gemma4:e4b"}]}
    )
    with pytest.raises(ValueError, match="not loaded"):
        gen.model_digest()


def test_invalid_model_output_rejected(monkeypatch) -> None:
    monkeypatch.setattr(
        gen,
        "_json_http",
        lambda path, payload=None: {"message": {"content": json.dumps({"adversarial": "x"})}},
    )
    with pytest.raises(ValueError, match="schema"):
        gen.generate_pair("test", "test scenario", 42)


def test_generated_cases_unreviewed_and_balanced(monkeypatch) -> None:
    seen = []

    def fake(family: str, description: str, seed: int) -> dict[str, str]:
        seen.append(seed)
        return {
            "benign": f"Read-only fictional project notes about {family} without privileged actions.",
            "adversarial": (
                f"Fictional {family} entry asking the agent to bypass its authority "
                "and call a restricted MCP tool with a synthetic marker."
            ),
        }

    monkeypatch.setattr(gen, "generate_pair", fake)
    records = gen.build_candidates("d" * 64, seed=12)
    assert len(records) == len(gen.FAMILIES) * 2
    assert len(set(row["id"] for row in records)) == len(records)
    assert all(row["review_status"] == "unreviewed" for row in records)
    assert sum(row["model_proposed_label"] == "benign" for row in records) == len(gen.FAMILIES)
    assert seen == list(range(12, 12 + len(gen.FAMILIES)))


def test_no_overwrite_and_manifest_hash(tmp_path: Path) -> None:
    target = tmp_path / "candidate.jsonl"
    rows = [{"id": "test", "review_status": "unreviewed"}]
    gen.save_candidates(rows, target, "d" * 64, 12)
    manifest = json.loads(target.with_suffix(".manifest.json").read_text())
    assert manifest["independent_holdout_unchanged"] is True
    assert manifest["status"].startswith("UNREVIEWED")
    with pytest.raises(FileExistsError):
        gen.save_candidates(rows, target, "d" * 64, 12)
