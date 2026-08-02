"""Prompt injection detection for MCP tool call arguments.

Hybrid detector using:
  1. FAST regex first-pass (< 1ms) — 12 patterns for known injection families
  2. ML second-pass — TF-IDF classifier from defense10 for ambiguous cases

If regex matches with high confidence, the ML pass is skipped.
If regex doesn't match, the ML classifier provides a secondary risk signal.
"""

from __future__ import annotations

import re
from typing import Any

# At least 10 patterns covering the major injection families.
INJECTION_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    (
        "ignore_previous_instructions",
        re.compile(
            r"ignore.{0,20}(previous|prior|above).{0,20}instructions?",
            re.IGNORECASE,
        ),
    ),
    (
        "system_override",
        re.compile(r"(system|admin)\s+override", re.IGNORECASE),
    ),
    (
        "forget_everything",
        re.compile(r"forget\s+(everything|all|your)", re.IGNORECASE),
    ),
    (
        "jailbreak_identity",
        re.compile(
            r"you\s+are\s+now\s+(dan|jailbreak|unrestricted|evil)",
            re.IGNORECASE,
        ),
    ),
    (
        "tag_injection",
        re.compile(r"<\s*/?system\s*>", re.IGNORECASE),
    ),
    (
        "do_anything_now",
        re.compile(r"do\s+anything\s+now", re.IGNORECASE),
    ),
    (
        "disregard_guidelines",
        re.compile(
            r"disregard.{0,20}(guidelines|rules|policies|restrictions|directives)",
            re.IGNORECASE,
        ),
    ),
    (
        "reveal_prompt",
        re.compile(
            r"(reveal|show|print|output).{0,20}(system\s+prompt|hidden\s+instructions|initial\s+prompt)",
            re.IGNORECASE,
        ),
    ),
    (
        "act_as_unrestricted",
        re.compile(
            r"act\s+as\s+(an?\s+)?(unrestricted|unfiltered|uncensored)",
            re.IGNORECASE,
        ),
    ),
    (
        "new_instructions",
        re.compile(
            r"(new|updated|real)\s+instructions?\s*(:|are|supersede)",
            re.IGNORECASE,
        ),
    ),
    (
        "bypass_safety",
        re.compile(
            r"bypass.{0,15}(safety|content|filter|moderation)",
            re.IGNORECASE,
        ),
    ),
    (
        "roleplay_evil",
        re.compile(
            r"(pretend|imagine)\s+(you.{0,10})?(have\s+no|without).{0,15}(restrictions|limits|rules)",
            re.IGNORECASE,
        ),
    ),
]


class PromptInjectionDetector:
    """Detects prompt injection attempts in MCP tool call arguments.

    Uses a two-pass approach:
      1. Regex patterns for fast, deterministic detection of known attacks
      2. ML classifier (TF-IDF + structural features) for ambiguous cases
    """

    def __init__(self, *, enable_ml: bool = True) -> None:
        self.patterns = INJECTION_PATTERNS
        self._enable_ml = enable_ml
        self._ml_classifier = None

    def _get_ml_classifier(self):
        """Lazy-load the ML classifier on first use."""
        if self._ml_classifier is None and self._enable_ml:
            try:
                from mcp_monitor.defense10.ml_classifier import MLThreatClassifier

                self._ml_classifier = MLThreatClassifier(threshold=0.7)
                self._ml_classifier.train()
            except Exception:
                # If ML deps unavailable, degrade gracefully to regex-only
                self._enable_ml = False
        return self._ml_classifier

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def detect(self, tool_call: dict[str, Any]) -> tuple[bool, list[str]]:
        """Scan all string values in *tool_call* arguments for injection.

        Parameters
        ----------
        tool_call:
            Dict with at least ``{"name": str, "arguments": dict}``.

        Returns
        -------
        tuple of (detected: bool, matched_pattern_names: list[str])
        """
        arguments = tool_call.get("arguments", {})
        texts = self._extract_strings(arguments)
        matched: list[str] = []

        # Pass 1: Fast regex scan (< 1ms)
        for text in texts:
            for name, pattern in self.patterns:
                if pattern.search(text) and name not in matched:
                    matched.append(name)

        # If regex matched, high confidence — skip ML
        if matched:
            return (True, matched)

        # Pass 2: ML classifier for ambiguous cases
        if self._enable_ml and texts:
            clf = self._get_ml_classifier()
            if clf is not None:
                prediction = clf.classify(tool_call)
                if prediction.is_threat and prediction.confidence >= 0.7:
                    family = prediction.threat_family or "ml_detected"
                    matched.append(f"ml_{family}")

        return (bool(matched), matched)

    def risk_score(self, tool_call: dict[str, Any]) -> int:
        """Return a risk score 0-100 based on matched pattern count and severity.

        Combines regex confidence with ML confidence for a unified score.
        """
        arguments = tool_call.get("arguments", {})
        texts = self._extract_strings(arguments)
        regex_matched: list[str] = []

        # Regex pass
        for text in texts:
            for name, pattern in self.patterns:
                if pattern.search(text) and name not in regex_matched:
                    regex_matched.append(name)

        if regex_matched:
            # High confidence from regex
            base = 30
            per_pattern = 15
            score = base + per_pattern * len(regex_matched)
            return min(score, 100)

        # ML pass for ambiguous cases
        if self._enable_ml and texts:
            clf = self._get_ml_classifier()
            if clf is not None:
                prediction = clf.classify(tool_call)
                if prediction.is_threat:
                    # Scale ML confidence to 0-100 risk score
                    # ML alone caps at 80 (regex gets full 100)
                    return min(int(prediction.confidence * 80), 80)

        return 0

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _extract_strings(self, obj: Any) -> list[str]:
        """Recursively extract all string values from a nested structure."""
        strings: list[str] = []
        if isinstance(obj, str):
            strings.append(obj)
        elif isinstance(obj, dict):
            for value in obj.values():
                strings.extend(self._extract_strings(value))
        elif isinstance(obj, list | tuple):
            for item in obj:
                strings.extend(self._extract_strings(item))
        return strings
