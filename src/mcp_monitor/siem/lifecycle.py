"""Detection-engineering lifecycle utilities for the SIEM correlation rules.

This module adds a *measurable* detection-engineering lifecycle around the
existing correlation rules (COR-001..COR-006 in ``correlation.py``) and the
committed Elastic detection rules (``detection_rules/elastic_rules.toml``).

It provides four capabilities:

1. ``build_coverage_matrix`` — maps every correlation rule and every Elastic
   rule to its MITRE ATT&CK tactic/technique (and ATLAS where applicable) and
   reports which techniques are covered.
2. ``run_precision_recall`` — runs the :class:`CorrelationEngine` over a small,
   explicitly-synthetic labeled dataset and computes per-rule precision /
   recall / F1 with confusion counts.
3. ``run_latency_bench`` — measures ingest+evaluate latency over N synthetic
   events and reports p50/p95/p99.
4. ``write_artifacts`` — serializes the above to committed JSON + Markdown.

IMPORTANT — scope and honesty caveats:
    * All datasets here are **synthetic fixtures**, hand-labeled to exercise
      specific rule logic. They are NOT real-world MCP traffic and the
      resulting precision/recall figures describe behaviour *on these
      fixtures only*. They must not be read as real-world detection efficacy.
    * The latency benchmark is a **local single-process synthetic-load
      microbenchmark**. It is not a production throughput or SLA measurement.
"""

from __future__ import annotations

import json
import statistics
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from mcp_monitor.siem.correlation import (
    BUILTIN_RULES,
    CorrelationEngine,
    CorrelationRule,
    SecurityEvent,
)

try:  # Python 3.11+
    import tomllib  # type: ignore
except ModuleNotFoundError:  # pragma: no cover - fallback for < 3.11
    tomllib = None  # type: ignore


# ------------------------------------------------------------------
# Repo path helpers
# ------------------------------------------------------------------

# lifecycle.py -> siem -> mcp_monitor -> src -> <repo root>
REPO_ROOT = Path(__file__).resolve().parents[3]
ELASTIC_RULES_PATH = REPO_ROOT / "detection_rules" / "elastic_rules.toml"
DEFAULT_ARTIFACT_DIR = REPO_ROOT / "docs" / "detection"


# ------------------------------------------------------------------
# Technique reference names (for readable coverage output)
# ------------------------------------------------------------------

TACTIC_NAMES: dict[str, str] = {
    "TA0001": "Initial Access",
    "TA0002": "Execution",
    "TA0004": "Privilege Escalation",
    "TA0009": "Collection",
    "TA0010": "Exfiltration",
    "TA0043": "Reconnaissance",
}

TECHNIQUE_NAMES: dict[str, str] = {
    "T1005": "Data from Local System",
    "T1059": "Command and Scripting Interpreter",
    "T1074": "Data Staged",
    "T1190": "Exploit Public-Facing Application",
    "T1199": "Trusted Relationship",
    "T1567": "Exfiltration Over Web Service",
    "T1595": "Active Scanning",
}

# ATLAS mappings for the AI/agent-specific angle of some techniques.
# These are advisory cross-references, not 1:1 equivalents.
ATLAS_CROSSREF: dict[str, str] = {
    # Prompt-injection driven execution chains
    "T1059": "AML.T0051 (LLM Prompt Injection)",
    # Exfiltration via agent tool calls
    "T1567": "AML.T0024 (Exfiltration via ML Inference API)",
    # Data staging / collection through agent access
    "T1074": "AML.T0035 (ML Artifact Collection)",
    "T1005": "AML.T0035 (ML Artifact Collection)",
}


# ------------------------------------------------------------------
# 1. Coverage matrix
# ------------------------------------------------------------------


@dataclass
class CoverageEntry:
    source: str  # "correlation" | "elastic"
    rule_id: str
    rule_name: str
    severity: str
    tactic_id: str
    tactic_name: str
    technique_id: str
    technique_name: str
    atlas: str = ""


def _elastic_rules_raw() -> list[dict[str, Any]]:
    """Parse the committed Elastic rules TOML into a list of rule dicts."""
    if tomllib is None:  # pragma: no cover
        raise RuntimeError("tomllib unavailable; Python 3.11+ required to parse Elastic rules")
    if not ELASTIC_RULES_PATH.exists():
        raise FileNotFoundError(f"Elastic rules not found at {ELASTIC_RULES_PATH}")
    with ELASTIC_RULES_PATH.open("rb") as fh:
        data = tomllib.load(fh)
    return list(data.get("rule", []))


def _first_threat_mapping(rule: dict[str, Any]) -> tuple[str, str, str, str]:
    """Extract (tactic_id, tactic_name, technique_id, technique_name) from a
    parsed Elastic rule, or empty strings if no threat mapping present."""
    threats = rule.get("threat") or []
    if not threats:
        return ("", "", "", "")
    tactic = threats[0].get("tactic", {})
    techniques = threats[0].get("technique", [])
    tech = techniques[0] if techniques else {}
    return (
        tactic.get("id", ""),
        tactic.get("name", ""),
        tech.get("id", ""),
        tech.get("name", ""),
    )


def build_coverage_matrix(
    correlation_rules: list[CorrelationRule] | None = None,
) -> dict[str, Any]:
    """Build the coverage matrix mapping every rule to MITRE (and ATLAS).

    Returns a JSON-serializable dict with per-rule entries and an aggregate
    ``techniques_covered`` / ``techniques_not_covered`` summary relative to the
    universe of techniques referenced anywhere in the rule set.
    """
    rules = correlation_rules if correlation_rules is not None else BUILTIN_RULES
    entries: list[CoverageEntry] = []

    # Correlation rules
    for rule in rules:
        entries.append(
            CoverageEntry(
                source="correlation",
                rule_id=rule.rule_id,
                rule_name=rule.name,
                severity=rule.severity,
                tactic_id=rule.mitre_tactic,
                tactic_name=TACTIC_NAMES.get(rule.mitre_tactic, ""),
                technique_id=rule.mitre_technique,
                technique_name=TECHNIQUE_NAMES.get(rule.mitre_technique, ""),
                atlas=ATLAS_CROSSREF.get(rule.mitre_technique, ""),
            )
        )

    # Elastic rules
    for raw in _elastic_rules_raw():
        tac_id, tac_name, tech_id, tech_name = _first_threat_mapping(raw)
        entries.append(
            CoverageEntry(
                source="elastic",
                rule_id=raw.get("name", ""),
                rule_name=raw.get("name", ""),
                severity=raw.get("severity", ""),
                tactic_id=tac_id,
                tactic_name=tac_name or TACTIC_NAMES.get(tac_id, ""),
                technique_id=tech_id,
                technique_name=tech_name or TECHNIQUE_NAMES.get(tech_id, ""),
                atlas=ATLAS_CROSSREF.get(tech_id, ""),
            )
        )

    # Universe of techniques referenced across all rules that HAVE a mapping.
    referenced = sorted({e.technique_id for e in entries if e.technique_id})
    covered = sorted(
        {
            e.technique_id
            for e in entries
            if e.technique_id and e.source in ("correlation", "elastic")
        }
    )
    # Rules with no technique mapping at all (operational rules like rate limit).
    unmapped_rules = [
        {"source": e.source, "rule_id": e.rule_id, "rule_name": e.rule_name}
        for e in entries
        if not e.technique_id
    ]

    not_covered = [t for t in referenced if t not in covered]

    return {
        "_meta": {
            "description": "Detection coverage matrix for MCP correlation + Elastic rules.",
            "disclaimer": (
                "Coverage is measured against the set of ATT&CK techniques referenced "
                "by these rules. It does not imply coverage of the full ATT&CK matrix."
            ),
            "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "correlation_rule_count": sum(1 for e in entries if e.source == "correlation"),
            "elastic_rule_count": sum(1 for e in entries if e.source == "elastic"),
        },
        "entries": [e.__dict__ for e in entries],
        "techniques_referenced": referenced,
        "techniques_covered": covered,
        "techniques_not_covered": not_covered,
        "unmapped_rules": unmapped_rules,
    }


def coverage_matrix_to_markdown(matrix: dict[str, Any]) -> str:
    """Render the coverage matrix as a Markdown document with a table."""
    meta = matrix["_meta"]
    lines: list[str] = []
    lines.append("# Detection Coverage Matrix")
    lines.append("")
    lines.append(f"> {meta['disclaimer']}")
    lines.append("")
    lines.append(f"- Generated: `{meta['generated_at']}`")
    lines.append(f"- Correlation rules: **{meta['correlation_rule_count']}**")
    lines.append(f"- Elastic rules: **{meta['elastic_rule_count']}**")
    lines.append(
        f"- Techniques referenced: **{len(matrix['techniques_referenced'])}** "
        f"({', '.join(matrix['techniques_referenced']) or 'none'})"
    )
    lines.append("")
    lines.append("## Rule → MITRE ATT&CK / ATLAS mapping")
    lines.append("")
    lines.append("| Source | Rule | Severity | Tactic | Technique | ATLAS cross-ref |")
    lines.append("|---|---|---|---|---|---|")
    for e in matrix["entries"]:
        tactic = f"{e['tactic_id']} {e['tactic_name']}".strip() or "—"
        tech = f"{e['technique_id']} {e['technique_name']}".strip() or "—"
        atlas = e["atlas"] or "—"
        lines.append(
            f"| {e['source']} | `{e['rule_id']}` | {e['severity'] or '—'} "
            f"| {tactic} | {tech} | {atlas} |"
        )
    lines.append("")
    lines.append("## Coverage summary")
    lines.append("")
    if matrix["techniques_not_covered"]:
        lines.append(
            "- Techniques referenced but **not covered** by any active rule: "
            + ", ".join(matrix["techniques_not_covered"])
        )
    else:
        lines.append("- Every referenced ATT&CK technique is covered by at least one active rule.")
    if matrix["unmapped_rules"]:
        lines.append("")
        lines.append("### Operational rules without an ATT&CK mapping")
        lines.append("")
        lines.append("These are availability/operational detections, not TTP detections:")
        lines.append("")
        for r in matrix["unmapped_rules"]:
            lines.append(f"- ({r['source']}) `{r['rule_id']}`")
    lines.append("")
    return "\n".join(lines)


# ------------------------------------------------------------------
# 2. Precision / recall harness over synthetic labeled fixtures
# ------------------------------------------------------------------


@dataclass
class LabeledSequence:
    """A synthetic, hand-labeled sequence of events.

    ``expected_rules`` is the ground-truth set of correlation rule_ids that
    SHOULD fire for this sequence. An empty set means the sequence is benign
    and no rule should fire.
    """

    seq_id: str
    label: str  # "benign" | "malicious"
    description: str
    events: list[dict[str, Any]]
    expected_rules: set[str] = field(default_factory=set)


def _mk_event(session_id: str, offset: float, base_ts: float, **kw: Any) -> SecurityEvent:
    defaults: dict[str, Any] = {
        "timestamp": base_ts + offset,
        "event_type": "block",
        "tool_name": "",
        "server_id": "",
        "agent_id": session_id,
        "session_id": session_id,
        "enforcement_action": "block",
        "layer_name": "",
        "risk_score": 50,
        "findings": [],
    }
    defaults.update(kw)
    return SecurityEvent(**defaults)


def build_synthetic_dataset(base_ts: float | None = None) -> list[LabeledSequence]:
    """Return the synthetic labeled dataset (SYNTHETIC FIXTURES, not real traffic).

    Each sequence is designed to exercise a specific correlation rule or to be
    a benign control. Ground-truth ``expected_rules`` are asserted from the
    rule definitions in ``correlation.py``.
    """
    sequences: list[LabeledSequence] = []

    # --- Malicious: COR-001 recon -> sensitive -> exfil ---
    sequences.append(
        LabeledSequence(
            seq_id="mal-cor001",
            label="malicious",
            description="recon (tools/list) -> sensitive read -> network egress exfil",
            events=[
                {
                    "tool_name": "tools/list",
                    "findings": ["discover"],
                    "enforcement_action": "allow",
                },
                {"tool_name": "read_file", "findings": ["sensitive"], "offset": 5},
                {
                    "tool_name": "email.send",
                    "layer_name": "network_egress",
                    "findings": ["exfiltration", "hidden_recipient"],
                    "offset": 10,
                },
            ],
            expected_rules={"COR-001"},
        )
    )

    # --- Malicious: COR-002 injection -> privilege escalation ---
    sequences.append(
        LabeledSequence(
            seq_id="mal-cor002",
            label="malicious",
            description="prompt injection -> process spawn",
            events=[
                {"findings": ["prompt_injection detected"]},
                {"layer_name": "process_spawn", "findings": ["subprocess"], "offset": 5},
            ],
            expected_rules={"COR-002"},
        )
    )

    # --- Malicious: COR-003 shadow server -> exfil ---
    sequences.append(
        LabeledSequence(
            seq_id="mal-cor003",
            label="malicious",
            description="shadow/unregistered server -> exfil",
            events=[
                {"layer_name": "server_trust", "findings": ["unregistered", "shadow_server"]},
                {
                    "layer_name": "network_egress",
                    "findings": ["exfiltration"],
                    "offset": 5,
                },
            ],
            expected_rules={"COR-003"},
        )
    )

    # --- Malicious: COR-004 persistent high-risk blocks ---
    sequences.append(
        LabeledSequence(
            seq_id="mal-cor004",
            label="malicious",
            description="three high-risk blocks in quick succession",
            events=[
                {"enforcement_action": "block", "risk_score": 70},
                {"enforcement_action": "deny", "risk_score": 80, "offset": 1},
                {"enforcement_action": "block", "risk_score": 65, "offset": 2},
            ],
            expected_rules={"COR-004"},
        )
    )

    # --- Malicious: COR-005 injection -> exfil ---
    sequences.append(
        LabeledSequence(
            seq_id="mal-cor005",
            label="malicious",
            description="prompt injection -> exfil (indirect injection chain)",
            events=[
                {"findings": ["prompt_injection"]},
                {"layer_name": "network_egress", "findings": ["exfiltration"], "offset": 5},
            ],
            # Note: COR-005 (injection->exfil) fires. COR-002 needs process
            # escalation which is absent, so only COR-005 is ground-truth.
            expected_rules={"COR-005"},
        )
    )

    # --- Malicious: COR-006 sensitive -> shadow server ---
    sequences.append(
        LabeledSequence(
            seq_id="mal-cor006",
            label="malicious",
            description="sensitive data access -> unregistered server (staging)",
            events=[
                {"tool_name": "get_secret", "findings": ["credentials"]},
                {"layer_name": "server_trust", "findings": ["unregistered"], "offset": 5},
            ],
            expected_rules={"COR-006"},
        )
    )

    # --- Benign controls (no rule should fire) ---
    sequences.append(
        LabeledSequence(
            seq_id="ben-normal-1",
            label="benign",
            description="ordinary allowed tool calls, no attack pattern",
            events=[
                {"tool_name": "math.add", "enforcement_action": "allow", "findings": ["normal"]},
                {
                    "tool_name": "math.multiply",
                    "enforcement_action": "allow",
                    "findings": ["normal"],
                    "offset": 3,
                },
            ],
            expected_rules=set(),
        )
    )

    sequences.append(
        LabeledSequence(
            seq_id="ben-single-block",
            label="benign",
            description="a single low-risk block, insufficient for any multi-event rule",
            events=[
                {"enforcement_action": "block", "risk_score": 30, "findings": ["policy_violation"]},
            ],
            expected_rules=set(),
        )
    )

    sequences.append(
        LabeledSequence(
            seq_id="ben-low-risk-blocks",
            label="benign",
            description="repeated but LOW-risk blocks (<60), below COR-004 threshold",
            events=[
                {"enforcement_action": "block", "risk_score": 40},
                {"enforcement_action": "block", "risk_score": 45, "offset": 1},
                {"enforcement_action": "block", "risk_score": 30, "offset": 2},
            ],
            expected_rules=set(),
        )
    )

    return sequences


def _events_from_sequence(seq: LabeledSequence, base_ts: float) -> list[SecurityEvent]:
    events: list[SecurityEvent] = []
    for i, ev in enumerate(seq.events):
        ev = dict(ev)
        offset = ev.pop("offset", float(i))
        events.append(_mk_event(seq.seq_id, offset, base_ts, **ev))
    return events


def run_precision_recall(
    dataset: list[LabeledSequence] | None = None,
    rules: list[CorrelationRule] | None = None,
) -> dict[str, Any]:
    """Run the correlation engine over the synthetic dataset and compute
    per-rule precision / recall / F1 and confusion counts.

    Detection semantics: for each sequence we build a FRESH engine (each
    sequence is an isolated session), ingest its events, and collect the set of
    rule_ids that fired at any point. A rule ``R`` counts as:
        TP  if R in expected_rules and R in fired_rules
        FP  if R not in expected_rules but R in fired_rules
        FN  if R in expected_rules but R not in fired_rules
        TN  otherwise
    """
    dataset = dataset if dataset is not None else build_synthetic_dataset()
    rules = rules if rules is not None else BUILTIN_RULES
    rule_ids = [r.rule_id for r in rules]

    # per-rule confusion counters
    conf: dict[str, dict[str, int]] = {
        rid: {"tp": 0, "fp": 0, "fn": 0, "tn": 0} for rid in rule_ids
    }
    per_sequence: list[dict[str, Any]] = []

    base_ts = time.time()
    for seq in dataset:
        engine = CorrelationEngine(window_seconds=600)
        engine.add_rules(rules)
        fired: set[str] = set()
        for ev in _events_from_sequence(seq, base_ts):
            for match in engine.ingest(ev):
                fired.add(match.rule_id)

        for rid in rule_ids:
            expected = rid in seq.expected_rules
            got = rid in fired
            if expected and got:
                conf[rid]["tp"] += 1
            elif not expected and got:
                conf[rid]["fp"] += 1
            elif expected and not got:
                conf[rid]["fn"] += 1
            else:
                conf[rid]["tn"] += 1

        per_sequence.append(
            {
                "seq_id": seq.seq_id,
                "label": seq.label,
                "expected_rules": sorted(seq.expected_rules),
                "fired_rules": sorted(fired),
            }
        )

    def _prf(c: dict[str, int]) -> dict[str, float]:
        tp, fp, fn = c["tp"], c["fp"], c["fn"]
        precision = tp / (tp + fp) if (tp + fp) else 0.0
        recall = tp / (tp + fn) if (tp + fn) else 0.0
        f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
        return {"precision": precision, "recall": recall, "f1": f1}

    per_rule: dict[str, Any] = {}
    for rid in rule_ids:
        c = conf[rid]
        per_rule[rid] = {**c, **_prf(c)}

    # Aggregate (micro-averaged over all rules)
    agg_tp = sum(conf[r]["tp"] for r in rule_ids)
    agg_fp = sum(conf[r]["fp"] for r in rule_ids)
    agg_fn = sum(conf[r]["fn"] for r in rule_ids)
    agg_tn = sum(conf[r]["tn"] for r in rule_ids)
    micro = _prf({"tp": agg_tp, "fp": agg_fp, "fn": agg_fn, "tn": agg_tn})

    return {
        "_meta": {
            "description": "Per-rule precision/recall over SYNTHETIC labeled fixtures.",
            "disclaimer": (
                "SYNTHETIC FIXTURES ONLY. These sequences are hand-crafted to exercise "
                "specific rule logic and are NOT real-world MCP traffic. Metrics describe "
                "behaviour on these fixtures only and must not be read as real-world "
                "detection efficacy."
            ),
            "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "sequence_count": len(dataset),
            "malicious_sequences": sum(1 for s in dataset if s.label == "malicious"),
            "benign_sequences": sum(1 for s in dataset if s.label == "benign"),
        },
        "per_rule": per_rule,
        "micro_average": {
            "tp": agg_tp,
            "fp": agg_fp,
            "fn": agg_fn,
            "tn": agg_tn,
            **micro,
        },
        "per_sequence": per_sequence,
    }


# ------------------------------------------------------------------
# 3. Latency microbenchmark
# ------------------------------------------------------------------


def run_latency_bench(n_events: int = 2000, seed_rules: bool = True) -> dict[str, Any]:
    """Measure ingest+evaluate latency over ``n_events`` synthetic events.

    Reports p50/p95/p99 (milliseconds). This is a LOCAL, single-process,
    synthetic-load microbenchmark — not a production throughput measurement.
    """
    engine = CorrelationEngine(window_seconds=300)
    if seed_rules:
        engine.add_rules(BUILTIN_RULES)

    base_ts = time.time()
    # Rotate through a handful of event shapes to exercise the predicates.
    shapes = [
        {"tool_name": "tools/list", "findings": ["discover"], "enforcement_action": "allow"},
        {"tool_name": "read_file", "findings": ["sensitive"]},
        {"layer_name": "network_egress", "findings": ["exfiltration"]},
        {"findings": ["prompt_injection"]},
        {"enforcement_action": "block", "risk_score": 70},
        {"tool_name": "math.add", "enforcement_action": "allow", "findings": ["normal"]},
    ]

    latencies_ms: list[float] = []
    for i in range(n_events):
        shape = dict(shapes[i % len(shapes)])
        # Spread across a few sessions so windows stay bounded.
        session = f"bench-{i % 8}"
        ev = _mk_event(session, float(i % 200), base_ts, **shape)
        t0 = time.perf_counter()
        engine.ingest(ev)
        t1 = time.perf_counter()
        latencies_ms.append((t1 - t0) * 1000.0)

    latencies_ms.sort()

    def _pct(p: float) -> float:
        if not latencies_ms:
            return 0.0
        k = max(0, min(len(latencies_ms) - 1, int(round((p / 100.0) * (len(latencies_ms) - 1)))))
        return latencies_ms[k]

    total_s = sum(latencies_ms) / 1000.0
    return {
        "_meta": {
            "description": "Ingest+evaluate latency microbenchmark.",
            "disclaimer": (
                "LOCAL SYNTHETIC-LOAD MICROBENCHMARK. Single process, in-memory engine, "
                "synthetic events. NOT a production throughput or SLA measurement."
            ),
            "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "n_events": n_events,
            "rules_loaded": len(engine.rules),
        },
        "latency_ms": {
            "p50": _pct(50),
            "p95": _pct(95),
            "p99": _pct(99),
            "min": latencies_ms[0] if latencies_ms else 0.0,
            "max": latencies_ms[-1] if latencies_ms else 0.0,
            "mean": statistics.fmean(latencies_ms) if latencies_ms else 0.0,
        },
        "throughput_events_per_s_local": (n_events / total_s) if total_s > 0 else 0.0,
    }


def latency_bench_to_markdown(bench: dict[str, Any]) -> str:
    meta = bench["_meta"]
    lat = bench["latency_ms"]
    lines = [
        "# Detection Latency Microbenchmark",
        "",
        f"> {meta['disclaimer']}",
        "",
        f"- Generated: `{meta['generated_at']}`",
        f"- Events: **{meta['n_events']}**",
        f"- Rules loaded: **{meta['rules_loaded']}**",
        "",
        "| Metric | Value (ms) |",
        "|---|---|",
        f"| p50 | {lat['p50']:.4f} |",
        f"| p95 | {lat['p95']:.4f} |",
        f"| p99 | {lat['p99']:.4f} |",
        f"| min | {lat['min']:.4f} |",
        f"| max | {lat['max']:.4f} |",
        f"| mean | {lat['mean']:.4f} |",
        "",
        f"Local throughput (single process): ~{bench['throughput_events_per_s_local']:.0f} events/s.",
        "",
    ]
    return "\n".join(lines)


def precision_recall_to_markdown(pr: dict[str, Any]) -> str:
    meta = pr["_meta"]
    lines = [
        "# Detection Precision / Recall (synthetic fixtures)",
        "",
        f"> {meta['disclaimer']}",
        "",
        f"- Generated: `{meta['generated_at']}`",
        f"- Sequences: **{meta['sequence_count']}** "
        f"({meta['malicious_sequences']} malicious, {meta['benign_sequences']} benign)",
        "",
        "## Per-rule metrics",
        "",
        "| Rule | TP | FP | FN | TN | Precision | Recall | F1 |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for rid, m in pr["per_rule"].items():
        lines.append(
            f"| `{rid}` | {m['tp']} | {m['fp']} | {m['fn']} | {m['tn']} "
            f"| {m['precision']:.3f} | {m['recall']:.3f} | {m['f1']:.3f} |"
        )
    micro = pr["micro_average"]
    lines += [
        "",
        "## Micro-average (all rules)",
        "",
        f"- Precision: **{micro['precision']:.3f}**",
        f"- Recall: **{micro['recall']:.3f}**",
        f"- F1: **{micro['f1']:.3f}**",
        f"- Confusion: TP={micro['tp']} FP={micro['fp']} FN={micro['fn']} TN={micro['tn']}",
        "",
    ]
    return "\n".join(lines)


# ------------------------------------------------------------------
# 4. Artifact writer
# ------------------------------------------------------------------


def _write_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, sort_keys=False) + "\n", encoding="utf-8")


def _write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _serialize_dataset(dataset: list[LabeledSequence]) -> dict[str, Any]:
    return {
        "_meta": {
            "description": "Synthetic labeled event sequences for the detection harness.",
            "disclaimer": ("SYNTHETIC FIXTURES ONLY — hand-labeled, NOT real-world MCP traffic."),
        },
        "sequences": [
            {
                "seq_id": s.seq_id,
                "label": s.label,
                "description": s.description,
                "expected_rules": sorted(s.expected_rules),
                "events": s.events,
            }
            for s in dataset
        ],
    }


def write_artifacts(
    artifact_dir: Path | str = DEFAULT_ARTIFACT_DIR,
    n_latency_events: int = 2000,
) -> dict[str, str]:
    """Generate all lifecycle artifacts and write them to ``artifact_dir``.

    Returns a mapping of artifact-name -> written path (as str).
    """
    out = Path(artifact_dir)

    dataset = build_synthetic_dataset()
    matrix = build_coverage_matrix()
    pr = run_precision_recall(dataset)
    bench = run_latency_bench(n_events=n_latency_events)

    paths: dict[str, str] = {}

    p = out / "coverage_matrix.json"
    _write_json(p, matrix)
    paths["coverage_matrix_json"] = str(p)

    p = out / "coverage_matrix.md"
    _write_text(p, coverage_matrix_to_markdown(matrix))
    paths["coverage_matrix_md"] = str(p)

    p = out / "fixtures" / "synthetic_events.json"
    _write_json(p, _serialize_dataset(dataset))
    paths["fixtures_json"] = str(p)

    p = out / "precision_recall.json"
    _write_json(p, pr)
    paths["precision_recall_json"] = str(p)

    p = out / "precision_recall.md"
    _write_text(p, precision_recall_to_markdown(pr))
    paths["precision_recall_md"] = str(p)

    p = out / "latency_bench.json"
    _write_json(p, bench)
    paths["latency_bench_json"] = str(p)

    p = out / "latency_bench.md"
    _write_text(p, latency_bench_to_markdown(bench))
    paths["latency_bench_md"] = str(p)

    return paths


def main() -> None:  # pragma: no cover - CLI convenience
    paths = write_artifacts()
    print("Wrote detection-lifecycle artifacts:")
    for name, path in paths.items():
        print(f"  {name}: {path}")


if __name__ == "__main__":  # pragma: no cover
    main()
