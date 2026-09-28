# Detection Rule Tuning Log

This log records deliberate tuning decisions for the correlation rules in
`src/mcp_monitor/siem/correlation.py`. Each entry states the parameter, the
before/after value, and the rationale that can be traced directly to the rule
code and the synthetic-fixture measurements in `docs/detection/`.

> Scope note: rationale is grounded in the rule definitions and the synthetic
> fixture harness (`docs/detection/precision_recall.json`). These are
> fixture-scoped measurements, not real-world traffic tuning. Thresholds should
> be re-validated against real telemetry before production use.

---

## Decision 1 — `COR-004` persistent-attacker: `risk_score >= 60` gate + `min_events=3` @ `window_seconds=60`

**Rule:** `PERSISTENT_ATTACKER_RULE` (COR-004)
**Predicate:** `_is_repeated_block` — fires only when
`enforcement_action in ("block", "deny") and event.risk_score >= 60`.

**Before (hypothetical naive design):**
- Trigger on *any* 2 blocked events in the window, regardless of risk score.
- `min_events = 2`, no risk floor.

**After (current code):**
- `_is_repeated_block` requires `risk_score >= 60`.
- `min_events = 3`, three repeated high-risk blocks required.
- `window_seconds = 60`.

**Rationale:**
A single low-risk block is routine (policy denials, malformed args). Counting
*any* block would make COR-004 fire on ordinary benign-but-denied traffic,
producing false positives. Two design choices suppress that:

1. **Risk floor (`>= 60`).** Only blocks the gateway already scored as
   medium/high risk count toward "persistent probing". This is validated by
   the `ben-low-risk-blocks` fixture in `docs/detection/fixtures/synthetic_events.json`
   — three blocks at risk 40/45/30 do **not** fire COR-004, while the
   `mal-cor004` fixture (blocks at 70/80/65) does. Per-rule confusion for
   COR-004 in `precision_recall.json` shows `fp = 0` on the current fixtures.
2. **`min_events = 3` in a 60s window.** Requiring three high-risk blocks
   inside one minute targets *systematic* bypass probing rather than a single
   retried mistake, trading a small amount of recall (a 2-block burst won't
   fire) for materially higher precision.

**Net effect on fixtures:** COR-004 precision/recall = 1.0/1.0 with FP=0 across
the 9-sequence synthetic set. The low-risk benign control is correctly ignored.

---

## Decision 2 — `COR-002` injection→escalation: tighter `window_seconds=120`

**Rule:** `INJECTION_THEN_ESCALATION_RULE` (COR-002)
**Parameter:** `window_seconds`

**Before:** default correlation window of `300` seconds (5 minutes, the class
default used by `CorrelationEngine` and `CORRELATION_RULE.window_seconds`).

**After:** `window_seconds = 120` (2 minutes) on the rule itself.

**Rationale:**
COR-002 models a *causal* chain: a prompt-injection attempt that then drives a
process-spawn / privilege-escalation attempt. In a genuine indirect-injection
exploit these stages occur back-to-back within the same agent turn or a few
follow-up tool calls — seconds to low tens of seconds apart. A 5-minute window
would allow an unrelated injection attempt and an unrelated later escalation in
the same session to be stitched into a false chain.

Shortening to 120s keeps comfortable headroom over realistic multi-tool
latency while cutting the opportunity for coincidental pairing. The window
logic is enforced in `CorrelationRule.evaluate` via
`time_span = matched[-1].timestamp - matched[0].timestamp` compared against
`window_seconds`, and is exercised by `test_siem.py::test_window_expiry`, which
confirms events outside the window do not correlate.

**Net effect on fixtures:** the `mal-cor002` fixture places the escalation 5s
after the injection — well inside 120s — so COR-002 still fires (recall = 1.0),
while the tighter bound reduces cross-session/coincidental FP risk on real
telemetry.

---

## Decision 3 (supporting) — `COR-005` scoped to injection→exfil without escalation

**Rule:** `INJECTION_THEN_EXFIL_RULE` (COR-005), `window_seconds = 180`.

The `mal-cor005` fixture (injection followed by network-egress exfil, no
process spawn) is ground-truthed to fire **only** COR-005, not COR-002, because
`_is_privilege_escalation` is not satisfied. This is asserted in the harness and
kept COR-002's precision at 1.0 (no spurious fire on the injection→exfil path).
It documents why COR-002 and COR-005 are separate rules rather than one broad
"injection then anything" rule: separating them keeps each rule's tactic/technique
mapping precise (T1059/Privilege-Escalation vs T1567/Exfiltration).
