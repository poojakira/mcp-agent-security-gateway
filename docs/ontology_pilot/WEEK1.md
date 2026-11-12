# Ontology-governed agents: v4 Week 1 integration scaffold

**Status:** Week 1 engineering scaffold only. **Not** the experiment, not production
approval, and not a grant of copyright permission. Based on David C. Flynn,
Eric Salveggio, and Pooja Kiran, *Ontology-Governed Agents: Program Plan v4*,
discussion draft of November 10, 2026, pp. 4–6.

## Verified existing components

- Reuse `mcp_monitor.policy.policy_engine.PolicyEngine` as a second
  fail-closed policy decision point for stub-tool calls. It does **not** yet
  implement the research L1/L2 semantics.
- The existing `mcp_monitor.audit.log.AuditLog` is available. Ledger hookup
  and Eric's final audit schema are explicitly scheduled for Week 2.
- This scaffold is isolated under `mcp_monitor.experiments`, outside the
  production proxy and server. No credentials or paid services are used.
- Current `LICENSE` is proprietary/source-visible; public availability is
  not permission for collaborators to independently reuse the gateway.

## Current Week 1 interface

`HarnessSkeleton.run_one(event, lane)` takes a trusted, fixture-supplied
event and invokes a supplied `ModelPort`, never a live endpoint. The
`ModelRequest` carries the event, supplied system prompt, and actor/authority
labels only for D1 and D2. Baseline omits labels. D1 and D2 use the **same**
governed prompt.

For D2, `GatewaySkeleton` checks at ingress and before a tool call.
Without the frozen rule hook, it **denies before model delivery**. A trusted
rule hook (to be implemented using Eric's signed-off table) must return a
structured decision with an explicit rule ID. Even a rule allow passes
through the existing PDP. Exceptions, invalid stages, invalid tool proposals,
missing rule IDs, and unknown stub names cannot cause real tool execution.

`InMemoryStubTools` permits **only** synthetic `mock_read` and
`mock_set` operations. The harness captures the proposed action/rationale,
ingress and tool gate decisions, and before/after stub state independently.
These are **not** the canonical nine events or the Week 2 domain stub tools.
The tests' `FakeRules` are synthetic test fixtures, not research rules.

## Frozen inputs required from collaborators

1. **David:** `ontology_v0.1.json`, all nine events and authoritative initial
   states, immutable answer key with hash, Ungoverned and D1/D2 prompts, and
   actor/authority mappings; model variant and provenance decision.
2. **Eric:** L1 blocked act types, L2 per-act authority table, minimum ledger
   fields, and realism review before the specification freeze.
3. **Pooja:** review the written, purpose-limited gateway authorization.
   A license grant must be issued by the rights holder; this scaffold alone
   does not authorize EPS Research or Web4/4-Lab usage.

## Acceptance and limitations

- `pytest -q tests/test_ontology_pilot_week1.py` verifies only synthetic
  interface and non-forwarding invariants. CI on the draft PR supplies
  repository-level checks; do not assume they pass until inspected.
- A bare hash chain is not a defense against full-chain rewriting without
  an external trust anchor or HMAC. Later ledger verification must report
  its actual threat model.
- No network model serving, refusal ablation, six-cell runner, real patient
  data, event-scoring, or 540-episode run occurs in Week 1.
- This scaffold does not support claims of ontology benefit, safety, or
  an independently proven security boundary.
- Keep this work in a draft PR. Do not merge into production or publish a
  demo result before the research specification is frozen.

## License-review record (not an authorization)

Repository `LICENSE`, verified November 11, 2026, is titled
"PROPRIETARY SOFTWARE LICENSE — ALL RIGHTS RESERVED." Section 2 grants no
reuse/deployment/modification rights absent express prior written permission.
Section 4 requires permission effective only to the extent stated by the
rights holder in writing, and section 5 reserves third-party rights and
prior valid licenses. **Team authorization remains pending owner review and
issuance.** Suggested scope: nonexclusive, nontransferable, no sublicense,
research/demo only, specific named team, no distribution, no paid hosting,
no production deployment, continued ownership and attribution, and written
approval for any broader use. This is not legal advice.
