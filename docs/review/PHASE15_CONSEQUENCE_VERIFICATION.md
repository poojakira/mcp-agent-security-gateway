> **Evidence reconciliation (2026-11-11; historical phase/snapshot):** Historical results below retain their original dates and denominators. Latest tested Phase 1–16 development SHA is `43a72c8984bf9a472b9055d4f9e84cc759f61718` ([CI](https://github.com/poojakira/mcp-agent-security-gateway/actions/runs/42971171992): 1,211 passed, 6 skipped per Python version), **not** a merged or production-approved release. Offline research tests require no paid provider or provider-issued API keys; deployed HTTP authentication and unverified real credential revocation remain separate. See [operating restrictions](../../PRODUCTION.md) and [release evidence](../../docs/review/PHASE1_16_RELEASE_CANDIDATE_NO_GO_20261110.md).

# Phase 15 — Independent consequence verification

> **Evidence boundary (2026-11-09):** Lost acknowledgments and observed file state are tested in a local bounded adapter; an `UNKNOWN` outcome cannot be inferred away from a returned response or journal entry. [Production release gate](../../docs/review/PHASE13_RELEASE_READINESS.md): **NO-GO**. [Integration candidate](https://github.com/poojakira/mcp-agent-security-gateway/pull/167): draft, unmerged.
**Scope:** disposable first-party MCP manifest adapter, synthetic operator approval, trusted local observer, no API keys, no paid service. **Production release: NO-GO.**

## The question this phase answers

A downstream MCP server may apply a permitted side effect, then its success response may be dropped, blocked, delayed or lost. A JSON-RPC error, lost acknowledgment or successful CI assertion cannot establish the actual consequence. The gateway's Phase 11 journal conservatively records `UNCERTAIN` before dispatch and denies duplicate keys; it does not reconcile the world.

For a precisely bounded protected `package.json` change, Phase 15 adds **independent, read-only postcondition observation** that never accepts the MCP result as evidence of its file state. The trusted observer runs outside the protected subprocess and receives a preflight snapshot and an independently operator-approved exact package/version change, not request-controlled filesystem paths.

## Outcome classification

| Observation | State | Permitted automatic action |
|---|---|---|
| File is byte-identical to preflight snapshot | `VERIFIED_NO_EFFECT` | Record evidence; **do not automatically retry** |
| File changed only to exact approved semantic postcondition | `VERIFIED_EFFECT` | Record evidence; **do not automatically replay** |
| File is present but has unrelated or unauthorized changes | `UNEXPECTED_EFFECT` | Halt and escalate |
| File missing, invalid JSON, symlink, duplicate JSON keys, bad inode or observation unavailable | `INDETERMINATE` | Halt and escalate |

The observer additionally rejects a preflight package version mismatch, missing operator approval, malformed file, hardlinked manifest, and excessive file sizes. A `VERIFIED_EFFECT` classification proves the observed file content matches the configured approved postcondition. **It cannot prove which actor caused the change, absence of other external side effects, or trustworthy operator context**.

## Real lost-ACK experiment

1. Bootstrap a fresh SQLite effect journal and reserve one operator-named operation key before dispatch.
2. Snapshot the disposable manifest independently.
3. Launch the actual first-party MCP server as a subprocess. Send a real, allowed dependency update over MCP stdio.
4. Deliberately discard the returned acknowledgement, simulating a gateway/client response loss.
5. Independently read the on-disk manifest. Verify its exact approved postcondition.
6. Restart a new journal instance: the same operation remains `UNCERTAIN`; duplicate key re-dispatch fails closed; no automatic replay is attempted.

This deliberately **does not** call `mark_completed` solely because the observer sees the effect. A trusted human/operator reconciliation procedure with durable evidence and appropriate authority is required before changing the journal state. Phase 16 revocation-safe execution must not assume that observation alone authorizes a retry.

## Executable evidence

- `src/mcp_monitor/protocol/consequence_verifier.py`: minimal independent read-only manifest observer.
- `tests/test_phase15_consequence_verification.py`: actual MCP subprocess, lost acknowledgment, persistence/restart refusal to retry, no-effect, exact effect, unexpected change, missing file, symlink, duplicate-key and preflight mismatch tests.
- `.github/workflows/phase15-consequence-verification.yml`: Python 3.10–3.12, Ruff, Phase 11 durable journal regressions, Phase 14 real-protected adapter regressions, and rebuilt offline protected Docker image/effect checks.

## Exit scope

**Phase 15 can be marked complete for this declared bounded laboratory consequence-observation problem only after green CI on the exact committed source.** It does not prove host power-loss durability, downstream exactly-once semantics, cross-host reconciliation, remote or arbitrary MCP side effects, causal attribution, agent-proof credential authorization, or revocation-safe execution. An attacker with host filesystem access or operator privileges is outside the trusted-observer model.

Phase 14 is a validated standalone Docker laboratory demonstration, not a production security certificate. Phase 16 remains a separate dependent milestone. PRs remain drafts/unmerged until reviewed; no production environment is changed.
