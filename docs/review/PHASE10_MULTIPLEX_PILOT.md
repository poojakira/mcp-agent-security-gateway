> **Evidence reconciliation (2026-11-11; historical phase/snapshot):** Historical results below retain their original dates and denominators. Latest tested Phase 1–16 development SHA is `43a72c8984bf9a472b9055d4f9e84cc759f61718` ([CI](https://github.com/poojakira/mcp-agent-security-gateway/actions/runs/42971171992): 1,211 passed, 6 skipped per Python version), **not** a merged or production-approved release. Offline research tests require no paid provider or provider-issued API keys; deployed HTTP authentication and unverified real credential revocation remain separate. See [operating restrictions](../../PRODUCTION.md) and [release evidence](../../docs/review/PHASE1_16_RELEASE_CANDIDATE_NO_GO_20261110.md).

# Phase 10 — Bounded MCP stdio multiplexing and cancellation (pilot)

> **Integration-documentation review (2026-11-09):** The stdio multiplexing pilot intentionally implements a subset of MCP/JSON-RPC behavior, not complete Streamable HTTP, notifications, cancellation rollback or full protocol interoperability. The development integration is [draft PR #167](https://github.com/poojakira/mcp-agent-security-gateway/pull/167), **not a production-approved release**.
Opt-in `multiplexed=True` replaces the sequential receive wait with a
single-reader request-ID broker. It permits multiple concurrent requests on
one stdio connection and dispatches responses to their correct waiting calls.

## Supported pilot properties

- Unique JSON-RPC request identifiers, bounded to at most 64 in flight.
- Separately arriving/out-of-order replies, including batches.
- Independent client notifications (no response expected).
- Client `notifications/cancelled` suppresses the active caller response;
  late results after cancellation or timeout are discarded.
- Request identifiers are not recycled within the broker lifetime. A bounded
  retirement ledger fences the entire connection when exhausted.
- Unknown IDs, duplicate responses, unexpected server requests or
  notifications, malformed JSON and send/receive errors fail closed.
- The existing gateway pre-send policy/ACL/identity checks and post-receive
  detector/response-ID validation remain on the response path.

## Explicitly unsupported

- No server-originated MCP request handlers (`sampling/createMessage`,
  elicitation, roots requests) or unsolicited notification handling.
  Those cause this pilot to close the broker rather than be forwarded.
- No progress streaming, partial updates or server-request delegation.
- No real distributed cancellation or guaranteed rollback of already
  executed downstream writes.
- No cancellation/timeout control that can guarantee stopping actions
  initiated by the downstream MCP server.
- The opt-in transport has a finite ID-retirement limit. Long-running
  production sessions require an independently designed resumption protocol.
- No genuine HTTP/SSE or Streamable HTTP MCP transport implementation.
- No paid services, real targets or production rollout; test fixtures are
  synthetic and standard GitHub-hosted CI runners are used.

The Phase 10 pilot is complete only if exact-commit cross-version CI passes.
Production protocol completeness remains an open goal.


## Verified scoped milestone

**Exact source commit:** `ff6a0c81021cec8e1924beae38ea5eea90fb29f0`.
**GitHub Actions:** [run #42541381322](https://github.com/poojakira/mcp-agent-security-gateway/actions/runs/42541381322), completed successfully, **3/3 matrix jobs passed**.

| Validation | Verified result |
|---|---|
| Python 3.10 full repository suite | **1,060 passed, 3 skipped**, 83.03% coverage |
| Python 3.11 full repository suite | **1,060 passed, 3 skipped**, 83.00% coverage |
| Python 3.12 full repository suite | **1,060 passed, 3 skipped**, 83.00% coverage |
| Focused multiplex and previously hardened protocol security tests | **56 passed** per Python version |
| Ruff lint and formatting | Passed on all three |
| Real cross-transport multiplex / streaming / server-originated request support | Not implemented |
| Paid services / production deployment | None |

The verified code implements a single-reader, bounded **opt-in** stdio
response broker. It rejects unsolicited server-originated messages and
does not implement the full MCP protocol or Streamable HTTP. Cancellation
quarantines response IDs but does NOT undo effects already executed by tools.

**Phase 10 bounded stdio multiplexing pilot: COMPLETE and VERIFIED.**
**Production/full MCP protocol gate: OPEN.**
