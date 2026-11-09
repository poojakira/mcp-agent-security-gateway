# Phase 10 — Bounded MCP stdio multiplexing and cancellation (pilot)

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
