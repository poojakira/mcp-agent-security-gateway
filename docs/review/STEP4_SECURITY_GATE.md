# Step 4: Production-oriented security controls (in progress)

This is a **research prototype hardening** workstream following the verified private Step 3 tests at gateway commit `7901a2c`. It does not authorize deployment, merging PR #148, real targets, or paid services.

## Current bounded change

`PolicyEngine._extract_destinations` now surfaces any **non-null** value in recognized top-level egress fields (`url`, `host`, `endpoint`, `target`). Previously, malformed or empty strings, numbers and other non-string values could be skipped and the request could pass if another candidate was allowed. The existing `_evaluate_egress` now rejects those inputs with `DENY_EGRESS_MALFORMED`.

The regression suites in `tests/test_step4_egress_validation.py` and
`tests/test_step4_nested_egress.py` cover malformed recognized fields,
nested `url`/`host`/`endpoint`/`target`/`destination` keys, list
nesting, conflicting candidates, and bounded scanning limits.
Known-key inspection can reject benign metadata. It does **not** parse arbitrary
free-form commands or tool-specific opaque destination representations, nor
does it enforce OS/network traffic or intercept redirects and DNS resolution.

## Outstanding Stage 4 gates

| Gate | Current state | Required acceptance evidence |
|---|---|---|
| Recognized egress argument shape validation | Patch prepared, CI required | Full Python matrix, Ruff, Pyright, CodeQL and Docker on exact commit |
| Nested recognized destination keys | Bounded recursive patch, CI required | Regression matrix across Python versions |
| Dynamic/opaque tool destinations | Not solved | Schema-aware tool integration and negative tests |
| Actual OS/network egress | Not solved | Controlled namespace/firewall policy, DNS rebinding and redirects verified |
| Distributed ACL/revocation | Optional authoritative checker prepared; no production integration | Simulated two-guard tests, authenticated ordered feed, real two-node test and restart rollback guard |
| Identity and tenant authorization | Not solved | Bound authenticated sessions, tenant isolation and negative spoof tests |
| Full MCP message coverage | Not solved | Protocol state-machine, multiplexing/notification stress tests |
| Detector effectiveness | Not benchmarked | Held-out attack corpus with measured precision/recall/false positives |
| Recovery and side effects | Not solved | Idempotency, crash/retry and rollback experiments with disposable resources |

A green CI result confirms only what its tests actually exercise. The original draft PR #148 stays unmerged until separately approved.

## Step 4: Optional authoritative permission checking

`ACLGuard(authority_check=...)` accepts a **trusted operator-supplied**
synchronous callback that must return a strict boolean for every
(principal, resource) pair. The local ACL must allow *and* the callback must
return the literal `True`. A denied result, malformed return, or exception
fails closed. The gateway's existing pre-forward and post-receive ACL checks
use this guard, allowing a shared authority to override an otherwise stale
local ACL snapshot. `authorized_search` excludes resources denied by the
authority from its backend pre-filter; callback errors deny the entire search.

The suite `tests/test_step4_authoritative_acl.py` models independent
in-memory ACL snapshots sharing an in-memory authority and a revocation while
the downstream response is paused. This is **simulated shared state**, not an
external authenticated decision service, distributed CDC, or durable storage.
Callbacks are synchronous and run under an in-process lock; network-backed
lookups require explicit latency bounds, authentication, timeout behavior,
and cancellation safeguards before deployment. Access can still race between
the last authorization check and response delivery, and already-executed
downstream effects cannot be rolled back.

The default ACL guard has no authority callback and retains its original
local-only semantics. No paid or external authorization service is involved.

## Step 4: Protocol and transport hardening

The proxy validates incoming JSON-RPC envelope version, method, parameter
shape, request-ID type and duplicate batch IDs **before** forwarding to tools.
It now applies downstream response-ID correlation and the configured content
detector to *all* request responses, including tool discovery, prompts, and
resources, not only `tools/call`. The JSON-RPC notification/client-response
path remains one-way and is not inspected as a server response.

The default response wait is bounded (120 seconds), and both request and
downstream response bytes are capped at 1 MiB. The native subprocess transport
also rejects overly long stdio response lines. See
`tests/test_step4_protocol_resilience.py` for bounded synthetic and local
subprocess validation.

**Limitations:** the stdio proxy does not yet implement true JSON-RPC
multiplexing, unsolicited downstream notification handling, cancellation,
session authentication, or OS-level egress blocking. An already-forwarded tool
may have caused side effects when a downstream timeout occurs. Security
detector coverage and false-positive rates must be separately benchmarked.
These safeguards are a prototype **fail-closed** baseline, not a production
service-level guarantee.
