# Local MCP execution workbench

## Product contract and acceptance

The intended user is an agent developer verifying tool permissions before integrating an MCP server. The smallest useful flow is editable user JSON -> existing authorization/injection checks -> a constrained real stdio tool -> independently observed file state -> permission change -> rerun -> redacted export. No model or cloud account is needed.

Acceptance is exercised in `tests/test_workbench.py` and `scripts/workbench_e2e.py`. Read, denied write, permitted rerun, isolated fresh state, injection, malformed message, cross-workspace path, alternate method, outbound refusal, crash, timeout, duplicate append, hostile Host/Origin, request bounds and rate limits have executable checks. The full master contract is not yet met: credential lifecycle, output PII filtering, arbitrary-server containment, durable reconciliation and complete current MCP conformance are NOT IMPLEMENTED in this local flow.

## Architecture and decision

```mermaid
sequenceDiagram
    participant User as Local browser
    participant App as Loopback HTTP server
    participant Gateway as Existing StdioMCPProxy and PolicyEngine
    participant Tool as First-party stdio child
    User->>App: POST editable JSON-RPC and exact permission preset
    App->>Gateway: initialize, list, requested operation
    alt Gateway denies
        Gateway-->>App: error; no operation forwarded
    else Gateway allows
        Gateway->>Tool: one-line JSON-RPC
        Tool-->>Gateway: actual response or process failure
        Gateway-->>App: response or uncertainty
    end
    App->>App: stop child; inspect fixed note and receipts; hash evidence
    App-->>User: report; temporary workspace removed
```

The frontend contains no detection logic. `runtime.execute` invokes the existing policy and proxy; `FixtureTransport` canonicalizes pretty editor JSON into required single-line stdio frames. The child receives a minimal explicit environment and isolated Python invocation (`-I`). The operator cannot supply an executable or root directory. No arbitrary executable or deserializer is exposed.

ADR: a stdlib, serial HTTP server avoids adding a backend framework dependency. Separate static assets permit a CSP without unsafe-inline/unsafe-eval. Processing one operation at a time bounds child concurrency. This trades throughput and rich multi-user sessions for a small maintainable local tool. Every run starts from identical synthetic note content; compare targets are separate temporary directories. The same-run repeat option intentionally exposes duplicate effects rather than promising deduplication.

## Threat model

Assets: operator host, local inputs, generated evidence, policy enforcement and tool-side state. Actors: one trusted local operator; malicious JSON, tool arguments and external websites. Trust boundaries: browser/HTTP, user input/policy configuration, proxy/tool process, tool response/evidence UI.

Controls: fixed IPv4 loopback bind; exact Host/Origin; application/json and no chunked uploads; 16 KiB body/8 KiB request/2 KiB note-change limit; 30 requests/minute; serial execution; one-second operation timeout; fixed tool inventory and exact `note.txt` path; no outbound implementation; no shell invocation; HTML output uses textContent; restrictive CSP; redacted exports; subprocess teardown and temporary-directory cleanup. User input never selects a path used by the host to open a file.

Residual risks: local OS users can access the process and temporary files; loopback access is not authentication against other local processes. A trusted first-party child is not OS isolation for arbitrary malicious code. The serial HTTP service can be occupied by a slow local client until its five-second socket timeout. Power loss can leave temporary data; deletion is best-effort filesystem unlinking, not secure erasure. Full response PII filtering is absent. Audit chains are unkeyed, ephemeral and not independently anchored. A hostile privileged host can rewrite receipts and logs. No internet-exposed or multi-tenant deployment is approved.

## Outcome interpretation

- `NOT_INVOKED`: no operation message was sent by the transport.
- `CONFIRMED_SUCCEEDED`: a completed non-error tool response and fixture receipt support the result; the report also shows independently read note state.
- `CONFIRMED_FAILED`: the first-party tool produced an explicit failure; receipts may show it was invoked.
- `UNKNOWN / REQUIRES_RECONCILIATION`: a forwarded request lacks sufficient confirmation, including actual crash/timeout. No automatic successful retry is inferred.

The authorization decision is distinct from injection checks and final outcome. A policy ALLOW does not itself prove execution. External provider exactly-once contracts, durable side-effect journals, cancellation and recovery across host crash remain absent.

## API and operations

`GET /` serves the workbench. `GET /health` reports software version 0.1.0, the exact package checkout's Git commit and CLEAN/DIRTY status when available, and protocol subset 2025-03-26. An installed wheel reports source commit UNKNOWN, including when its environment is inside another Git repository; deployment builds must supply traceable source packaging before release. Configuration evidence includes repeat count, effective tool allowlist and protocol version, so one and two deliveries have distinct configuration hashes.

`POST /api/execute` requires Content-Type exactly `application/json` and a declared body up to 16384 bytes:

```json
{"request":"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"read_note\",\"arguments\":{}}}","preset":"read-only","guarded":true,"repeats":1}
```

Allowed presets: `read-only`, `read-write`. `guarded=false` substitutes the read/write allowlist; other controls stay enabled. `repeats` is 1 or 2. Unknown payload fields fail closed. Errors: 400 invalid payload, 403 peer/Host/Origin, 404 route, 413 bytes, 415 content framing/type, 429 rate limit, 500 engine failure. A valid request can return HTTP 200 with an error/unknown outcome; inspect the outcome and response rather than treating HTTP success as tool success.

No inputs leave the machine. Raw request/response/note stay in browser memory and transient process memory; the temporary workspace is deleted before normal response completion. Download exports omit those content fields and retain metadata, hashes, receipts and a synthetic unkeyed audit entry. Check exports before sharing because tool names and trace metadata remain.

Startup: `python -m mcp_monitor.workbench` (default port 8761), optional `--port NUMBER`; no bind-host override. Shutdown: Ctrl+C, which stops accepting requests; current serial execution completes before handling interrupt. No persistence migration or backup is required. Rollback: check out the prior reviewed commit and reinstall; no default branch history is rewritten. Do not adapt this server for public hosting.

## Developer checks and adversarial review

See README commands. Full regression includes existing engine tests; focused workbench checks use actual subprocesses, not FakeTransport. Browser tests use the real backend, compare identical request hashes, assert tool-side receipt/state, and validate export redaction. Supply-chain tooling, complete legacy documentation reconciliation, arbitrary-platform testing and container release validation are separate outstanding gates.

Autopsy: pretty-printed JSON initially reached the newline-delimited stdio transport as multiple lines and crashed the fixture server. The cause was editor/wire framing mismatch. FixtureTransport now serializes the already-validated message to one line; `test_pretty_printed_editor_json_uses_single_line_stdio_frame` reproduces that defect and requires an actual completed read. Browser tests also use locator assertions, keeping CSP enabled. No security check was weakened to fix either issue.

Independent review found three further evidence defects: Python 3.10 raises `asyncio.TimeoutError` rather than the later built-in alias; an installed wheel could inherit another repository's commit; and repeat count was absent from the configuration hash. The runtime now catches the cross-version exception, accepts Git provenance only from a tracked editable-source checkout with explicit CLEAN/DIRTY status, and hashes the complete exposed execution configuration. Real-process repeat tests and temporary Git repository regressions cover these failures. A receipt without a completed response still produces UNKNOWN.

The strongest counterargument remains that a controlled offline fixture does not prove security for arbitrary MCP tools. The UI and exported limitations state that scope explicitly. The advanced branch's independent image gate failure remains unaddressed by this candidate, which does not merge that branch.

## Acceptance status matrix

| Contract area | Implementation / executable evidence | Remaining limit |
|---|---|---|
| Browser request, permission change, same-input rerun | `runtime.execute`, `test_policy_change_same_request_and_fresh_target`, browser harness | Fixed first-party target only |
| Tool-side outcome and export | Actual subprocess receipts/state; browser export checks | No external provider evidence or independently anchored log |
| Authorized read / denied write | Actual subprocess integration tests | No arbitrary real host filesystem |
| Cross-workspace attempt / alternate path | Fixed-path refusal and strict proxy methods tests | No multiple authenticated users |
| Untrusted prompt injection | Existing detector inspects supplied context; real denial test | Indirect tool-output injection is NOT IMPLEMENTED |
| Outbound destination / malformed input | Existing policy egress denial and proxy parser tests | No networked tools provided |
| Rate limiting | Local HTTP 429 test; existing proxy limiter regression | No public abuse protection claim |
| Crash / timeout / duplicate effects | Actual child termination and repeated append tests | Durable replay/reconciliation is NOT IMPLEMENTED |
| MCP initialize/list/call | Real stdio transcript with clientInfo/capabilities | Full conformance, cancellation/concurrency and latest version NOT VERIFIED |
| Sensitive output / credential lifecycle | Explicit UI limitations | PII filtering, invalid/expired/revoked identity NOT IMPLEMENTED |
| Independent release and branch hygiene | Candidate branch; baseline refs preserved | Exhaustive docs/branch consolidation and deployment signoff remain BLOCKED |
