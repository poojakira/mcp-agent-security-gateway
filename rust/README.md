# Rust port of the MCP stdio proxy inspection core (Gap 5)

This crate re-implements the **security-critical decision logic** of the Python
`src/mcp_monitor/proxy/stdio_proxy.py` (`inspect_message`) in Rust, to
demonstrate systems-programming capability and a memory-safe, dependency-light
enforcement core.

## Verification status

**Current-head status: consult the exact-source manifest linked from [docs/EVIDENCE.md](../docs/EVIDENCE.md).** No native result is inferred from the Python suite. Earlier documentation reported 9 tests passing in a containerized `rust:1-slim` toolchain, but did not supply a source-scoped run manifest here. That report is historical, not a current result. The Python workbench does not use this native port. Use the build commands below from this directory with an explicitly pinned/reviewed toolchain, capture exact source/versions/output, and record the real outcome before claiming parity. Container image tags can change.

## Parity with the Python implementation

The Rust source intends to reproduce these selected Python inspection semantics:

| Input | Python `inspect_message` | Rust `inspect_message` |
|---|---|---|
| Malformed JSON | BLOCK `malformed_jsonrpc` | BLOCK `malformed_jsonrpc` |
| Duplicate object keys | BLOCK (`_unique_json_pairs`) | BLOCK (`has_duplicate_keys`) |
| Empty batch `[]` | BLOCK | BLOCK |
| Non-object (e.g. `42`) | BLOCK | BLOCK |
| Non-`tools/call` method | ALLOW (pass-through) | ALLOW |
| Benign `tools/call` | ALLOW | ALLOW |
| Injection in args | BLOCK with patterns | BLOCK with patterns |
| Detector throws | INDETERMINATE (fail closed) | INDETERMINATE |
| Batch, one bad member | BLOCK all (atomic) | BLOCK all (atomic) |

Nine unit tests in `src/lib.rs` assert each row above.

## Build / verify runbook

On any machine with a stable Rust toolchain (`rustup` recommended):

```bash
cd rust
cargo build            # compiles lib + bin
cargo test             # runs the 9 parity unit tests — expect: test result: ok. 9 passed
cargo clippy -- -D warnings   # optional lint gate
```

Smoke-test the binary against NDJSON on stdin:

```bash
printf '%s\n' '{"method":"tools/call","id":1,"params":{"arguments":{"q":"ignore previous instructions"}}}' \
  | cargo run --quiet
# -> {"decision":"block","reason":"Prompt injection detected: ignore previous", ...}
```

After execution, preserve a source-scoped external manifest with commands, toolchain and actual outcomes. Do not infer complete proxy/transport parity from these unit cases.

## Scope (intentional)

Ported: JSON-RPC parsing, duplicate-key rejection, batch atomicity, the
allow/block/indeterminate decision, and a pluggable `Detector` trait. Not ported:
the downstream subprocess transport, rate limiter, and async runtime — those are
orchestration, not the security decision, and are covered by the Python tests.
