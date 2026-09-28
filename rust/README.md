# Rust port of the MCP stdio proxy inspection core (Gap 5)

This crate re-implements the **security-critical decision logic** of the Python
`src/mcp_monitor/proxy/stdio_proxy.py` (`inspect_message`) in Rust, to
demonstrate systems-programming capability and a memory-safe, dependency-light
enforcement core.

## STATUS: VERIFIED via containerized Rust toolchain

The maintainer's host has no local Rust toolchain, so the crate was compiled and
tested inside the official `rust:1-slim` Docker image:

```
docker run --rm -v "${PWD}:/work" -w /work rust:1-slim sh -c "cargo test"
```

Result (recorded evidence): `cargo build` finishes with **zero warnings** and
`cargo test` reports **`test result: ok. 9 passed; 0 failed`**. Re-run the
command above to reproduce.

## Parity with the Python implementation

The Rust `inspect_message` reproduces the Python fail-closed semantics:

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

When `cargo test` passes, record the output here and flip the status to VERIFIED.

## Scope (intentional)

Ported: JSON-RPC parsing, duplicate-key rejection, batch atomicity, the
allow/block/indeterminate decision, and a pluggable `Detector` trait. Not ported:
the downstream subprocess transport, rate limiter, and async runtime — those are
orchestration, not the security decision, and are covered by the Python tests.
