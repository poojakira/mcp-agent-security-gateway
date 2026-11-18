# C++ port of the MCP stdio proxy inspection core

This directory re-implements the **security-critical decision logic** of the
Python `src/mcp_monitor/proxy/stdio_proxy.py` (`inspect_message`) in C++17,
alongside the Rust port in [`../rust`](../rust). It demonstrates a native,
dependency-light enforcement core with an explicit, auditable duplicate-key
rejection path.

## Verification status

**Current-head status: consult the exact-source manifest linked from [docs/EVIDENCE.md](../docs/EVIDENCE.md).** No native result is inferred from the Python suite. Earlier documentation reported 11 checks passing in a containerized `gcc:13` toolchain, but did not supply a source-scoped run manifest here. That report is historical, not a current result. The Python workbench does not use this native port. Use the build commands below from this directory with an explicitly pinned/reviewed toolchain, capture exact source/versions/output, and record the real outcome before claiming parity. Container image tags can change.

## Parity with the Python and Rust implementations

| Input | Decision |
|---|---|
| Malformed JSON | BLOCK (`malformed_jsonrpc`) |
| Duplicate object keys | BLOCK |
| Empty batch `[]` | BLOCK |
| Non-object (e.g. `42`) | BLOCK |
| Non-`tools/call` method | ALLOW (pass-through) |
| Benign `tools/call` | ALLOW |
| Injection in arguments | BLOCK with matched patterns |
| Detector throws | INDETERMINATE (fail closed) |
| Batch, one bad member | BLOCK all (atomic) |

The 11 assertions in `tests/test_inspect.cpp` cover every row above (some rows
have two checks).

## Layout

- `include/mcp_inspect.hpp` — header-only core: a small self-contained JSON
  parser (security subset) that **detects duplicate keys** — the property most
  JSON libraries silently drop — plus `inspect_message` / `inspect_value` and a
  pluggable `Detector` (`std::function`). Detector exceptions map to
  INDETERMINATE (fail closed).
- `src/main.cpp` — NDJSON stdin/stdout driver (mirrors the Rust binary).
- `tests/test_inspect.cpp` — self-contained parity tests (no framework).
- `CMakeLists.txt` / `Makefile` — two build paths.

## Build / verify runbook

With a local toolchain:

```bash
cd cpp
make test          # -> 11/11 checks passed
# or
cmake -S . -B build && cmake --build build && (cd build && ctest --output-on-failure)
```

Smoke-test the binary:

```bash
make mcp-inspect
echo '{"method":"tools/call","id":1,"params":{"arguments":{"q":"ignore previous instructions"}}}' | ./mcp-inspect
# -> {"decision":"block","reason":"Prompt injection detected: ignore previous", ...}
```

## Scope (intentional)

Ported: JSON parsing with duplicate-key rejection, batch atomicity, and the
allow/block/indeterminate decision. Not ported: the downstream subprocess
transport, rate limiter, and async loop — those are orchestration, not the
security decision, and remain covered by the Python test suite.
