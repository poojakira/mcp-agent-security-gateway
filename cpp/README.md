# C++ port of the MCP stdio proxy inspection core

This directory re-implements the **security-critical decision logic** of the
Python `src/mcp_monitor/proxy/stdio_proxy.py` (`inspect_message`) in C++17,
alongside the Rust port in [`../rust`](../rust). It demonstrates a native,
dependency-light enforcement core with an explicit, auditable duplicate-key
rejection path.

## STATUS: VERIFIED via containerized toolchain

At the original verification checkpoint, the host had no local C++ toolchain,
so the code was compiled and tested inside
the official `gcc:13` Docker image:

```
docker run --rm -v "${PWD}:/work" -w /work gcc:13 sh -c "make test"
```

Recorded evidence:
- `make test` compiles `tests/test_inspect.cpp` with `-Wall -Wextra -Wpedantic`
  (no warnings) and prints **`11/11 checks passed` / `test result: ok`**.
- CMake path also verified: `cmake -S . -B build && cmake --build build && ctest`
  reports **`100% tests passed, 0 tests failed out of 1`**.

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

## Serializer remediation verification, October 12, 2026

The auxiliary NDJSON driver previously inserted reasons and pattern names into
JSON without escaping quotes, backslashes or control characters. A quoted method
name reproduced an invalid JSON response. The proposed patch uses one JSON
quoting function in the driver and inspection-value serializer.

Local g++ C++17 compilation with `-Wall -Wextra -Wpedantic` passed. All **11**
existing inspection assertions passed, along with **2** Python unittest methods
covering response string roundtrips and malformed/injection decisions. Independent
review also checked every ASCII byte through the quoting function. Run the new
standalone checks with `python3 cpp/tests/test_serializer.py`; its only compiler
requirement is g++. The dedicated PR workflow runs these checks without accessing
credentials, Python gateway workloads, telemetry or the external pilot.

At the initial serializer checkpoint, the parser retained raw `\uXXXX`
escape text rather than decoding Unicode; number grammar, Unicode parsing,
parser-depth limits and broader Python/Rust parity remained separate review work.
No gateway deployment or Cerberus pilot capability is established by these tests.
The older Docker/CMake results above remain historical evidence.

## Parser remediation verification, October 13, 2026 UTC

Standalone reproductions found that escaped `tools/call` method names bypassed
tool inspection, escaped injection text evaded the sample detector, and escaped
duplicate keys were not recognized as duplicates. Invalid number grammar,
unescaped controls and malformed Unicode/UTF-8 were accepted. These paths now
decode and validate Unicode before method/key comparisons and inspection,
validate JSON number grammar, and reject nesting beyond **64 containers**. A
valid request after a rejected deep request remains processable. Parsed number
spellings are preserved for detector input rather than rounded on serialization.

Local strict g++ C++17 builds passed with `-Wall -Wextra -Wpedantic -Werror`.
All **7 parser unittest methods**, **2 serializer methods**, and **11 original
C++ assertions** passed. Independent review reran those checks and **39** additional
valid/invalid Unicode, number and syntax cases. Run the standalone tests with:

```bash
python3 -m unittest discover -s cpp/tests -p 'test_*.py'
make -C cpp test
```

Five additional address/undefined-behavior sanitizer probes passed without
diagnostics after disabling leak detection: LeakSanitizer failed under the
workspace's process tracing, so leak detection is **unverified**. The dedicated
PR workflow now includes the parser suite; hosted results must be checked at the
updated PR head.

At this parser checkpoint, the checks did not establish full Python/Rust parity
or resistance to every
resource-exhaustion attack. Numeric conversion retains `std::stod` range behavior;
out-of-range numbers fail closed. Total line size/node count and quadratic
duplicate-key comparisons remained unbounded; the follow-up below adds bounds.
The 64-container limit intentionally
rejects inputs that the previous parser accepted. The sample detector remains
a small substring detector, not the full Python gateway detector. No pilot or
persistent deployment validation is implied.

## Parser resource-boundary follow-up, October 13, 2026 UTC

Additional standalone fixtures showed records above 1 MiB and documents above
65,536 values still returned ALLOW. The proposed follow-up limits a JSON message
to **1 MiB** and its complete parsed tree to **65,536 values**, in addition to
the 64-container depth limit. The driver retains at most the message cap while
discarding an oversized record through its newline, emits a BLOCK response and
continues inspecting the next record. The direct header API also checks the
untrimmed input size. Decoded duplicate keys are tracked in a hash set rather
than comparing every key with all prior ordered pairs; ordered value storage
and existing duplicate rejection remain intact.

All **10 parser unittest methods**, **2 serializer methods**, and **11 original
C++ assertions** passed locally. New cases exercise each exact limit and one
above it, oversized-line recovery, a 10,000-key valid object and a late escaped
duplicate. These limits intentionally reject larger messages that the previous
implementation accepted. They bound retained input and parsed values, not every
wall-clock or memory cost: draining an oversized stream still requires input,
and hostile filesystem/process behavior and full Python/Rust parity are outside
this standalone test scope. No general availability or production-readiness
claim is established.

Independent review reran all 12 methods and 11 assertions, plus additional EOF,
CRLF, whitespace, recovery and direct-header byte-boundary cases. Seven updated
address/undefined-behavior sanitizer probes passed without diagnostics with leak
detection disabled for the previously observed tracing limitation. Hash-set
lookup is average-case, not a guaranteed worst-case linear-time bound. The
driver counts physical record bytes excluding LF; CR is included in that cap.
