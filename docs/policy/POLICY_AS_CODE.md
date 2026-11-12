> **Evidence reconciliation (2026-11-11; living reference):** Historical results below retain their original dates and denominators. Latest tested Phase 1–16 development SHA is `43a72c8984bf9a472b9055d4f9e84cc759f61718` ([CI](https://github.com/poojakira/mcp-agent-security-gateway/actions/runs/42971171992): 1,211 passed, 6 skipped per Python version), **not** a merged or production-approved release. Offline research tests require no paid provider or provider-issued API keys; deployed HTTP authentication and unverified real credential revocation remain separate. See [operating restrictions](../../PRODUCTION.md) and [release evidence](../../docs/review/PHASE1_16_RELEASE_CANDIDATE_NO_GO_20261110.md).

# Policy-as-Code & Enforcement (Gap 2)

> **Review context (2026-11-09):** Python policy decision tests and any experimental Rego bundles must be evaluated separately. Do not infer that an untested OPA policy is enabled or enforced end-to-end. The [integrated release-readiness gate](../../docs/review/PHASE13_RELEASE_READINESS.md) is **PRODUCTION NO-GO**.
This gateway expresses MCP tool-call authorization as **policy-as-code** in two
parallel implementations that are kept in parity:

1. A **pure-Python fail-closed Policy Decision Point (PDP)** — the **VERIFIED** path.
2. A set of **Rego policies for OPA** — the **UNVERIFIED (needs-opa)** path.

Both encode the same three controls:

- **Dangerous-tool denylist** — destructive/privilege-escalating tools (e.g.
  `shell_exec`, `delete_file`, `assume_role`, `drop_database`) are denied
  outright, regardless of server or egress.
- **Server allowlist** — the downstream `server_id` must be explicitly allowed.
- **Egress allowlist** — if a tool call reaches out to the network, the
  destination host must be on the allowlist; loopback/private/link-local
  destinations are blocked unless explicitly allowlisted (anti-SSRF).

The engine is **default-deny**, **deny-wins**, and **fail-closed**: malformed or
unparseable input yields a DENY, never an ALLOW.

---

## ✅ VERIFIED — Python PDP

**Source:** `src/mcp_monitor/policy/policy_engine.py`
**Tests:** `tests/test_policy_enforcement.py`

Verified in this environment with the repo venv:

```text
.\.venv\Scripts\python.exe -m pytest tests/test_policy_enforcement.py -q
...............                                                          [100%]
15 passed in 0.08s
```

Lint clean:

```text
.\.venv\Scripts\ruff.exe check src/mcp_monitor/policy tests/test_policy_enforcement.py
All checks passed!
```

### What the tests prove

The suite proves **enforcement**, not merely decision-making. A
`FakeDownstreamTransport` exposes `send`/`receive` as mocks and an
`EnforcingGateway` forwards downstream **only** on ALLOW:

- **Denied calls never reach downstream** — for dangerous tools, disallowed
  servers, disallowed egress, loopback egress, and malformed input, the tests
  assert `downstream.send.assert_not_called()` **and**
  `downstream.receive.assert_not_called()`.
- **Allowed calls do reach downstream** — `send`/`receive` are each called
  exactly once and the downstream result is returned.

Decisions are **structured** objects (`PolicyDecision`) carrying a
machine-readable `ReasonCode` (`ALLOWED`, `DENY_DEFAULT`,
`DENY_MALFORMED_INPUT`, `DENY_DANGEROUS_TOOL`, `DENY_SERVER_NOT_ALLOWED`,
`DENY_EGRESS_NOT_ALLOWED`, `DENY_EGRESS_MALFORMED`), a human message, and the
matched rule name.

---

## ⚠️ UNVERIFIED (needs-opa) — Rego policies

**Source:** `policy/rego/tool_authorization.rego`, `policy/rego/egress.rego`
**Tests:** `policy/rego/tool_authorization_test.rego`, `policy/rego/egress_test.rego`
**Docs:** `policy/rego/README.md`

These Rego policies mirror the Python PDP logic and ship with `*_test.rego`
unit tests. They **can** be verified on a machine that has the OPA binary:

```bash
opa test policy/rego -v
```

> **The OPA binary is NOT installed in the environment where these were
> authored, so `opa test` was NOT run here. The Rego path is UNVERIFIED.**
> Do not claim the Rego tests passed until `opa test policy/rego -v` is executed
> on a host with OPA installed.

---

## Files created

| File | Type | Path |
|------|------|------|
| Python PDP package init | source | `src/mcp_monitor/policy/__init__.py` |
| Python fail-closed PDP | source | `src/mcp_monitor/policy/policy_engine.py` |
| Enforcement + PDP tests | test (VERIFIED) | `tests/test_policy_enforcement.py` |
| Tool authorization policy | Rego | `policy/rego/tool_authorization.rego` |
| Egress control policy | Rego | `policy/rego/egress.rego` |
| Tool authorization tests | Rego test (UNVERIFIED) | `policy/rego/tool_authorization_test.rego` |
| Egress control tests | Rego test (UNVERIFIED) | `policy/rego/egress_test.rego` |
| Rego bundle README | docs | `policy/rego/README.md` |
| This document | docs | `docs/policy/POLICY_AS_CODE.md` |
