# MCP Policy-as-Code (Rego / OPA)

This directory contains [Open Policy Agent](https://www.openpolicyagent.org/)
Rego policies that express authorization and egress control for MCP
`tools/call` requests.

| File | Package | Purpose |
|------|---------|---------|
| `tool_authorization.rego` | `mcp.authz` | Default-deny tool authorization: denies dangerous/destructive tools and enforces a server allowlist. |
| `egress.rego` | `mcp.egress` | Default-deny egress control: destination host must be on the egress allowlist; blocks internal/loopback. |
| `tool_authorization_test.rego` | `mcp.authz_test` | Unit tests for the authorization policy. |
| `egress_test.rego` | `mcp.egress_test` | Unit tests for the egress policy. |

## Verifying the policies

These policies ship with Rego unit tests. To run them you need the OPA binary.

```bash
opa test policy/rego -v
```

Optional formatting / static checks:

```bash
opa fmt --list policy/rego     # report files that need formatting
opa check policy/rego          # type/compile check
```

> **UNVERIFIED here — requires opa binary.**
> The OPA binary is **not installed** in the environment where these files were
> authored, so `opa test` has **not** been executed here. Do not treat the Rego
> path as verified until you run the command above on a machine with OPA
> installed. Install via <https://www.openpolicyagent.org/docs/latest/#running-opa>
> (e.g. `brew install opa`, `choco install opa`, or download the release binary).

## Parity with the Python PDP (the verified path)

The same allow/deny logic is implemented in pure Python at
[`src/mcp_monitor/policy/policy_engine.py`](../../src/mcp_monitor/policy/policy_engine.py).
That Python Policy Decision Point (PDP) **is** covered by pytest
(`tests/test_policy_enforcement.py`) and is the authoritative, verified
enforcement path in this repository. The Rego bundle exists for portability to
an OPA-based control plane and is kept intentionally in parity:

* dangerous-tool denylist ↔ `DEFAULT_DANGEROUS_TOOLS`
* server allowlist ↔ `allowed_servers`
* egress allowlist ↔ `allowed_egress_hosts`
* reason codes ↔ `ReasonCode` (`DENY_DANGEROUS_TOOL`, `DENY_SERVER_NOT_ALLOWED`, `DENY_EGRESS_NOT_ALLOWED`, `ALLOWED`)

See [`docs/policy/POLICY_AS_CODE.md`](../../docs/policy/POLICY_AS_CODE.md) for the
verified-vs-unverified breakdown.
