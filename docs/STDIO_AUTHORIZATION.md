# Stdio tool authorization (security fix, November 7, 2026)

The executable `mcp_monitor.proxy.stdio_proxy` now calls the same Python
`PolicyEngine` used by the standalone policy unit tests on **each** routed
`tools/call`, before the subprocess transport can receive the request.

## Usage

```bash
python -m mcp_monitor.proxy.stdio_proxy \
  --server-id filesystem \
  -- npx -y @modelcontextprotocol/server-filesystem /tmp

# Permit one explicitly approved network destination:
python -m mcp_monitor.proxy.stdio_proxy \
  --server-id search --allow-egress-host api.example.com \
  -- python -m approved_search_server
```

The `--server-id` is a trusted label associated with the **configured**
downstream command. It is never taken from a client-supplied `params.server_id`.
The default label is `local` for compatibility with existing launcher
configuration. Supplying a specific label is recommended.

With no custom policy, the server allowlist contains only that configured
server ID, the egress allowlist is empty, and the `PolicyEngine` dangerous-tool
denylist is active. A tool operation may also be denied by the content detector
or the rate limiter. Policy errors fail closed.

## Verified boundary

The changed path is the **stdio subprocess proxy**, not every possible MCP
transport or wrapper. The new `TestStdioAuthorizationEnforcement` tests use the
real `StdioMCPProxy.handle_message` call with an instrumented fake transport
to prove prohibited requests are not forwarded. They exercise dangerous tools,
server allowlisting, egress, policy failures and batch atomicity.

The standalone `tests/test_policy_enforcement.py` suite uses a separate fake
`EnforcingGateway`; those tests alone did **not** previously prove that the
real stdio proxy enforced the PDP.

## Remaining boundaries

- Policy decisions depend on accurately specified dangerous tool names and
  detectable destination fields. A generic URL hidden inside arbitrary nested
  arguments or an indirect DNS resolution is not exhaustively controlled.
- This is **application-layer tool authorization**, not a system network firewall
  or kernel sandbox. Explicitly allowlisted hosts do not establish DNS pinning.
- Server capabilities and tool names are determined by the subprocess that
  is configured. A malicious subprocess can act outside the proxy.
- Standalone stdio request size limits, downstream response correlation, and
  independent adversarial validation remain separate follow-up work.

## Verification instructions

```bash
python -m pytest tests/test_stdio_proxy.py tests/test_policy_enforcement.py -q
python -m ruff check src/mcp_monitor/proxy/stdio_proxy.py tests/test_stdio_proxy.py
python -m ruff format --check src/mcp_monitor/proxy/stdio_proxy.py tests/test_stdio_proxy.py
```

Until those commands complete on the fix branch, the regression tests are
**added but not independently verified passing**.
