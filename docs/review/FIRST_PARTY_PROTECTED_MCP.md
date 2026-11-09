# First-party protected repository MCP server (free local demonstrator)

The first-party server is a **real stdio MCP server** with no paid model, cloud account, OAuth provider or third-party MCP server requirement. It is a separate Python subprocess exercised through the actual `StdioMCPProxy` and independently checked via the filesystem.

## Threat model and explicit trust boundaries

- Authenticated principal: **operator of the local process**, not an independently authenticated remote user. The trusted launcher provisions `MCP_PROTECTED_REPO_ROOT` and `MCP_APPROVED_DEPENDENCY_UPDATES` and restricts who can change them. **The MCP protocol client does not authenticate a person.**
- Attacker controls MCP method names, IDs and tool arguments; may propose alternative tool names, arbitrary paths or unexpected dependency values. The agent cannot add server tools or alter the trusted environment variables through an MCP argument.
- Actual resource scope: **one fixed `package.json` under the configured absolute workspace root**. There is no arbitrary file read/write tool, no tool execution and no network client.
- Trusted enforcement: the downstream server independently checks its exact tool names, arguments, approved package/version mapping and expected pre-existing version; the gateway provides an additional policy/detector layer.
- A denied request must not modify the protected `security-policy.json`. The test asserts its SHA-256 and checks the real manifest state.
- Not guaranteed: OS sandbox containment, remote client authentication, TOCTOU resistance to a local attacker who can edit the workspace simultaneously, cryptographic intent signing, immutable manifests, atomic multi-process update ordering, full MCP transport support, or safety against a privileged actor launching the downstream process directly. Running as the repository owner still provides filesystem permissions independent of MCP. For production, use an isolated unprivileged process, read-only mounts for protected files, per-user auth, safe file-descriptor operations, durable operation reconciliation and network deny-by-default.
- Tool-response inspection remains the gateway's responsibility. A red-team prompt-injection dataset benchmark is a **separate experiment**; these tests measure resource authorization and real file effects, not measured model compromise rates.

## Run completely locally

From a clean checkout of the review branch, with Python 3.10+:

```bash
python -m pip install -e ".[dev,oidc]"
mkdir -p /tmp/protected-mcp-workspace
printf '{"name":"example","dependencies":{"safe-package":"1.0.0"}}\n' > /tmp/protected-mcp-workspace/package.json
printf '{"audit":"required"}\n' > /tmp/protected-mcp-workspace/security-policy.json
export MCP_PROTECTED_REPO_ROOT=/tmp/protected-mcp-workspace
export MCP_APPROVED_DEPENDENCY_UPDATES='{"safe-package":"1.1.0"}'
python -m mcp_monitor.proxy.stdio_proxy --server-id protected-repo -- \
  python -m mcp_monitor.protected_repo_server
```

The last command runs a long-lived MCP server over stdin/stdout; it must be launched by an MCP client or tested with the real-process harness. To run deterministic client-side checks:

```bash
python -m pytest tests/test_first_party_protected_mcp.py -q -s
```

All real file operations in CI use separate temporary directories and disposable dependency manifests. No customer repository or external service is modified. These are actual tool invocations and operating-system subprocess communication, not mocked transport responses. Dependency names and file contents are lab fixtures; do not call them an independently sourced real-world vulnerability dataset.

## Case-level verification

| Operation | Expected side effect |
|---|---|
| initialize / tools/list | Real MCP handshake and two narrow tools |
| read_manifest | Allowed manifest dependency read |
| update_dependency to operator-approved version, with matching prior version | Exactly one actual manifest change in disposable project |
| arbitrary read_file / write_file against protected security-policy.json | Denied; no file change |
| unapproved dependency version or extra path argument | Denied; manifest unchanged |
| shell command execution | Denied |
| repeated update with stale previous-version precondition | Denied |
| package.json symlink to external file | Denied, external file unchanged |

**Do not claim** this endpoint is a general file protection appliance. It only protects this one declared server contract, and does not prove that another MCP server or direct OS process is inaccessible.

## Release assessment

**Research / controlled local demonstrator only. Production NO-GO.** Every CI run must be cited by exact SHA and reported separately from independent third-party adversarial results. Do not merge or deploy by default.
