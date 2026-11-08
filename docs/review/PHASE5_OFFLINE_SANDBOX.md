# Phase 5 — Offline downstream MCP container isolation (pilot)

## Scope

Phase 5 starts from draft PR #149 and keeps all source changes isolated in a
new draft PR. This first gate adds a **strict opt-in Docker network-none
subprocess profile** to the Python stdio MCP gateway. It targets actual network
connections initiated by the downstream tool server, rather than merely
examining tool argument destinations.

### Operator activation

1. Independently build and inspect a known-good local MCP server Docker
   image that already contains the executable and dependencies.
2. Obtain the local image ID with \`docker image inspect --format '{{ .Id }}' IMAGE\`.
3. Run the gateway using:
   \`\`\`bash
   python -m mcp_monitor.proxy.stdio_proxy \
     --offline-sandbox-image sha256:<64-hex-local-image-id> \
     -- python -u /opt/mcp/server.py
   \`\`\`
   The command after \`--\` runs **inside** the sandbox image.
4. The server runs with a read-only root, a small writable /tmp, a non-root
   UID, no extra capabilities, no host mounts, no IPC sharing, and no network
   interface beyond container loopback. \`--pull=never\` prevents hidden
   image pulls when the image ID is missing.

No runtime path grants network egress. Tool-argument allowlists remain
independent but cannot override the container's \`--network=none\` setting.

### Evidence target (free public CI)

- Python 3.10/3.11/3.12 configuration and backward compatibility regressions.
- A disposable image on a standard GitHub Actions Ubuntu runner, with a
  synthetic local MCP-like stdio server.
- Its test attempts a TCP connection only to IANA TEST-NET-1 \`192.0.2.1\`
  from \`--network=none\`, verifies that the host root is read-only,
  and verifies the effective non-root UID and allowed loopback interface.
- No user files, customer credentials, production services or paid runner.
- CI's Docker base image pull may access a public image registry. The
  sandbox itself has no network and no image pull capability.

### Critical limits

- **Not a production identity plane:** operator configuration is not an
  authenticated session principal, and an upstream agent can still misuse
  tools allowed by existing policy.
- **No online server support in this mode:** any server requiring outbound
  HTTP, remote MCP, model calls, DNS or registry pulls cannot operate.
- **Not an all-purpose host isolation proof:** Docker daemon privilege,
  kernel isolation, image supply chain, container breakout, loopback abuse,
  host socket exposure, image-embedded tools, and post-crash process lifecycle
  remain risk areas.
- **No rollback:** an already-executed local file/database action cannot
  be undone by rejecting a response.
- **No full protocol state machine:** concurrent requests, unsolicited
  notifications and cancellation remain out of scope.
- Do not use network, host or privileged Docker flags to bypass this
  profile. No third-party production targets are authorized.

The Phase 5 production gate stays **OPEN** pending explicit identity,
distributed authorization, broader protocol/recovery and deployment
evidence. Completion of this offline pilot, even with green CI, cannot
be described as overall production readiness.


## Verified first-gate result

GitHub Actions run [#42523565469](https://github.com/poojakira/mcp-agent-security-gateway/actions/runs/42523565469)
completed successfully at commit `e52a5aa849d3a12240e53eda9655312cbc9517c0`:

- Python 3.10 / 3.11 / 3.12: **71 focused and backward-compatibility tests passed per version**; Ruff lint and formatting passed.
- Disposable **real Docker integration**: **1 test passed**. It verified no usable outbound TCP connection, only loopback network interface, effective UID 65534 and denied writes to the root filesystem.
- CI used standard GitHub-hosted runners in a public repository, not paid services.
- These tests validate the offline Docker profile only. They do not cover networked tool servers or all production workload scenarios.

**Phase 5 is in progress**. This first offline isolation gate is verified;
production identity binding, durable distributed authorization, complete MCP
protocol coverage, side-effect recovery, security benchmarking and representative
deployment acceptance tests are still open. No production deployment or merge
has been authorized.
