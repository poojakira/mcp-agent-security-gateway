# Phase 9 — Internal network boundary and trusted egress sidecar (pilot)

Phase 9 first milestone adds a **restricted network attachment mode** for MCP
stdio tool servers without trusting agent-supplied URL or tool schema fields.

## Implemented controls

- Use a dedicated Docker `--internal` bridge with IPv6 disabled.
- Before launching the server, inspect the bridge by **immutable Docker
  network ID**, requiring an internal local bridge and exactly one attached
  container matching the operator-pinned proxy **container ID and name**.
- Start the untrusted MCP server with a separate pinned image, read-only root,
  non-root UID, no added capabilities, no privileged mode or Docker socket
  mounts, and bounded CPU/memory/PIDs.
- Supply fixed HTTP(S) proxy environment values for the *trusted sidecar*.
  An agent that ignores the proxy variables cannot route directly to the
  external network on an internal-only bridge.
- Reject absent, changed, externally routed, IPv6-enabled or multi-tenant
  network configurations. Failure to inspect Docker does not fall back to
  launching the process on the host.
- Reuse Phase 5 normal-stop container force-removal and verification.
- Negative unit tests and a **real disposable Docker test** using a synthetic
  HTTP-only sidecar (which never forwards outside the test network).
  The server can contact the local sidecar but fails to open a socket to the
  documentation-only IANA `192.0.2.1` target.

## Important security and functionality limits

**The first sidecar is NOT a production egress security proxy.** It replies to
a local synthetic health request and cannot connect to internet endpoints.
This milestone tests *network confinement and proxy topology*, not allowlist
enforcement or real remote service access. The next gate requires a trusted
CONNECT proxy with a strict allowlist, restricted ports, DNS/IP validation,
redirect resistance and independent security tests. Do not substitute a
generic unrestricted HTTP proxy or connect this isolated bridge to other
containers.

Docker bridge inspection is a startup snapshot, not a permanent guarantee
that privileged operators or a compromised Docker daemon cannot attach
another container later. The gateway host and Docker daemon are outside this
sandbox. The policy must eventually monitor membership/drift and fail
closed on a detected change. IPv6 networking, production HTTPS inspection,
operator identity management, secure DNS, real IdP integration, side-effect
recovery and resilience still require separate acceptance evidence.

**Milestone verdict:** pending CI. **Production secure online egress: OPEN.**
No paid services, private runner, external test targets or production
deployment. All preceding PRs remain draft and unmerged.
