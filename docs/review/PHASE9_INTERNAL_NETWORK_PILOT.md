> **Evidence reconciliation (2026-11-11; historical phase/snapshot):** Historical results below retain their original dates and denominators. Latest tested Phase 1–16 development SHA is `43a72c8984bf9a472b9055d4f9e84cc759f61718` ([CI](https://github.com/poojakira/mcp-agent-security-gateway/actions/runs/42971171992): 1,211 passed, 6 skipped per Python version), **not** a merged or production-approved release. Offline research tests require no paid provider or provider-issued API keys; deployed HTTP authentication and unverified real credential revocation remain separate. See [operating restrictions](../../PRODUCTION.md) and [release evidence](../../docs/review/PHASE1_16_RELEASE_CANDIDATE_NO_GO_20261110.md).

# Phase 9 — Internal network boundary and trusted egress sidecar (pilot)

> **Evidence boundary (2026-11-09):** The isolated internal Docker network and synthetic sidecar do not proxy real online traffic or enforce DNS, redirect, CIDR or internet access policy. [Production release gate](../../docs/review/PHASE13_RELEASE_READINESS.md): **NO-GO**. [Integration candidate](https://github.com/poojakira/mcp-agent-security-gateway/pull/167): draft, unmerged.
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

**Milestone verdict:** COMPLETED for the scoped internal-network isolation pilot. **Production secure online egress: OPEN.**
No paid services, private runner, external test targets or production
deployment. All preceding PRs remain draft and unmerged.

## Verified CI evidence

**Exact tested source commit:** `a075860545bccd9635892cbe7904836fc4bc13cb`.
**Actions run:** [#42539490251](https://github.com/poojakira/mcp-agent-security-gateway/actions/runs/42539490251), completed successfully (**4/4 jobs**).

| Validation | Result |
|---|---|
| Python 3.10 complete suite | 1,046 passed, 3 skipped; 82.94% coverage |
| Python 3.11 complete suite | 1,046 passed, 3 skipped; 82.91% coverage |
| Python 3.12 complete suite | 1,046 passed, 3 skipped; 82.91% coverage |
| Focused network-attestation tests | 19 passed per Python version |
| Real Docker internal bridge and local sidecar | 1 passed |
| Ruff lint and formatting | Passed |
| Actual allowlisted HTTPS CONNECT and DNS/redirect defense | **Not implemented or tested** |
| Production deployment / paid service | None |

This validates launch-time bridge attestation, direct outbound denial and
local synthetic sidecar connectivity. It does not prove that a *real* proxy
enforces allowed destinations, nor does it test DNS rebinding, TLS, internet
traffic, live network membership drift or host-container escape.

**Phase 9 network topology pilot: COMPLETE. General secure online egress
and the production Phase 9 gate: OPEN.**
