# Phase 5 — Offline MCP containment verification and exit assessment

> **Evidence boundary (2026-11-09):** The Docker containment results are bounded to offline, disposable fixtures and do not show resilience to kernel, daemon, privileged host or arbitrary power-loss failures. [Production release gate](../../docs/review/PHASE13_RELEASE_READINESS.md): **NO-GO**. [Integration candidate](https://github.com/poojakira/mcp-agent-security-gateway/pull/167): draft, unmerged.
**Scope:** The opt-in **offline** downstream MCP Docker containment pilot.
**Draft PR:** [#151](https://github.com/poojakira/mcp-agent-security-gateway/pull/151), stacked on Step 4 draft PR #149, which in turn depends on draft PR #148.
**Production security gate:** **OPEN**. This assessment is not a production approval.

## Verified engineering work

1. A strictly opt-in `OfflineDockerSandbox` that runs downstream MCP stdio servers in a separately launched Docker container.
2. Preloaded content-addressed image digest or image ID required; `--pull=never` prevents fallback registry pulls during runtime.
3. Explicit local Docker daemon via `unix:///var/run/docker.sock`, Docker `--network=none`, `--read-only`, `--cap-drop=ALL`, `--security-opt=no-new-privileges`, `--ipc=none`, UID 65534, bounded CPU/RAM/PIDs, small writable temporary filesystem.
4. Host-process fallback prevented when Docker is missing; tests confirm invalid configuration fails closed.
5. A cryptographically random, separately tracked container name and an explicit force-removal and post-removal query during normal shutdown; cleanup failure raises an error.
6. Synthetic **real Docker** integration checks that the sandbox process cannot connect to IANA TEST-NET-1 `192.0.2.1`, sees only loopback, cannot write to the root filesystem, runs as UID 65534, does not inherit a synthetic host secret, and leaves no named container behind after normal shutdown.
7. Full Python regression suite plus Ruff lint and formatting checks on Python 3.10, 3.11, and 3.12.

## Reproducible CI evidence

**Exact verified source commit:** `97236be89a3989cecfe92b6a324fae3ca07a5876`.

**GitHub Actions:** [Run #42526952330](https://github.com/poojakira/mcp-agent-security-gateway/actions/runs/42526952330): **completed, success (4/4 jobs)**.

| Check | Result |
|---|---|
| Python 3.10 complete tests | 953 passed, 2 skipped, 82.55% coverage |
| Python 3.11 complete tests | 953 passed, 2 skipped, 82.52% coverage |
| Python 3.12 complete tests | 953 passed, 2 skipped, 82.52% coverage |
| Phase 5 focused + Step 4 regressions | 77 passed per Python version |
| Ruff lint and formatting | Passed across three Python versions |
| Real isolated Docker integration | 1 passed |
| Public-repo GitHub hosted runner | Standard Ubuntu; no paid service or private Actions runner |

The Docker test uses a disposable synthetic server and a TEST-NET destination only. No production hosts, customer credentials, or real-world targets were exercised.

## Scope exit decision

**Offline sandbox prototype milestone: COMPLETE and CI-verified.**

**End-to-end production security certification: NOT COMPLETE.** These risks remain open:
- Actual authenticated user/session/tenant identity and trust binding.
- Durable authenticated distributed ACL revocation, failure recovery and restart synchronization.
- Full MCP multiplexing, notifications, cancellation and streaming transports.
- Online tool networking, including genuine constrained egress/DNS/redirect handling (the offline profile intentionally blocks all external networking).
- Response timeout or crash recovery, idempotency and effects already executed downstream.
- Held-out prompt-injection attack corpus and measured false-positive/false-negative rates.
- Container breakout, Docker daemon/socket security, image supply-chain attestation and kernel vulnerability risks.
- Representative production deployment, performance/load, failover, and CodeQL/Docker/Windows CI parity on the exact Phase 5 commit.

The offline sandbox mode is intentionally incompatible with MCP servers requiring outbound access. The gateway host and local Docker daemon are not sandboxed. Container cleanup is verified after **normal, controlled** shutdown, but not after arbitrary host power loss, kernel failures or daemon compromise.

This document does **not** authorize PR merges, production deployment or a future task. All work stays in draft branches pending explicit approval.
