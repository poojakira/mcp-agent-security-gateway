# MCP Agent Security Gateway — adversarial autopsy and pre-mortem

> **Date:** 2026-11-14 UTC. **Verdict:** PRODUCTION NO-GO. **Scope:** source and CI of public `main` (`6ff6a5ab`) versus draft integration branch through `b3700883`; authorized synthetic/in-memory negative tests and project-owned, disposable GitHub Actions only. No live external target, customer environment, paid service or provider API key was exercised. **This is not an independent third-party penetration-test certificate and not proof that all bugs have been found.**

## 1. Executive findings

Two concrete weaknesses in the integration branch were reproduced through five new adversarial tests: (A) production library construction bypassed hardened CLI isolation, exact-tool allowlisting and strict MCP method checks; (B) an unauthenticated HTTP request could consume the shared protected inspection budget, causing a legitimate request to receive HTTP 429. All four expected negative assertions failed in the first live CI run. Narrow fixes were applied and the same adversarial tests subsequently passed on Python 3.10, 3.11 and 3.12. Other production requirements remain open.

| Evidence | Commit or run | Outcome |
|---|---|---|
| Baseline integrated candidate | `861a8025`, [run 42945676258](https://github.com/poojakira/mcp-agent-security-gateway/actions/runs/42945676258) | Previously green scoped CI; not a full security assessment |
| Negative-test commit | `4e96bce4`, [run 43562760797](https://github.com/poojakira/mcp-agent-security-gateway/actions/runs/43562760797) | **4 failed, 1,159 passed, 6 skipped** in Python 3.12; all four new failures independently identified |
| First remediation | `6f0ee82f`, [run 43563008682](https://github.com/poojakira/mcp-agent-security-gateway/actions/runs/43563008682) | Additional missing `os` import discovered during real CI; not accepted |
| Corrected implementation | `b3700883`, [run 43563115471](https://github.com/poojakira/mcp-agent-security-gateway/actions/runs/43563115471) | **5/5 configured jobs passed**; Python 3.11 **1,163 passed, 6 skipped**, 42 focused cases passed; same regression suite green on Python 3.10/3.12 |

## 2. Entry-point and trust-boundary inventory

1. **HTTP inspection API** (`src/mcp_monitor/production/server.py`). API-key-gated inspection decisions, health, readiness, metrics, audit/WAL and optional best-effort identity/SIEM telemetry. It **does not physically intercept downstream calls** or prove enforcement by a separate MCP server.
2. **Legacy stdio MCP proxy** (`src/mcp_monitor/proxy/stdio_proxy.py`). Source-level policy and detector before tool dispatch, plus response scanning. The strict CLI and the Python library constructor historically had different protection defaults. The direct-construction production gap is now guarded on the integration branch.
3. **Protected first-party MCP adapter** (`src/mcp_monitor/protected_repo_server.py`, `protocol/revocation_fence.py`). One preapproved local `package.json` dependency update, optionally serialized against revocation using a trusted SQLite authority. No generic shell, network, arbitrary file API or multi-host consensus claim.
4. **Offline/internal Docker adapters** (`proxy/sandbox.py`, `proxy/internal_sandbox.py`). Container restrictions and internal-network membership attestation; proxy-side destination policy, malicious daemon/host and post-attestation changes are outside the proven boundary.
5. **Data/control plane extensions** (OIDC snapshot validator, durability journal, SIEM, detector set). Each requires separate credential trust, routing, custody, replay and incident-response evidence.

## 3. Red-team findings register

| ID | Priority | Verification | Finding / consequence | State |
|---|---|---|---|---|
| SEC-01 | High | **Reproduced, corrected** | Production `StdioMCPProxy` Python constructor accepted uncontained subprocesses, no exact tool allowlist, or nonstrict MCP methods although hardened CLI required these controls. Alternate library entry path could undermine assumed enforcement. | Guards added in constructor; negative tests pass at `b3700883` |
| SEC-02 | High availability | **Reproduced, corrected for anonymous protected POST** | HTTP token bucket was charged before authentication; a synthetic unauthorized request exhausted one token, next authorized request returned `429` instead of `200`. | Preauthorization check added for protected inspection endpoints. Authenticated tenants still share a global budget |
| SEC-03 | Critical deployment gate | **Source-grounded, not exploited** | Routing through the gateway is not universal. If a client can call a tool server directly or start another privileged subprocess, the gateway may never see the request. | OPEN; prove network/process non-bypassability in intended deployment |
| SEC-04 | High | **Source-grounded, deployment untested** | Production HTTP API keys do not provide full user/tenant/tool identity and distributed revocation. Local signed session/OIDC/JWKS pilots have bounded assumptions; issuer and token custody remain external. | OPEN |
| SEC-05 | High | **Source-grounded, real egress untested** | `PolicyEngine` inspects a small set of URL-shaped argument keys; real sockets, DNS resolution, redirects, domain rebinding and the sidecar's actual outbound policy require OS/network enforcement. | OPEN |
| SEC-06 | High | **Source-grounded, fault injection incomplete** | Durable effect journal only applies to explicitly configured tools and trusted operation-key discipline. Unknown downstream results, client-supplied fresh operation keys, external side effects and cross-host failure cannot be reduced to exactly-once execution. | OPEN; preserve `UNKNOWN` outcomes |
| SEC-07 | Medium to high | **Source-grounded** | Audit chain uses unkeyed SHA-256 when `MCP_AUDIT_HMAC_KEY` is absent; `Config.validate_for_production()` does not require that key. A party able to rewrite local logs could recompute an unkeyed chain. SIEM/identity exports may fail while inspection continues. | OPEN; protect custody, require authenticated integrity and off-host evidence in production |
| SEC-08 | Medium | **Source-grounded** | Rate limiter remains one bucket across authenticated callers. A credentialed noisy client may affect others; open health/readiness plus per-header read deadlines require bounded-connection/resource-capacity testing. | OPEN |
| SEC-09 | High security efficacy | **Not independently validated** | Prompt injection, malicious tool descriptions, schema/rug pulls, encoded payloads and authorized-tool abuse cannot be proven safe through named regex signatures or small synthetic fixtures. A blocked response is not a physical undo. | OPEN: blinded end-to-end adversarial evaluation |
| SEC-10 | Medium to high | **Source-grounded** | Runtime `Dockerfile` uses mutable base tag `python:3.11-slim`; packages are resolved by index at build time. SHA-pinned offline sandbox images do not by themselves establish reproducible source-to-image provenance. | OPEN: verified digest/lockfile/SBOM and signature evidence |
| SEC-11 | Medium, hypothesis | **Requires targeted validation** | HTTP framing allows some syntactically unusual header forms and has per-line read timeouts without a demonstrated aggregate connection/concurrency cap. Differences across front proxies may create request ambiguity or slow-client exhaustion. | OPEN: protocol differential and soak tests; no exploit claimed |
| SEC-12 | High release integrity | **Confirmed branch divergence** | Public `main` contains a hardened legacy-stdio production constructor check absent from the unmerged integration branch before this review. Draft PR #167 is not a single reconciled approved release; checks at old merge commits do not certify latest source. | OPEN pending reviewed reconciliation, mergeability and exact-commit release decision |

## 4. Post-mortem: why the defects survived earlier green CI

- **CLI/API assumption mismatch:** Earlier enforcement tests predominantly checked a hardened command-line configuration; direct Python construction was not subject to the equivalent production guard. A security property was documented at one entry point but not enforced at every entry point.
- **Authentication/rate-order inversion:** The HTTP server checked the global token bucket before a protected route authenticated. Tests verified `429` behavior and API authentication separately, but not the adversarial ordering sequence.
- **Branch divergence:** Independent security repairs landed on public main while the phase integration branch remained separate. A later merge can regress protection unless both paths are compared using executable gates.
- **Green-check misinterpretation:** A workflow titled `Production Gate` checks selected code/build tasks. It is not a decision that all formal release criteria, all deployment routes and independent adversarial evidence have been met.
- **Boundary conflation:** Parsing, policy decision, downstream action, durable effect record, verified external state and auditor-visible event are six distinct observables. A success in one does not imply success in the other five.

## 5. Pre-mortem: plausible failure stories and required evidence

| Failure story | Earliest observable warning | Acceptance evidence needed |
|---|---|---|
| A developer imports the proxy library instead of its hardened CLI, bypassing required sandbox configuration. | Production-mode constructor can create unconfined transport or omitted tool allowlist. | Negative constructor tests in all exposed APIs and a release manifest enumerating entry points. First gap now tested and repaired. |
| A credentialless client repeatedly posts malformed or unauthorized inspections and deprives authorized users of quota. | Authorized 429 immediately after unauthorized traffic. | Auth-first accounting, separate ingress abuse budgets and per-principal quotas; first sequence now tested and repaired. |
| A malicious tool serves persuasive instructions in `tools/list` descriptions or outputs, inducing a later legitimate tool invocation. | Model proposes unauthorized cross-tool action despite text inspection. | Independent agent-in-loop tests, schema pinning, tool authority binding and tool-layer enforcement, not a detector-only classification. |
| A write goes through on the downstream host, but the response is lost or authentication is revoked before response release. | Gateway denies the response while the file is already changed; audit/journal says `UNKNOWN`. | Trusted external-state verifier, stable operation keys, no automatic replay and explicit reconciliation. |
| A tool silently changes its network destination after the PDP reads a benign declared host. | Packet trace differs from inspected argument URL. | DNS, redirects, IP, port and direct socket fencing in the actual container/network; deny before effect. |
| An attacker or operator tampers with the local evidence ledger, then recomputes an unkeyed hash chain. | Local chain verification still passes despite altered entries. | HMAC or stronger authenticated append-only/off-host checkpointing, separate trust domain and tamper test. |
| A mutable dependency/base image changes during release after tests completed. | Rebuilt image differs from tested artifact digest. | Deterministic locks, digest pins, attestations, SBOM and approved artifact signing. |
| Security staff approve release because all workflows are green while routing, identity and egress gates remain open. | CI success is treated as deployment authorization. | Exact-SHA reviewed gate owner, explicit NO-GO/GO decision and signed residual risks. |

## 6. Test method and its limits

**Active proof:** New `tests/test_adversarial_release_regressions.py` performs five scoped negative checks without networking or executing a Docker container. The rate test uses an `asyncio.StreamReader`/fake writer and a deliberately mocked authorization result; it checks shared quota ordering, not a real public listener. Constructor tests set the local `MCP_ENV=production` string and only construct a never-started transport. First CI at `4e96bce4` reproduced exactly four failures; final tests at `b3700883` pass. Existing integration GitHub Actions also ran private-listener/sidecar source tests and the inherited Python suite. **No outside host was scanned or penetrated.**

**Existing laboratory coverage:** The repository contains tests for JSON duplicate keys, non-finite constants, malformed MCP methods and batches, response IDs, detector failures, inflight revocation, disposable filesystem MCP transport, WAL/audit persistence, Docker network identity, and consequence verification. Passing these does not guarantee all protocol implementations, operating systems, workloads or malicious runtimes.

**Benchmark qualification:** The frozen 96-case author-curated, regex-only historical exercise reports TP 40, FN 8, FP 16 and TN 32. These support fixture-scoped precision 71.4%, recall 83.3%, and benign false-positive rate 33.3%. They **do not** represent independent field performance, a held-out production population, or the effectiveness of the integrated gateway.

**Unperformed actions:** No destructive penetration of a running deployment, no cross-host crash/power-loss tests, no live OAuth issuer, no internet-scale real traffic, no provider-side secret revocation, no paid model API, no real AWS account/cloud resource and no customer data. These cannot be claimed as done.

## 7. Release decision and ordered closure criteria

**NO-GO remains in force.** Do not merge the draft integration PR or expose a production-facing MCP execution path based solely on the now-green regressions.

1. Reconcile public `main` changes against integration branch, verify every Python entry point and direct downstream route, and retain the four negative regressions as permanent gates.
2. Enforce production-grade trusted principal/tenant identity, token audience and scope restrictions, revocation freshness and exact per-tool capabilities.
3. Prove OS-level egress/mount/process constraints, actual proxy destination policy and direct-bypass resistance in the selected target deployment.
4. Execute cross-process fault injection for power loss, timeouts, duplicate keys, revocation races and immutable external-state verification; record both proposed and realized effect.
5. Run an independently annotated, legally sourced, benign/adversarial and representative evaluation: prompt injection, tool poisoning, encoded content, shadow servers, false positives and alternate transport paths.
6. Make audit key custody and off-host tamper evidence production requirements; prove SIEM failures are surfaced as degraded telemetry state.
7. Produce reproducible image/dependency provenance and cross-platform protocol interoperability evidence before explicit accountable human release approval.

## 8. Independent references

- [OWASP MCP Top 10](https://owasp.org/projects/mcp-top-10): token handling, scope creep, tool poisoning, supply chain, command execution, prompt/context injection, authentication, audit and shadow servers.
- [OWASP MCP Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/MCP_Security_Cheat_Sheet.html): untrusted tool descriptions, cross-server poisoning, confused deputy, replay and server-side least-privilege enforcement.
- [MCP 2026-07-28 specification update](https://blog.modelcontextprotocol.io/posts/2026-07-28/): contemporary protocol and authentication evolution; full protocol compliance is not claimed by this gateway.
- Exact code, tests, CI evidence and release register referenced above.

**Interpretation standard:** `reproduced` means an executable negative test observed a concrete unintended outcome at an exact code revision; `source-grounded` means the logic or missing assurance was seen in source but no operational exploit is proven; `open` means a mandatory real-world property has no sufficient validation. A zero-findings or production-safe claim is explicitly not made.
