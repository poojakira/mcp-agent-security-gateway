# Operating Contract and Production Release Restrictions

> **Status: PRODUCTION NO-GO.** This is a target operating and acceptance contract, **not evidence that a production service exists**. Current development and experimental results are recorded in [PR #167](https://github.com/poojakira/mcp-agent-security-gateway/pull/167) and the [release-readiness gate](docs/review/PHASE13_RELEASE_READINESS.md).

## System role and boundaries

The MCP Agent Security Gateway evaluates supported JSON-RPC/MCP requests using configured authorization, policy, inspection and audit components. Some paths return inspection decisions for an integrating client to enforce; others proxy a bounded subset of tool calls. The service does not intercept direct OS/network access and does not guarantee that every client reaches the gateway.

The HTTP inspection service, stdio proxy, offline identity pilots and protected first-party server have **different security properties**. No optional pilot should be presented as a universally enabled production control.

## Mandatory release gate

All applicable lint, type checks, regressions, vulnerability scans, dependency provenance checks, container builds and disposable integration smoke tests must pass on the **exact promoted commit**. That is necessary but not sufficient. Promotion also requires documented and independently verified:

1. Trusted client/tenant identity, policy authorization and revocation for every supported entry point, including restarts and concurrent requests.
2. Non-bypassable routing and real outbound host/IP/port/DNS/redirect restrictions in the intended deployment.
3. Crash/timeout/lost-acknowledgment effect reconciliation with durable, trusted operation-key custody and explicit `UNKNOWN` outcomes.
4. A versioned MCP protocol/transport/method matrix with negative and interoperability tests.
5. Representative independent benign/adversarial validation with reported limitations and false-positive costs.
6. Dependency/image provenance, license and SBOM review, secret scans, container and host restrictions, audit failure behavior and incident/rollback exercises.
7. An exact-SHA release manifest, signed-off residual-risk register and **explicit accountable human authorization**.

Until these gates are closed, the decision remains **NO-GO**, even if a workflow named `Production Gate` reports success.

## Configuration and operations

- Require fresh, operator-controlled authentication material. Reject known retired demonstration credentials and missing required production settings.
- Do not put secrets in Git, sample Compose configurations, CI source or runtime logs; use a protected secret facility where deployed. A local lab key is not evidence of trusted identity.
- Bind local development service ports to loopback. This is *not* a production perimeter or authenticated proxy.
- Default to the network socket peer for source attribution; accept forwarded addresses only from explicitly trusted, sanitizing proxies.
- Treat logs, W3C trace context, SIEM exports, WAL and hash-chained audit entries as supporting evidence with bounded trust. Verify durability, access controls and log-failure handling separately.
- Keep immutable artifact identifiers, reproducible builds, reviewable configuration, rollback and documented incident procedures.
- Never claim SLOs, live uptime, SOC effectiveness, global detector precision/recall, exactly-once side effects or broad sandbox isolation without measured deployment evidence.

## Development verification and evidence

See [RUNBOOK.md](RUNBOOK.md) for local exercises, [THREAT_MODEL.md](THREAT_MODEL.md) for attacker assumptions, [VERIFIED_METRICS.md](VERIFIED_METRICS.md) for dated October baseline measurements and [release gate](docs/review/PHASE13_RELEASE_READINESS.md) for outstanding requirements. Draft integration changes are unmerged and must be reviewed against `main`.

No production deployment, real credential revocation, independently audited environment or customer-scale acceptance is established by this document.
