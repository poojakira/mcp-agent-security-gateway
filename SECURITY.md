# Security policy

## Supported scope and versions

This is a pre-1.0 project. The maintainer's integration branch is `main`; no backport or response-time commitment is published. The local execution workbench is a separate reviewed candidate described in [README.md](README.md). Its software version is 0.1.0 and its tested MCP stdio subset is 2025-03-26. See [exact-source evidence](docs/EVIDENCE.md) rather than inferring support from a version string.

Release status is **PARTIAL**. The browser exercises a fixed first-party child through actual proxy/policy controls. It has no authenticated multi-user boundary, credential lifecycle, arbitrary-server OS containment, output PII filter, externally anchored audit or durable provider-effect reconciliation. Only traffic routed through an enforcing path is controlled. The optional HTTP inspection service has API-key authentication; that does not grant the loopback workbench a verified credential identity.

## Report a vulnerability

Use the repository's private GitHub security-advisory channel if available, or contact the maintainer through [the verified repository owner's profile](https://github.com/poojakira). Do not put exploitable details or secrets into a public issue. Include affected commit/version, prerequisites, a minimal synthetic reproduction, expected/observed behavior and impact. Reporting does not imply a service-level acknowledgment or fix deadline.

## Credentials and inputs

- Do not commit real keys, passwords, tokens, private keys, populated environment files or user inputs.
- The local workbench needs no provider credentials. Use synthetic data for evaluation.
- Optional services require operator-owned credentials in runtime secret storage; do not copy shared demonstration values.
- If a credential is exposed, revoke/rotate it at its provider/deployment first. Removing a file or rewriting history does not revoke it. Then address source, reachable history, artifacts and logs under a reviewed recovery plan.
- Do not enable live secret validation against external services merely to classify a scanner heuristic.

## Residual risk and related guidance

Heuristic detection can miss attacks or flag benign text. A hash identifies bytes, not authorization or safety; an unkeyed chain can be rewritten. Fixed-fixture tests do not establish general attack prevention, multi-tenant isolation or production efficacy. See the [threat model](THREAT_MODEL.md), [operations](RUNBOOK.md), [acceptance matrix](docs/WORKBENCH.md#acceptance-status-matrix) and [release gates](PRODUCTION.md). Dated security audits record their cited source only.
