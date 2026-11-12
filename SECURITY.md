> **Evidence reconciliation (2026-11-11; living reference):** Historical results below retain their original dates and denominators. Latest tested Phase 1–16 development SHA is `43a72c8984bf9a472b9055d4f9e84cc759f61718` ([CI](https://github.com/poojakira/mcp-agent-security-gateway/actions/runs/42971171992): 1,211 passed, 6 skipped per Python version), **not** a merged or production-approved release. Offline research tests require no paid provider or provider-issued API keys; deployed HTTP authentication and unverified real credential revocation remain separate. See [operating restrictions](PRODUCTION.md) and [release evidence](docs/review/PHASE1_16_RELEASE_CANDIDATE_NO_GO_20261110.md).

# Security Policy

> **Release status:** Research and engineering prototype. The integrated development candidate is a draft pull request and **not approved for production**. See [release-readiness evidence](docs/review/PHASE13_RELEASE_READINESS.md) and [integration PR #167](https://github.com/poojakira/mcp-agent-security-gateway/pull/167).

## Scope and supported versions

This repository develops an MCP/JSON-RPC gateway with several separately scoped enforcement paths. Tests demonstrate specific parser, authorization, inspection, audit, and protected-file behaviors; they do **not** establish universal enforcement, an authenticated enterprise deployment, or protection of requests routed directly to another MCP server.

The default branch `main` is the maintained public integration point; experimental research branches and draft pull requests are not released versions. No backport or production support commitment is implied.

## Privately report a vulnerability

Use the repository's GitHub security advisory reporting mechanism, if enabled. Alternatively, contact the maintainer through the contact information on [the GitHub profile](https://github.com/poojakira). Do not publish working exploits, credentials, or private data in a public issue.

Include the affected commit/branch, precise entry point, configuration and prerequisites, minimal non-destructive reproduction, impact, and whether a downstream side effect actually occurred. Use only authorized test systems.

## Credentials and secrets

- Never commit real API keys, service tokens, private keys, passwords, populated `.env` files, or customer data.
- There is **no assurance of a tracked safe `.env` template**. Create a local ignored environment file only if needed, supply a fresh operator-generated value through local environment variables or a suitable secret facility, and keep it outside Git.
- The local detection-lab Compose definition requires an operator-provided `MCP_API_KEY`; its published service ports are scoped to loopback by the integration tests. **Loopback bindings do not make the full deployment safe.**
- A previously published demonstration credential is retired from supported source configuration in the integration candidate. **Source retirement is not issuer-side revocation.** Whether that value was ever used by a real service, and whether any live credential was rotated or revoked, remain unverified.
- If an actual credential leaks, revoke/rotate it **at the provider or credential issuer**, invalidate dependent sessions when supported, assess active deployment exposure, then remove the value from current code, accessible history, logs, screenshots and CI artifacts as appropriate. Editing Git does not revoke a credential.
- Test fixtures must use clearly synthetic values. Do not use paid provider services or real customer material for repository experiments.

## Security guarantees and open risks

Supported endpoints and adapters have distinct controls. A local session assertion or offline JWKS test does not prove independent remote identity. An audit hash chain is not immutable storage, and a circuit breaker can fail differently by runtime path. The protected first-party MCP adapter and SQLite revocation/effect experiments are bounded local proofs, not distributed containment. The release review still requires independent adversarial validation, authentic authorization and revocation, restricted outbound traffic, protocol compatibility evidence, crash recovery, hardened deployment and human approval.

**Production release decision: NO-GO.** Do not merge or deploy the draft integration candidate solely because CI passes.

## References

- [Repository overview](README.md)
- [Threat model](THREAT_MODEL.md)
- [Historical security audit](SECURITY_AUDIT.md)
- [Incident handling](INCIDENT_RUNBOOK.md)
- [Release-readiness blockers](docs/review/PHASE13_RELEASE_READINESS.md)
