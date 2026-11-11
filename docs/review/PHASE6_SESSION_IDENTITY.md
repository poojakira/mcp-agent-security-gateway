# Phase 6 — Trusted local session assertion and tenant-scoped ACL pilot

> **Evidence boundary (2026-11-09):** The local session/tenant claims assume trusted issuer provisioning. Their verification is a laboratory pilot, not a complete production IdP integration. [Production release gate](../../docs/review/PHASE13_RELEASE_READINESS.md): **NO-GO**. [Integration candidate](https://github.com/poojakira/mcp-agent-security-gateway/pull/167): draft, unmerged.
## Security objective

Bind an *operator-provisioned* signed identity assertion to one gateway stdio
session and to one configured tenant. The gateway does not read caller identity
from agent tool-call arguments. The assertion is reverified before every
\`tools/call\` is forwarded and again before a response containing tool results
is released. Failed signature, expired claims, mismatched audience/issuer,
tenant or session identifier must fail closed.

The default legacy gateway remains unchanged unless \`session_binding\` is
explicitly supplied by a trusted embedding application. When enabled,
\`authenticated_principal\` cannot also be provided. ACL keys are
length-delimited tenant-scoped principal strings, preventing cross-tenant
grant conflation.

## Trust design: bounded prototype

- Local HMAC-SHA256 with a domain-separated fixed-format
  \`base64url(claims).base64url(signature)\` assertion.
- Strict keys: \`iss\`, \`aud\`, \`tenant\`, \`sub\`, \`sid\`, \`iat\`, \`exp\`.
- Immutable operator-bound verifier key, expected issuer, audience, tenant
  and session ID. Minimum 256-bit secret key; maximum 1-hour token lifetime.
- Strict identifier grammar and JSON duplicate-key and signature rejection.
- No signing key or assertion is placed in MCP messages, CLI flags, child
  process command, source repository or logs. Synthetic fixtures generate
  test assertions using test-only keys.
- No external network service, token signing service, or private CI.

**This is not OAuth/OIDC, mTLS, a trusted remote identity provider, token
revocation, session channel authentication, proof of possession, durable
anti-replay, key rotation or a production login system.** The verifier accepts
a bearer assertion that can be replayed by an attacker who obtains it *and*
the expected session binding. Protect the signing key and trust the caller
that creates the binding.

## Scope limitations and unresolved gates

1. Authenticate the actual MCP client channel and its upstream user, device
   and tenant using an industry-standard identity provider.
2. Integrate trusted key management and rotation, hard expiry and revocation,
   nonce/session lifecycle, replay resistance, and audited failure behavior.
3. Durable multi-node ACL sequence and failover.
4. Non-offline constrained egress controls and DNS/redirect/socket isolation.
5. Protocol multiplexing, side-effect retries, and recovery from write calls.
6. Independent held-out adversarial benchmarking, Docker daemon threat model,
   CodeQL, load/restart/failure acceptance in a representative environment.

**Phase 6 first identity pilot cannot certify production readiness.**

## Evidence

CI result will be recorded only after the exact PR source commit passes.
Use public-repository standard GitHub-hosted runners, no paid services,
no production deployments, and keep PRs #148, #149, and #151 draft/unmerged.
