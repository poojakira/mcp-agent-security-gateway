# Phase 7 — Offline JWKS verification and revocation pilot

**Scope:** A bounded identity and revocation pilot stacked on Phase 6 draft PR #152.
**No paid services, production deployment, remote IdP, or real user data.**

## Security boundary

The gateway now supports an opt-in `OfflineJWKSVerifier` and
`OIDCSessionBinding` for verifying **RS256-signed JWTs** with a trusted,
operator-provisioned public JWKS. Only a trusted embedding application may
supply an assertion, the JWKS snapshot, and the bound stdio session ID.
Neither an agent nor a tool-call parameter may choose the JWT signing key,
issuer, algorithm, audience, subject, or tenant.

- RS256 only, pinned key IDs, 2048-bit minimum RSA public keys.
- HTTPS issuer, exact audience and tenant, required subject, session ID,
  JWT ID, issue/not-before/expiration claims and bounded token lifetime.
- Rejects unsupported headers, attacker-supplied JKU/JWK, private JWKs,
  ambiguous or duplicate key IDs, unsigned and HS256 tokens.
- Trusted monotonic JWKS replacement permits key rotation and invalidates
  keys removed by the operator; stale/malformed updates fence the verifier.
- An operator-supplied **synchronous** revocation callback rechecks
  `(tenant, sid, jti)` before requests and again before releasing responses.
  Callback failures and unknown/non-boolean status fail closed.
- Session verification now also applies to other request methods, such as
  `resources/read`, not only `tools/call`.
- Existing Phase 6 signed local session behavior remains opt-in and preserved.

## Deliberate limitations

This module does **not** fetch or automatically authenticate issuer metadata
or remote JWKS; no real OIDC login flow, redirect handler, client identity
binding, mTLS channel, PKCE, proof-of-possession, or refresh tokens exist.
The operator must authenticate the JWKS provisioning channel and validate
that it belongs to the issuer. Synthetic RSA keys are generated in memory
only in tests. The revocation callback is local and **not distributed or
durable**; token theft and replay remain possible without a trusted session
transport and token revocation infrastructure. Key rotation operates on
locally authenticated snapshots, not a production identity provider.

A synchronous callback must be bounded and must not perform untrusted slow
network requests while holding verification locks. Automatic provider
discovery, secure refresh, outage strategy, key history and restart
consistency require separate design.

## Scope verdict

This first Phase 7 milestone is an **offline verifier/revocation proof of
concept**, not completion of Phase 7 production authentication. Green CI is
evidence only for its test cases, not for live IdP integration or production
authorization. All PRs remain draft and unmerged.

CI evidence will be recorded after successful execution on exact source commit.
