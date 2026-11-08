# Phase 6 — Signed local session and tenant isolation: verified prototype

**Draft PR:** [#152](https://github.com/poojakira/mcp-agent-security-gateway/pull/152) stacked on draft #151, #149 and #148.
**Scope:** Opt-in operator-controlled, locally signed session assertions with tenant-scoped ACL lookup.
**Production authentication:** **NOT VERIFIED**; no external identity provider, OAuth/OIDC, mTLS or authenticated remote channel.

## What the code does

- Verifies domain-separated HMAC-SHA256 assertions with a minimum 256-bit locally configured secret, strict claim set, duplicate-key rejection, signature check, issuer and audience matching, tenant and session identifier binding, and a maximum one-hour lifetime.
- Derives the ACL key from verified, length-delimited tenant and subject strings, rather than from agent-provided fields.
- Rejects a simultaneous legacy `authenticated_principal` and `session_binding` setting.
- On opt-in verified sessions, validates expiration/signature on every `tools/call` inspection and again after downstream response delivery, suppressing protected results if a session expires while the tool runs.
- Keeps the default legacy behavior unless the operator explicitly provisions the binding. A trusted embedding application must handle actual client-channel authentication and secret distribution.

## Verified CI evidence

**Source commit:** `510a229e2401ec8a1d0d3654fd8e7c633f5690e9`.
**Successful workflow:** [#42528157674](https://github.com/poojakira/mcp-agent-security-gateway/actions/runs/42528157674), completed successfully with **3/3 Python matrix jobs passed**.

| Check | Verified result |
|---|---|
| Python 3.10 complete suite | 984 passed, 2 skipped, 82.70% coverage |
| Python 3.11 complete suite | 984 passed, 2 skipped, 82.67% coverage |
| Python 3.12 complete suite | 984 passed, 2 skipped, 82.67% coverage |
| Focused Phase 6 identity + Step 4 authorization + stdio security tests | 54 passed per version |
| Ruff lint and formatter | Passed on all three Python versions |
| Deployment | None |
| Paid services | None; public repository standard GitHub-hosted runners |

All signing keys, subjects, tenants, resources, and test responses were synthetic; no production accounts or credentials were used.

## Remaining production security blockers

1. **Real channel authentication and identity-provider integration:** The local HMAC test verifier does not prove who connected to an actual MCP client, device or tenant, and is not OIDC/mTLS.
2. **Replay, logout and key management:** No durable nonce store, token revocation, rotating identity-provider key set, key custody, session logout propagation or proof-of-possession.
3. **Distributed authorization:** Durable multi-node permissions and replay-resistant revocation remain unimplemented.
4. **Networked tool egress:** The Phase 5 offline profile denies all outbound traffic and does not solve constrained online networking, DNS rebinding or redirects.
5. **MCP protocol handling:** Full request multiplexing, streaming and cancellation coverage remain unverified.
6. **Side effects and resilience:** Fail-closed response suppression does not undo writes already executed by tools; require idempotency and recovery testing.
7. **Security validation parity:** Independent detector corpus, load tests, CodeQL, full platform CI and representative deployment evidence are not claimed by this focused workflow.

## Exit decision

**Phase 6 first signed local session pilot: COMPLETE and CI-verified.**
**Phase 6 production identity and tenant gate: OPEN.**
PR #152 and its ancestors must remain draft and unmerged. No deployment or production certification is authorized.
