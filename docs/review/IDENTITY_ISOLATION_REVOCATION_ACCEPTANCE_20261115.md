# Production identity, isolation and revocation acceptance — 2026-11-15

**Release decision: PRODUCTION NO-GO.** This is an adversarial acceptance plan, not a production security certification. No external identity provider, cluster, credential issuer or live protected tenant resources were used.

## Findings 1–6 and observed boundary

| ID | Threat | Existing implementation | Missing acceptance evidence |
|---|---|---|---|
| 1 | Direct downstream MCP bypass | Opt-in offline Docker and internal sandbox adapters; deny-all Kubernetes policy; restricted protected-repository server | Hostile same-user, node, process, socket, workspace and Docker-daemon bypass attempts in a real isolated deployment. A gateway pod manifest alone cannot prevent direct downstream access. |
| 2 | Alternate tool path avoids authorization | Stdio proxy gates and protected-server local authorization; HTTP inspection endpoint API-key checks | Enumerate every reachable tool, transport, socket and process path; prove no direct execution outside the gate, including after restart and during failure. |
| 3 | Forged or unbound identity | Offline RS256 JWKS verifier with issuer, audience, tenant, session and revocation callback; local HMAC session prototype | Trusted issuer onboarding, authenticated client-channel binding, rotation, mTLS/OIDC integration and every supported transport. The HTTP service key is not tenant-aware OIDC. |
| 4 | Cross-tenant access | Tenant-scoped VerifiedSession.principal and OIDC verifier configured for one trusted tenant | Two real isolated tenants and resources; negative tests for substituted tenant, subject, session, tool and resource, across every transport. |
| 5 | Credential accepted after revocation | Retired demo-key denylist; local per-verification OIDC is_active callback; local SQLite authority | Live issuer-side revocation and propagation to all running replicas, key caches and channels; issuer and secret-store audit. The retired-key denylist does not revoke an external credential. |
| 6 | In-flight revocation race | SQLite BEGIN IMMEDIATE serializes cooperating local protected file commits and revocation; existing race tests | Distributed revocation fencing and provider-side consequence checks. A revocation requested during a local protected effect is acknowledged only after that effect commits; it does **not** retroactively cancel that effect. |

## Changes committed in this remediation series

- Kubernetes gateway pod explicitly disables host network, PID and IPC namespaces and service-account token automount; keeps non-root, read-only root filesystem, dropped capabilities and seccomp.
- Static deployment tests assert these pod restrictions and deny-all ingress/egress policy.
- These are defense-in-depth configuration controls, **not** proof of downstream non-bypassability or live network isolation.

## Required independent acceptance (not yet completed)

1. Provision two test tenants, a trusted OIDC issuer and separate resource ACLs; bind identities to authenticated channels, not MCP JSON arguments.
2. Run downstream server with a different OS identity and isolated filesystem/process namespace; ensure untrusted clients cannot reach its socket, executable, workspace or container runtime.
3. Validate actual CNI deny-all enforcement and narrowly allow only required gateway-to-downstream paths; attempt IPv4, IPv6, DNS, proxy, redirect, host-network and metadata bypasses.
4. Execute an exhaustive alternate-tool-path matrix and confirm denied calls produce **zero** downstream effects, not just a denial response.
5. Revoke credentials at the issuer, test every live replica and transport, record propagation latency and verify no post-revocation authorization.
6. Race revocation against queued, dispatched, committed and acknowledged effects; record authoritative external state. Specify whether revocation means 'no new authorization' or 'cancel all pending effects', and prove the selected contract.
7. Independently review evidence, preserve immutable commit and CI/run IDs, and require explicit production GO approval. Do not claim production acceptance based on unit tests.

**No API keys or paid provider services were used for this documentation and configuration change.**
