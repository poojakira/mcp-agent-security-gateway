# P0 deployment acceptance

**NO-GO. Neither target is production accepted.** Do not publish the intentionally invalid Kubernetes image digest.

Offline single-host target: trusted launcher binds one principal/session/tenant to a private stdio channel; distinct untrusted client OS identity cannot execute/read downstream code, access its workspace/socket or Docker daemon. Gateway operator is privileged; downstream is non-root with no network, dropped capabilities, readonly root, seccomp and no host namespaces. Dedicated writable resources only. SQLite is on a qualified durable local filesystem, shared by cooperating local processes, inaccessible to client identities. Test direct process/socket/filesystem/workspace/container attacks and inspect actual side effects. Local container success alone does not close P0-01.

Networked multi-tenant target: trusted OIDC issuer, authenticated TLS/mTLS edge, authoritative resource ownership/ACLs, session/token revocation and tested bound, shared transactional authority and durable deduplication with provider fencing/idempotency. Default-deny egress must be packet enforced across every process/transport, with validated DNS/IP/port/redirect behavior. Partitioned/stale replicas fail closed. This architecture is not implemented by independent SQLite databases.

Required acceptance owners and artifacts:

| Owner | Required evidence |
|---|---|
| Platform | Actual OS identities/permissions, runtime config, namespace/capability/seccomp checks, denied runtime socket access, no broad mounts |
| Kubernetes | Cluster/version/CNI identity, NetworkPolicy support actually exercised with approved/denied pods, IPv4/IPv6/lateral/host-network probes |
| Identity | Issuer onboarding, trusted keys/rotation, TLS peer identity/channel binding, two tenants, session/token reuse after revoke, outage behavior and measured latency bound |
| Network | All destination/alternate transport inventory; DNS rebind/redirect/proxy/metadata/IPv6 tests with actual deny observations |
| Distributed systems | Shared-state selection; consistency contract; leader loss/partition/delayed messages/stale worker fences and crash recovery |
| Release | Verified immutable gateway digest/source provenance, image SBOM/licenses/advisories, exact tested manifest, rollback/restore exercise |
| Independent reviewer | Frozen exact RC, complete evidence and residual-risk acceptance, protected environment/tag settings and human approval |

No cluster, issuer, production tenant, external effect provider or protected-environment settings were changed. Local proxy CA trust failure is a build-environment dependency; never disable TLS verification to bypass it.
