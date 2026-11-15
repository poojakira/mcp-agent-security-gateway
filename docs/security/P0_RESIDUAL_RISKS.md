# P0 residual risks

All 19 requested acceptance closures remain open. See the master register for exact per-finding dependencies. Verified local regressions must not be counted as full production fixes.

Mandatory blockers: hostile-process downstream containment; live trusted issuer/TLS channel binding; authoritative tenant resource ownership; measured issuer/session revocation; external commit fencing; shared distributed authority and deduplication; provider-backed resource/version binding; version-consistent external observations; actual CNI/network enforcement; qualified crash/power-loss recovery; private secret/artifact/issuer inventory; exact immutable deployment artifact/SBOM/license/provenance and rollback; independent human approval/protected settings.

Unsupported/unverified: cross-host SQLite, independent replica databases, automatic retries of uncertain effects, universal resources/prompts/subscriptions in hardened stdio, arbitrary provider reconciliation, client-supplied success evidence, Docker as complete host boundary, gateway inspection as interception of direct tool execution, plaintext network deployment as authenticated multi-tenant protection. Legacy library passthrough and research entry points are not approved production paths.

Security-sensitive assumptions: trusted launcher/operator/observer code; no hostile same-UID/root/Docker-daemon actor; protected configuration/journal directory; cooperative writers/revokers; durable local storage honors sync; authentic authoritative callbacks; accurate trusted clock; tested artifact equals deployed artifact. Each needs deployment evidence, not a comment.

Accessible public tracked files/reachable Git blobs are scan scope. Unreachable/deleted history, private repositories, secret stores, inaccessible/expired CI artifacts and deployed credentials are not exhaustively scanned. No confirmed active credential was identified by the bounded detector; no issuer-side revocation is claimed.
