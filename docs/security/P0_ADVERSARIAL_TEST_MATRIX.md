# P0 adversarial test matrix

Results must be read in [CI evidence](P0_CI_EVIDENCE.md); planned cases are not executed evidence. All fixtures use synthetic identities and disposable files/servers.

| IDs | Positive case | Negative/concurrent/fault case | Ground truth / evidence |
|---|---|---|---|
| 01,09 | Approved private channel | Direct socket/process/filesystem/alternate container/workspace from hostile UID | Actual downstream file hashes/effect count; full hostile-UID deployment pending |
| 02,04 | Permitted tool and own resource | Unsupported resources/prompts/subscriptions/aliases, malformed JSON/batch/duplicate keys, tenant substitution | `test_hardened_tool_discovery`, protocol/ACL suites; target state unchanged |
| 03,05,12 | Bound issuer/key/session/tenant | Forged, expired, rotated, mismatched JWT; revoked session and token; authority outage | Phase 6/7/8 tests; actual issuer and TLS edge pending |
| 02,05,06 | Fresh queued request | Revoke while waiting sequential and broker send locks | `test_revocation_while_waiting_to_dispatch_has_zero_effects`: actual dispatch-effect count zero |
| 06,13 | Local fenced commit | Child kill before/after commit; lock contention; live authority symlink/hardlink/permission substitution | Phase 16 process tests and new `test_live_revocation_fence_rejects_storage_substitution` |
| 07,15 | Exact independently observed manifest | False success/failure, unexpected edit, wrong arguments, mutable preflight snapshot, missing file/FIFO | Phase 15 and `test_snapshot_mutation_cannot_authorize_unrelated_modification`; real manifest inspected |
| 07,13 | Atomic evidence and completion | Drop evidence table before reconciliation; legacy mark_completed; missing/corrupt journal | New P0 journal tests: UNCERTAIN remains; no replay |
| 08,11,14 | Atomic first reservation | Concurrent same-key, conflicting payload, restart, timeout, lost ACK | Phase 11/13 tests; cross-host partition/failover pending |
| 10,12 | HTTPS public DNS mock / explicit local HTTP | Private/loopback/link-local/metadata/IPv6 DNS, proxy environment, redirect, DNS rebinding | `test_p0_webhook_transport`; local redirect receiver sees exactly one request; no redirect sent |
| 13 | Durable normal write | Disk exhaustion, corruption, unavailable DB, power loss | Local process-kill tests; this session experienced disk exhaustion (infrastructure errors retained); actual power loss pending |
| 16,17 | Harmless fixture | Token adjacent to PLACEHOLDER comment, historical secrets, issuer reuse | Redacted blob scan and P0 scanner tests; issuer authentication pending |
| 16 | Fail-closed policy/detector | Exception carrying secret marker | `test_dependency_exception_secrets_are_not_logged_or_returned`; zero dispatch |
| 18,19 | Synthetic complete approval | Missing/stale/unverified/evidenceless P0 records even with GO environment | `test_release_authorization`; actual approval remains absent |
| audit | Valid hash chain | Changed/deleted/forked logs, audit storage failure | `test_phase13_audit_integrity`; independent immutable retention not supplied |

Separate devil's-advocate review: queued authorization and nested-snapshot mutation were found by tracing alternate execution paths. Further review found and repaired missing observer/resource binding at reservation; tests reject an identical transformation on another workspace, stale preflight and legacy unbound intents. P0-07/15 remain open for provider/distributed acceptance. Checks before dispatch cannot cancel an already dispatched irreversible operation. Same-UID/root journal mutation and restoring old stores remain outside the trusted-local-storage contract. Hash chains can be truncated/forked without independently anchored retention. Release administrators can modify code/settings; repository tests cannot prove organizational separation of duties. No independent human penetration test occurred.
