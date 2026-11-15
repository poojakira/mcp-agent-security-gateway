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

## Separate final devil's-advocate pass

This is a second code-path/adversarial pass by the implementing agent, **not independent human acceptance**.

| Question | Finding / observed boundary | Disposition |
|---|---|---|
| 1. Direct downstream access? | Same-user/process/host bypass remains outside the tested container perimeter; isolated fixtures deny scoped attacks. | P0-01 OPEN; hostile OS identity acceptance required |
| 2. Compromised server changes authorization? | Arguments/results do not supply gateway identity or policy. Malformed, unexpected or injection-bearing responses are suppressed. | Local regressions pass; operator/configuration custody remains trusted |
| 3. Valid user accesses another tenant? | Verified principal includes tenant; authoritative resource ownership across deployed tenants is unverified. | P0-04 OPEN |
| 4. Revoked authority on another replica? | Independent local readers observe session/token revocation; no cross-host consensus or propagation bound. | P0-05/11 OPEN |
| 5. Duplicate after timeout? | Intent reserved before dispatch; reuse denied after restart/timeout. Independent databases/provider retries are not fenced globally. | P0-08/14 OPEN |
| 6. False success hides missing effect? | Acknowledgment cannot complete. Independent exact bound resource observation required. | Regression/adversarial pass; provider acceptance still open |
| 7. False failure triggers retry? | Failure/lost ACK leaves UNCERTAIN; no automatic retry branch. | Phase 11/15 regressions pass within local fault model |
| 8. State changes after verification? | Yes. Evidence explicitly means point-in-time observation, not immutable final state. | P0-15 OPEN for provider conditional/versioned verification |
| 9. Crash corrupts journal? | Process-kill, corrupt/unavailable store and dedicated tmpfs exhaustion tests fail closed; physical power loss/rollback not proven. | P0-13 OPEN |
| 10. DNS/proxy/IPv6/redirect bypass? | Webhook validates/pins DNS and refuses redirects/proxies/private answers; this does not confine all downstream packets. | P0-10 OPEN for deployment-wide enforcement |
| 11. Stale token/key bypass? | Offline strict validation and rotation tests pass; live trusted issuer/key-feed/channel binding unavailable. | P0-03/05 OPEN |
| 12. Suppressed/manipulated audit? | Exception secrets were reproducibly logged on response-inspection failure and are now redacted. Default development stores are private. Owner/root can still truncate/fork unanchored logs. | Local leaks fixed; independent retention acceptance OPEN |
| 13. CI green with different artifact? | Nine-job/Python-only CI passed while the first runtime image had Critical advisories. Added a separate exact-image build/smoke/SBOM/advisory gate; it correctly fails on remaining High matches. | P0-18 OPEN; no clean-image claim |
| 14. Privileged operator bypasses approval? | Administrator can edit code/settings; release-environment API read was 404, not proof of protection. | P0-19 OPEN; human/settings verification required |
| 15. Fail open during outages? | Local policy, detector, authority, journal/evidence and full-storage negative tests deny; external provider/IdP/CNI partition semantics unverified. | No universal outage guarantee |
