# Phase 14 — Real MCP execution and bypass resistance

**State: PARTIAL — production NO-GO, no claim of full bypass resistance.**

This branch is based on the independently green Phase 13 lab gate at `365f99c679bb780864e888c3287ba9bec3c1cc30`. The initial first-party server and real filesystem test are incorporated from research PR #160 and updated to run through **explicit gateway tool allowlists** and the hardened MCP method boundary. The repository remains a disposable offline experiment. No API keys, paid services, or real third-party infrastructure are used.

## Threat model and trust

- **Trusted actor for this experiment:** the local machine operator who launches and provisions the protected server process. **No remote user authentication** is demonstrated.
- **Untrusted input:** MCP JSON-RPC frames, tool names, arguments, candidate dependency versions, agent-reported identity/role, path representations and untrusted file content.
- **Enforcement boundary:** exact tool allowlist in the gateway plus the separately running protected MCP server's fixed resource and operator-approved package/version mapping. The latter continues checking requests if the client connects directly.
- **Protected resources:** `security-policy.json` must not be modified by the declared MCP tools. `package.json` allows only one preapproved exact dependency update. A returned allow/deny alone is insufficient; tests inspect bytes independently.

## Executable evidence

- `tests/test_first_party_protected_mcp.py`: real subprocess, actual stdio MCP initialization, tool discovery, benign read, forbidden read/write/command, unauthorized dependency version and extra arguments, approved dependency update, duplicate update, independent SHA-256 of protected file; direct-to-server negative calls.
- `tests/test_first_party_public_manifest.py`: disposable copy of a real pinned open-source MCP repository manifest with expected Git blob verified before the test. Not a malicious dataset and no upstream changes.
- `tests/test_phase14_bypass_matrix.py`: method confusion, disallowed tool names, unapproved package/version, forged role/principal, nested and encoded path attempts and duplicate JSON keys; verify no effect by comparing actual file hashes.
- CI: `.github/workflows/first-party-protected-mcp.yml`, Python 3.10/3.11/3.12, free GitHub Actions, lint/format, real-process exercise, verified pinned public manifest, protocol/policy regressions.

## Observed limitations (not waived)

1. **Direct execution path remains possible** to the same-user subprocess if the attacker possesses local process-launch capabilities. The first-party server rejects unauthorized MCP methods but a direct caller can still submit an operator-approved update. Tests do not prove all production connections must traverse the gateway. This is a **release blocker**.
2. **No OS-level access isolation in the experiment.** The test process runs as the same user that can edit workspace files directly. `security-policy.json` is not protected from a malicious local OS principal. A real deployment must restrict process credentials, mounts, file descriptors, and network egress.
3. **Potential local TOCTOU.** The server checks for symlinks and uses atomic replacement, but it does not eliminate races against an attacker able to modify directory entries simultaneously. A strong implementation needs trusted ownership or secure fd-relative operations.
4. The trusted local operator sets scope via process environment. There is no external attested user identity, authorization provenance or cryptographic delegation proof.
5. MCP interoperability is intentionally narrow: this first-party server supports a bounded stdio subset. Other transports, reverse/server-originated calls, notifications and streaming require separate evaluation.
6. A denied request may still have an effect in *other* downstream servers; the scope here is this fixed protected adapter only.
7. The independent public manifest is authentic workflow data, not an independent adversarial sample or a blind security benchmark.

## Decision

- **PASS if supported by exact-head CI:** scoped real MCP effects, resource restriction and selected bypass-negative cases.
- **OPEN:** universal non-bypassable gateway path, OS containment, trusted principal, concurrent filesystem mutation robustness, broader MCP interoperability and independent evaluation.
- **NO-GO:** full Phase 14 acceptance. In particular, the real deployment bypass surface is not closed.
- **DOWNSTREAM DEPENDENCY:** Phases 15–19 must not be marked complete or production approved based on this partial Phase 14 test. Next engineering milestone is isolating the adapter in a minimal OS sandbox and proving direct-path denial to the protected scope.

## Phase roadmap retained from the approved execution plan

| Phase | Description | State |
|---|---|---|
| 13 | Integrated security baseline | Laboratory scope verified; production NO-GO |
| 14 | Real MCP execution and bypass resistance | Partial, blocked on OS/direct-path containment |
| 15 | Independent consequence verification | Not started: requires trusted effect boundary and transactional reconciliation |
| 16 | Revocation-safe execution | Not started: requires Phase 15 fenced effect adapter |
| 17 | Realistic adversarial evaluation | Not started: requires stable demonstrator and independent inputs |
| 18 | NVIDIA OpenShell comparative research | Not started: must pin upstream version and test equivalent workloads |
| 19 | Final security engineering release | Not started: requires the full evidence package and human approval |

No auto-merge, production deployment, or paid API usage is authorized by this review.
