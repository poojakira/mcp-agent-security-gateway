# Real-world prototype: operator questions and acceptance criteria

> Status: public **research/engineering prototype**, not a certified production security boundary. This document distinguishes implementation and demonstrated test behavior from requirements that remain unverified. Always consult the GitHub checks for the exact commit being evaluated.

## What is actually runnable?

- The Python stdio gateway launches an external MCP server through `SubprocessTransport` and processes MCP JSON-RPC messages via `StdioMCPProxy.handle_message`.
- `.github/workflows/real-mcp-smoke.yml` runs `tests/test_live_filesystem_mcp.py` with a real, pinned external filesystem MCP server and temporary files. The test covers a permitted read, an unauthorized read, a denied write with unchanged file contents, a malicious file response, and a revocation after a server response has been obtained but before it is released.
- The last scenario **does not** demonstrate revocation during the downstream server's computation, an atomic guarantee across response delivery, or a distributed permission change feed.
- The gateway is **not** itself a separately authored general-purpose MCP tool server.

## Questions a security reviewer should ask

| Question | Evidence or current answer | What remains |
|---|---|---|
| Where does untrusted input enter? | Tool-call arguments and downstream tool results pass through `src/mcp_monitor/proxy/stdio_proxy.py`. See [dependency map](REPOSITORY_DEPENDENCY_MAP.md). | Validate alternate transports and uninspected paths before relying on this as the sole control. |
| Who is the authenticated principal? | `authenticated_principal` and `ACLGuard` use operator-supplied trusted state; the test sets it explicitly. | An external authentication/identity integration, session binding, tenancy boundaries, and spoofing tests. |
| Is a denied operation executed? | Policy integration tests check lack of forwarding; real filesystem test checks a denied write leaves an existing file unchanged. | No guarantee about side effects of calls that were previously allowed or enforcement outside the proxy. |
| What happens after permission revocation? | Controlled concurrency tests and a paused real-server response-delivery test suppress the protected result. | Distributed revocation, durable CDC, process restarts, cache purge, and response-release race analysis. |
| What if the detector or server returns invalid data? | `tests/test_stdio_adversarial_responses.py` tests malformed replies and synthetic detector failures. | Load, process crashes, recovery and every JSON-RPC multiplexing variant. |
| Can prompt injection always be stopped? | Named test cases are blocked; prompt-injection detector and response checks exist. | Unknown attacks, non-text content, multilingual bypasses, false positives and false negatives. No universal guarantee. |
| Is network exfiltration contained? | Tool-policy checks include disallowed destinations in controlled tests. | Actual socket/OS egress enforcement, DNS/redirect handling and non-MCP network traffic. |
| Are credentials embedded in Git? | Secret hygiene workflow and ignore rules check common patterns; `.env` files/templates are no longer intended to be committed on this branch. | Historical exposure checks cannot prove absence of every secret. Rotate any credential found exposed; ignoring does not erase history. |
| Are audit records dependable? | Audit/WAL implementations and documentation exist in this repository. | Confirm durability, integrity, retention, backup/recovery and correlation under realistic failure and multi-instance conditions. |
| Can it survive real operations? | CI provides lint, tests, static checks, Docker, Windows and real-MCP jobs when those jobs complete successfully. | Representative workload and latency testing, failure injection, disaster recovery, patch process, alerting, and a validated deployment topology. |

## Reproducibility and acceptance gate

From a clean checkout of the **specific branch/commit under review**, in an isolated test environment:

```bash
python -m pip install -e ".[dev]"
ruff check src/ tests/ poster/render_poster.py scripts/recruiter_demo.py
ruff format --check src/ tests poster/render_poster.py scripts/recruiter_demo.py
python -m pytest tests/test_stdio_policy_integration.py tests/test_stdio_inflight_revocation.py tests/test_stdio_adversarial_responses.py tests/test_acl_guard.py -q
MCP_RUN_REAL_SERVER=1 python -m pytest tests/test_live_filesystem_mcp.py -v -s
```

The real-MCP test requires compatible Node/npm, network access to fetch the pinned external package, and an isolated disposable filesystem. **A green CI badge is evidence only for the exact commit, configured jobs, and environment it ran in.** Inspect job results including Docker and security checks instead of treating passing unit tests as production approval.

### Practical acceptance criteria for the public prototype

1. All required CI jobs finish successfully on a single final commit; rerun after every corrective commit.
2. A permitted MCP operation reaches the downstream server and returns the expected synthetic result.
3. Denied reads and writes do not expose protected markers or cause the asserted filesystem changes.
4. Malformed responses, prompt-injection fixtures and detector exceptions are handled as specified by tests.
5. Permission-revocation tests distinguish controlled races and paused response delivery from computation-time or distributed races.
6. No real credentials or sensitive datasets are committed; security scans are reviewed and actual leaks rotated.
7. Documentation includes limitations, exact commands, relevant source/tests, and an explicit residual-risk statement.
8. Public demos use synthetic data and approved local endpoints only.

## What this prototype does **not** establish

It is not a complete product security assessment; it has not proven production-grade high availability, multi-tenant identity and authorization, irreversible-action prevention, general exfiltration containment, detector completeness, compliance certification, or safe operation across arbitrary MCP servers. These are **open engineering and validation requirements**, not hidden features.

## Separate private product track

Real-world consequence experiments should be designed in a different private repository using isolated infrastructure, synthetic or explicitly authorized data, authorized receivers, rollback procedures, and measurable effects. Do not make public prototype claims based on future work.

## Supporting evidence

- [Attack-to-control matrix](ATTACK_CONTROL_EVIDENCE.md)
- [Reviewed MCP dependency and execution map](REPOSITORY_DEPENDENCY_MAP.md)
- [ACL/CDC guard assumptions](../policy/ACL_CDC_GUARD.md)
- [PR #148 checks](https://github.com/poojakira/mcp-agent-security-gateway/pull/148/checks)
