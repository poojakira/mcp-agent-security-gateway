# MCP Agent Security Gateway

A local security workbench for agent developers to compare tool permissions, execute constrained MCP requests, and inspect actual tool-side outcomes. The browser calls the repository's `StdioMCPProxy`, `PolicyEngine`, and injection detector against a first-party disposable file server.

**Release status: PARTIAL.** This candidate adds a functioning local workflow. It is not an approved production release. Historical test counts and coverage elsewhere in this repository do not attest to this candidate. Run the checks below; generated evidence must identify the actual checked-out commit.

## Start locally

Requires Python 3.10+ and a browser. No API keys, external models, or paid services.

```sh
python -m venv .venv
. .venv/bin/activate
python -m pip install -e .
python -m mcp_monitor.workbench
```

Open **http://127.0.0.1:8761**. The server binds only to IPv4 loopback. Do not expose it through a reverse proxy or public tunnel. Stop with Ctrl+C. Each run's temporary directory and subprocess are removed before the response returns; no durable incident database is created.

1. Execute **Read sample note**. Inspect the actual response, tool receipt and state hash.
2. Select **Write note** and execute with **Read-only / Tool permission ON**. The request is denied without a tool receipt.
3. Keep the request unchanged and turn **Tool permission OFF**. A fresh disposable target receives the same request using the read/write allowlist. Inspect the changed note.
4. Export redacted evidence. Raw request, response and note content are removed; checksums and metadata remain.

OFF changes only the tool allowlist. Injection, egress and protocol checks remain enabled. The comparison does not measure real-world incident reduction.

![Browser running the local MCP workbench with candidate execution evidence](https://raw.githubusercontent.com/poojakira/mcp-agent-security-gateway/refs/tags/evidence/local-workbench-20261116/release-evidence/browser/desktop.png)

The screenshot and its source commit are retained separately under an evidence archive tag. The tag is not a software release. This source commit does not claim to contain its own post-execution evidence hash.

## What is supported

- An editable JSON-RPC request reaches the actual proxy, then a real stdio subprocess.
- Exact read/write permission comparison; independent fixture state and invocation receipts.
- Injection-in-arguments and disallowed-destination denial through existing engine controls.
- Fixed-path cross-workspace refusal, malformed request and alternate-method rejection.
- Actual crash/timeout scenarios with honest unknown outcomes, and observable duplicate append effects.
- Protocol subset: MCP 2025-03-26 stdio initialize, initialized notification, tools/list, tools/call and ping. Full conformance, cancellation/concurrency semantics and the current protocol version are **NOT VERIFIED**.

This workbench accepts requests to its first-party fixture only. It cannot launch arbitrary servers, execute commands, select host paths, or make outbound requests. It does not verify credential identity, expiry/revocation, external action reconciliation, output PII filtering, or multi-user isolation. It offers no exactly-once guarantee. Unkeyed hash chains do not prevent an attacker rewriting an entire log.

## Development and verification

```sh
python -m pip install -e '.[dev]'
PYTHONPATH=src python -m pytest tests/ -q
ruff check src/ tests/ poster/render_poster.py scripts/recruiter_demo.py
ruff format --check src/ tests/ poster/render_poster.py scripts/recruiter_demo.py
python -m pip install playwright
PYTHONPATH=src python scripts/workbench_e2e.py --output /tmp/mcp-workbench-evidence --chromium /usr/bin/chromium
python -m build
```

The browser command needs Chromium installed at the chosen path. It starts and tears down its own loopback server, exercises real read/denied write/permission rerun/export, checks a mobile viewport, and records screenshots. Tests use synthetic data only. The workbench itself has no new runtime dependency; existing optional services retain their authentication behavior.

## Documentation

- [Product, architecture and threat boundaries](docs/WORKBENCH.md)
- [API, operations and limitations](docs/WORKBENCH.md#api-and-operations)
- [Evidence and remaining release gates](docs/EVIDENCE.md)
- [Read-only repository baseline](docs/internal/REPOSITORY_AUDIT.md)
- [Security reporting](SECURITY.md)
- [Change history](CHANGELOG.md)

Other documents describe legacy engine paths, experiments and historical evidence. Their metrics and release claims have not all been reconciled against this candidate; that incomplete audit remains a release blocker. Advanced protected-server/journal/revocation branches remain preserved and unmerged.
