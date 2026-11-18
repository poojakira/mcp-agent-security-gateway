> **READ [LICENSE](LICENSE) BEFORE COPYING OR CHANGING ANYTHING.** This is an owner-maintained, proprietary repository. **Unsolicited code/documentation contributions are not accepted.** The development instructions below apply **only to people who have received prior written authorization** from Pooja Kiran. Public viewing/forking under GitHub's Terms, applicable law, third-party rights, and prior valid licenses remain unaffected. Any accepted external work requires an agreed written copyright license or assignment; a PR alone does not transfer ownership. For permission contact poojakiranbhardwaj@gmail.com.

# Authorized development

Contributions require the prior written authorization described above. Read [LICENSE](LICENSE) and [SECURITY.md](SECURITY.md); a public repository or submitted PR does not itself grant additional rights or transfer ownership.

## Set up and verify

Use [README setup and development commands](README.md#develop-and-verify). The browser module is `mcp_monitor.workbench`; actual policy/proxy code lives under `src/mcp_monitor/policy` and `src/mcp_monitor/proxy`. [docs/WORKBENCH.md](docs/WORKBENCH.md) maps the architecture, limits and tests. Keep new work on a short-lived reviewed branch; retain active or unique work during cleanup.

Run the applicable complete regression, browser, lint/format, type/security, build and documentation gates from a clean candidate. Use synthetic data and out-of-tree artifacts. Record exact SHA, UTC interval, commands, dependencies, exits, pass/fail/skip counts and artifact hashes. Existing results at a prior source are historical until rerun for your head. Do not weaken thresholds, remove security assertions or relabel skipped checks as passing.

## Review a change

Explain the concrete problem, resulting behavior, scope, source/test evidence and limitations. Update task-oriented docs in the same series. Do not silently broaden the loopback fixture to arbitrary executables/network destinations, public hosting or multi-user use. Preserve legal/historical records and identify older claims by their source/date rather than copying metrics into a new current headline.

Open a review proposal only under the agreed contribution terms. Default-branch merge, package/container publication, external telemetry and deployment are separate actions with their own gates. Report security issues privately. Use respectful, precise technical communication.
