# Security Policy

## Scope

`mcp-agent-security-gateway` is maintained as a production-oriented security gateway for MCP/JSON-RPC tool calls. Supported runtime paths are expected to fail explicitly, emit audit evidence, and enforce configured policy before forwarding controlled requests. Deployment at a specific scale or environment still requires operator validation, SLOs, and integration testing.

## Reporting a Vulnerability

If you find a security issue in this project, please report it privately rather
than opening a public issue:

- Open a GitHub security advisory on this repository, or
- Email the maintainer (see the profile at https://github.com/poojakira).

Please include:
- A description of the issue and its impact
- Steps to reproduce (a minimal proof of concept if possible)
- The affected commit or version

## Supported Versions

This is a pre-1.0 project. Only the latest `main` is maintained; there is no
backport policy.

## Related Documents

- [`SECURITY_AUDIT.md`](SECURITY_AUDIT.md) — security review and validation notes
- [`THREAT_MODEL.md`](THREAT_MODEL.md) — adversaries, attack surfaces, and mitigations
