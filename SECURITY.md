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

<!-- credential-response:start -->
## Credential and secret handling

- Real API keys, tokens, passwords, private keys, cloud credentials, and populated environment files must never be committed.
- Local users must create their own `.env` from the repository's safe template when environment variables are needed, and must supply **their own** credentials. CI/CD credentials belong in GitHub repository/environment secrets or an external secret manager, not in source or workflow YAML.
- If a real credential is exposed, treat it as compromised even if the commit is quickly deleted. **Revoke or rotate the credential at its provider first.** Then remove it from the current tree, reachable Git history, logs/artifacts, examples, screenshots, and documentation as applicable.
- Rewriting Git history or deleting a file does **not** revoke a credential. Provider-side rotation/revocation is required.
- Placeholder/test credentials must be clearly marked and must not be valid for real services.
<!-- credential-response:end -->
