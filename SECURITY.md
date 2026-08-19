# Security Policy

## Supported Versions

| Version | Supported          |
|---------|--------------------|
| 1.0.x   | ✅ Active support  |
| < 1.0   | ❌ No support      |

## Reporting a Vulnerability

If you discover a security vulnerability in the MCP Agent Security Gateway, please report it responsibly.

**DO NOT** open a public GitHub issue for security vulnerabilities.

### How to Report

1. **Email:** Send details to the maintainer via GitHub's private vulnerability reporting feature on this repository.
2. **Include:**
   - Description of the vulnerability
   - Steps to reproduce
   - Affected component/layer (Layer 1-5, audit log, circuit breaker, etc.)
   - Potential impact assessment
   - Suggested fix (if you have one)

### Response Timeline

- **Acknowledgment:** Within 72 hours
- **Initial assessment:** Within 7 days
- **Fix or mitigation:** Within 30 days for critical/high severity

### Scope

The following are in scope for security reports:

- Bypass of any security layer (1-5) that allows a malicious tool call through
- Hash-chain integrity violations (ability to tamper with audit log undetected)
- Injection into the gateway's own configuration or rule files
- Denial of service against the inspection pipeline
- Information leakage from the gateway's internal state
- Bypass of rate limiting or circuit breaker mechanisms

### Out of Scope

- Vulnerabilities in upstream dependencies (report to the dependency maintainer)
- Issues requiring physical access to the host
- Social engineering attacks against maintainers

### Recognition

Security researchers who report valid vulnerabilities will be credited in the CHANGELOG.md and release notes (unless they prefer to remain anonymous).

## Security Design

This project follows defense-in-depth principles:

- **No single point of bypass:** Each of the 5 layers independently evaluates requests
- **Fail-safe defaults:** Unknown patterns are blocked, not allowed
- **Audit integrity:** SHA-256 hash-chained logs detect tampering
- **Minimal dependencies:** Reduces supply-chain attack surface
- **CI security scanning:** Bandit SAST, pip-audit SCA, Trivy container scanning on every commit
