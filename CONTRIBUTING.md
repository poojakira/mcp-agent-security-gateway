> **READ [LICENSE](LICENSE) BEFORE COPYING OR CHANGING ANYTHING.** This is an owner-maintained, proprietary repository. **Unsolicited code/documentation contributions are not accepted.** The development instructions below apply **only to people who have received prior written authorization** from Pooja Kiran. Public viewing/forking under GitHub's Terms, applicable law, third-party rights, and prior valid licenses remain unaffected. Any accepted external work requires an agreed written copyright license or assignment; a PR alone does not transfer ownership. For permission contact poojakiranbhardwaj@gmail.com.

> **Documentation alignment (2026-11-09):** Contributions must preserve exact-commit evidence, explicit trust-boundary language, reproducible offline tests and the distinction between protected adapters and external deployment. The [release gate](docs/review/PHASE13_RELEASE_READINESS.md) is **PRODUCTION NO-GO**; [draft integration PR #167](https://github.com/poojakira/mcp-agent-security-gateway/pull/167) is not a released deployment.
# Contributing to mcp-agent-security-gateway

Only specifically invited contributors may propose changes under prior written terms. Technical guidance follows.

## How to Contribute

### 1. Fork and Clone the Repository

First, fork the repository to your GitHub account and then clone it locally:

```bash
git clone https://github.com/your-username/mcp-agent-security-gateway.git
cd mcp-agent-security-gateway
```

### 2. Create a New Branch

Create a new branch for your feature or bug fix:

```bash
git checkout -b feature/your-feature-name
```

### 3. Set up your Development Environment

This project uses `pip` for dependency management. Install the development dependencies:

```bash
pip install -e ".[dev]"
```

### 4. Make Your Changes

- Ensure your code adheres to the existing style and conventions.
- Write clear, concise commit messages.
- Add unit tests for new features or bug fixes.

### 5. Run Tests

Before submitting a pull request, ensure all tests pass:

```bash
pytest
```

### 6. Update Documentation

If your changes affect the functionality or usage, please update the relevant documentation (e.g., `README.md`).

### 7. Submit a Pull Request

Push your changes to your forked repository and open a pull request to the `main` branch of the original repository. Please provide a clear description of your changes and why they are necessary.

## Contribution Conduct

Use respectful, technical communication. Security reports should follow `SECURITY.md` rather than public issue threads when disclosure could increase risk.

Thank you for contributing!
## Security-sensitive contributions

Open pull requests against the reviewed branch; do not merge or deploy draft candidates without authorization. Include affected threat boundary, a benign and an adversarial regression, the full command used and its exact commit/run, and explicit limitations. Never include live tokens, outside-system probing, customer data or paid-provider dependencies. A screenshot, passing sample fixture or successful poster render is not a production-security claim.
