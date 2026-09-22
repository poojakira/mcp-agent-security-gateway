# Contributing to mcp-agent-security-gateway

We welcome contributions to the `mcp-agent-security-gateway` project. Please keep reviews and discussions technical, respectful, and focused on the repository.

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