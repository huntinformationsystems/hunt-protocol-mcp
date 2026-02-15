# Contributing to Provara

We welcome contributions to the Provara MCP server. This document explains how to set up your development environment, run tests, and submit changes.

## Getting Started

### Prerequisites

- Python 3.10 or later
- Git
- A GitHub account

### Development Setup

1. **Fork the repository** on GitHub.

2. **Clone your fork:**

   ```bash
   git clone https://github.com/YOUR_USERNAME/hunt-protocol-mcp.git
   cd hunt-protocol-mcp
   ```

3. **Create a virtual environment:**

   ```bash
   python -m venv .venv
   source .venv/bin/activate   # On Windows: .venv\Scripts\activate
   ```

4. **Install in development mode:**

   ```bash
   pip install -e .
   ```

5. **Verify the install:**

   ```bash
   python server.py
   ```

   The server should start and connect to the reference backpack in `examples/reference_backpack/`.

## Running Tests

Run the test suite with pytest from the repository root:

```bash
pytest -v
```

If tests require the reference backpack, ensure `examples/reference_backpack/` is intact. Do not modify the reference backpack unless you are specifically testing vault operations and plan to restore it afterward.

Before submitting a pull request, confirm that all tests pass on your branch.

## Submitting Changes

### Branch Naming

Use descriptive branch names:

- `fix/broken-merkle-verification`
- `feature/search-by-date-range`
- `docs/improve-tool-descriptions`

### Pull Request Process

1. **Create a branch** from `main`:

   ```bash
   git checkout -b feature/your-feature-name
   ```

2. **Make your changes.** Keep commits focused and atomic. Write commit messages in imperative mood ("Add search filter" not "Added search filter").

3. **Run the tests** and confirm everything passes.

4. **Push your branch:**

   ```bash
   git push origin feature/your-feature-name
   ```

5. **Open a pull request** against `main` on GitHub. In the PR description:
   - Explain what the change does and why.
   - Reference any related issues.
   - Note any breaking changes.

6. **Respond to review feedback.** The Provara team aims to review PRs within a week. We may request changes, ask questions, or suggest alternatives.

### What Makes a Good PR

- Solves one problem. If you have multiple unrelated fixes, submit separate PRs.
- Includes tests for new functionality.
- Does not introduce new dependencies without prior discussion (open an issue first).
- Matches the existing code style and conventions.

## Code Style

- **Match existing patterns.** Read the code in `hunt_protocol/` before writing new code. Follow the same naming conventions, module structure, and documentation style.
- **No unnecessary abstractions.** This is a small, focused codebase. Prefer clarity over cleverness.
- **Type hints are encouraged** but not strictly required for contributions.
- **Docstrings:** Public functions should have docstrings explaining what they do, their parameters, and their return values.

## Dependencies

The project intentionally has a minimal dependency footprint: `fastmcp` and `cryptography`. Do not add new dependencies without opening an issue to discuss it first. If your contribution requires a new dependency, explain why existing tools are insufficient.

## Protocol Specification

The protocol specification (`PROTOCOL_PROFILE.txt`) is frozen. Contributions must not violate the normative spec. If you believe the spec needs a change, open an issue to begin the RFC process described in [GOVERNANCE.md](GOVERNANCE.md).

## Good First Issues

Issues labeled **"good first issue"** on the GitHub issue tracker are suitable for newcomers. These are typically well-scoped tasks with clear acceptance criteria. If you are new to the project, start there.

If you want to work on an issue, leave a comment so we know someone is on it.

## Licensing and Originality

By submitting a pull request, you certify that:

- The contribution is your original work, or you have the right to submit it.
- The contribution is licensed under the [Apache License 2.0](LICENSE), consistent with the project license.
- The contribution does not include code copied from projects with incompatible licenses.

We do not require a Contributor License Agreement (CLA) at this time. The Apache 2.0 license terms in the LICENSE file govern all contributions.

## Reporting Issues

- **Bugs:** Open a GitHub Issue with steps to reproduce, expected behavior, and actual behavior.
- **Feature requests:** Open a GitHub Issue describing the use case and proposed solution.
- **Security vulnerabilities:** Do NOT open a public issue. Email **hello@provara.dev** with "SECURITY" in the subject line. See [SECURITY.md](SECURITY.md) for details.

## Contact

For questions about contributing, open a GitHub Issue or email **hello@provara.dev**.
