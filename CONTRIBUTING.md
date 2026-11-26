# Contributing to DeceptEnv

Thank you for your interest in contributing to DeceptEnv! This document provides guidelines for contributing to the project.

## Development Setup

```bash
# Clone the repository
git clone https://github.com/your-username/deceptenv.git
cd deceptenv

# Create and activate virtual environment
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install with dev dependencies
pip install -e ".[dev]"
```

## Code Quality

Before submitting a pull request, ensure all checks pass:

```bash
# Lint
make lint

# Type check
make typecheck

# Run tests
make test

# Run tests with coverage
make test-cov
```

### Minimum Standards

- **Ruff**: Zero lint warnings
- **Mypy**: Strict mode, zero errors
- **Tests**: All existing tests must pass; new features must include tests
- **Coverage**: Aim for ≥60% overall coverage

## Code Style

- **Formatter**: `ruff format` (88-char line length)
- **Type Hints**: All functions must have full type annotations (enforced by mypy strict mode)
- **Docstrings**: All public classes and functions must have docstrings
- **Python Version**: Must be compatible with Python 3.9+ (no walrus operator in hot paths, no `match` statements)

## Security Guidelines

Since DeceptEnv is a security tool, extra care is required:

1. **Never hardcode secrets or keys** — use `secrets.token_bytes()` or persistent key files
2. **Wrap all filesystem operations** in `try/except OSError` — macOS TCC and sandboxed environments will raise `PermissionError` on many paths
3. **Validate all paths** — use `Path.resolve()` and `is_relative_to()` to prevent directory traversal
4. **Never operate on PIDs without ownership verification** — always call `_verify_ownership()` first
5. **Bound all resource consumption** — memory dumps, file reads, and loop iterations must have limits

## Pull Request Process

1. Fork the repository and create a feature branch from `main`
2. Make your changes with appropriate tests
3. Ensure all CI checks pass locally (`make lint typecheck test`)
4. Submit a pull request with a clear description of changes
5. Address any review feedback

## Reporting Security Issues

If you discover a security vulnerability, please **do not** open a public issue. Instead, email the maintainers directly with details of the vulnerability.

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
