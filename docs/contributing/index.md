---
title: Contributing
description: How to contribute to IAM Policy Validator
---

# Contributing

Thank you for your interest in contributing to IAM Policy Validator!

## Ways to Contribute

- **Report bugs** — [Open an issue](https://github.com/boogy/iam-policy-validator/issues)
- **Request features** — [Start a discussion](https://github.com/boogy/iam-policy-validator/discussions)
- **Submit code** — Fork, develop, and submit a pull request
- **Improve docs** — Fix typos, add examples, clarify explanations

## Getting Started

1. [Development Setup](development-setup.md) — Set up your environment
2. [Testing](testing.md) — Run and write tests
3. [Releasing](releasing.md) — Release process (maintainers)

## Quick Start

```bash
# Clone repository
git clone https://github.com/boogy/iam-policy-validator.git
cd iam-policy-validator

# Set up development environment
uv sync --extra dev

# Run tests
uv run pytest

# Run linting
uv run ruff check .
uv run mypy iam_validator/
```

## Code of Conduct

Be respectful and constructive. We're all here to make IAM policies more secure.

## Questions?

- [GitHub Discussions](https://github.com/boogy/iam-policy-validator/discussions)
- [GitHub Issues](https://github.com/boogy/iam-policy-validator/issues)
