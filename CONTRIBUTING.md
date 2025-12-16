# Contributing to IAM Policy Validator

Thank you for your interest in contributing! Full contribution documentation is available in the [docs/contributing/](docs/contributing/) directory.

## Quick Start

```bash
# Clone and setup
git clone https://github.com/boogy/iam-policy-validator.git
cd iam-policy-validator
uv sync --extra dev

# Run quality checks
make check

# Run tests
make test
```

## Development Workflow

1. Fork and clone the repository
2. Create a feature branch: `git checkout -b feature/your-feature`
3. Make changes and add tests
4. Run `make check` to verify
5. Submit a pull request

## Commit Convention

Follow [Conventional Commits](https://www.conventionalcommits.org/):

- `feat:` New feature
- `fix:` Bug fix
- `docs:` Documentation
- `refactor:` Code refactoring
- `test:` Test changes
- `chore:` Maintenance

## Documentation

- [Development Setup](docs/contributing/development-setup.md) - Environment setup, dependencies
- [Testing Guide](docs/contributing/testing.md) - Running tests, writing tests
- [Releasing](docs/contributing/releasing.md) - Version bumps, publishing

## Project Structure

```
iam_validator/
├── checks/          # Built-in validation checks (19)
├── commands/        # CLI commands (7)
├── core/            # Validation engine, models, formatters
├── integrations/    # GitHub, MS Teams
└── sdk/             # Python SDK
```

## Adding New Features

- **New Check**: See [Custom Checks Guide](docs/developer-guide/custom-checks/)
- **New Command**: Add to `iam_validator/commands/`
- **New Formatter**: Add to `iam_validator/core/formatters/`

## Getting Help

- [GitHub Issues](https://github.com/boogy/iam-policy-validator/issues)
- [GitHub Discussions](https://github.com/boogy/iam-policy-validator/discussions)
