# Contributing to IAM Policy Validator

Thank you for your interest in contributing to IAM Policy Validator! This document provides guidelines and instructions for contributing to the project.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Project Structure](#project-structure)
- [Development Workflow](#development-workflow)
- [Testing](#testing)
- [Code Quality](#code-quality)
- [Documentation](#documentation)
- [Submitting Changes](#submitting-changes)
- [Release Process](#release-process)

## Code of Conduct

This project follows a code of conduct to ensure a welcoming environment for all contributors. Please be respectful, constructive, and professional in all interactions.

## Getting Started

### Prerequisites

- Python 3.11 or higher
- [uv](https://github.com/astral-sh/uv) package manager
- Git
- AWS account (optional, for testing AWS integrations)

### First Time Setup

1. **Fork and Clone the Repository**

   ```bash
   git clone https://github.com/YOUR-USERNAME/iam-policy-auditor.git
   cd iam-policy-auditor
   ```

2. **Install uv (if not already installed)**

   ```bash
   curl -LsSf https://astral.sh/uv/install.sh | sh
   ```

3. **Set up Development Environment**

   ```bash
   # Create virtual environment and install dependencies
   uv sync

   # Install development dependencies
   uv sync --extra dev
   ```

4. **Verify Installation**

   ```bash
   uv run iam-validator --help
   ```

## Development Setup

### Using the Makefile

The project includes a comprehensive Makefile for common development tasks:

```bash
make help          # Show all available commands
make dev           # Install dev dependencies
make check         # Run all quality checks (lint, type-check, test)
make test          # Run tests
make lint          # Run linter (ruff)
make format        # Format code (ruff)
make type-check    # Run type checker (mypy)
make clean         # Clean build artifacts
make build         # Build distribution packages
```

### Manual Setup

If you prefer not to use the Makefile:

```bash
# Install dependencies
uv sync --extra dev

# Run tests
uv run pytest

# Format code
uv run ruff format .

# Lint code
uv run ruff check .

# Type check
uv run mypy iam_validator
```

## Project Structure

```
iam-policy-auditor/
├── iam_validator/              # Main package
│   ├── cli.py                  # CLI entry point
│   ├── checks/                 # Built-in validation checks
│   ├── commands/               # CLI command implementations
│   ├── core/                   # Core validation engine
│   │   ├── formatters/         # Output formatters
│   │   └── data/               # Static data files
│   └── integrations/           # External integrations
│
├── tests/                      # Test suite
│   ├── test_policy_checks.py   # Core validation tests
│   ├── test_aws_fetcher.py     # AWS integration tests
│   ├── test_cache_and_optimizations.py  # Cache/optimization tests
│   └── test_benchmarks.py      # Performance benchmarks
│
├── docs/                       # Documentation
│   ├── getting-started/        # Quick start guides
│   ├── guides/                 # User guides
│   ├── reference/              # Reference documentation
│   ├── advanced/               # Advanced topics
│   └── development/            # Development docs
│
├── examples/                   # Example policies and configs
│   ├── configs/                # Configuration examples
│   ├── custom_checks/          # Custom check examples
│   └── github-actions/         # GitHub Actions examples
│
├── .github/workflows/          # CI/CD workflows
├── pyproject.toml              # Project metadata and dependencies
├── Makefile                    # Development commands
└── default-config.yaml         # Example configuration file
```

## Development Workflow

### 1. Create a Branch

```bash
git checkout -b feature/your-feature-name
# or
git checkout -b fix/issue-number-description
```

### 2. Make Changes

- Write clean, readable code following Python best practices
- Add type hints to all functions and classes
- Follow the existing code style (enforced by Ruff)
- Write tests for new functionality
- Update documentation as needed

### 3. Test Your Changes

```bash
# Run all tests
make test

# Run specific test file
uv run pytest tests/test_policy_checks.py

# Run with coverage
uv run pytest --cov=iam_validator --cov-report=html

# Skip slow tests
uv run pytest -m "not slow"

# Skip benchmarks
uv run pytest -m "not benchmark"
```

### 4. Check Code Quality

```bash
# Run all checks
make check

# Or run individually:
make lint          # Check code style
make format        # Auto-format code
make type-check    # Type checking
```

## Testing

### Writing Tests

- Place tests in the `tests/` directory
- Use descriptive test names: `test_should_validate_valid_policy`
- Use pytest fixtures for common setup
- Mark slow tests with `@pytest.mark.slow`
- Mark benchmarks with `@pytest.mark.benchmark`

### Test Categories

```python
import pytest

# Regular test
def test_basic_validation():
    pass

# Async test
@pytest.mark.asyncio
async def test_async_validation():
    pass

# Slow test (skipped by default)
@pytest.mark.slow
def test_large_dataset():
    pass

# Benchmark test (skipped by default)
@pytest.mark.benchmark
def test_performance():
    pass
```

### Running Tests

```bash
# All tests
uv run pytest

# Specific file
uv run pytest tests/test_policy_checks.py

# Specific test
uv run pytest tests/test_policy_checks.py::test_valid_policy

# With verbose output
uv run pytest -v

# With coverage
uv run pytest --cov=iam_validator

# Skip slow tests
uv run pytest -m "not slow"
```

## Code Quality

### Code Style

We use [Ruff](https://github.com/astral-sh/ruff) for linting and formatting:

```bash
# Format code
make format
# or
uv run ruff format .

# Check code style
make lint
# or
uv run ruff check .

# Fix auto-fixable issues
uv run ruff check --fix .
```

### Type Checking

We use [mypy](https://mypy-lang.org/) for static type checking:

```bash
make type-check
# or
uv run mypy iam_validator
```

### Pre-commit Checks

Before committing, always run:

```bash
make check
```

This runs linting, type checking, and tests.

## Documentation

### Writing Documentation

- Keep documentation clear and concise
- Include code examples where appropriate
- Update relevant docs when changing functionality
- Follow the existing documentation structure

### Documentation Structure

- **Getting Started**: Quick start guides for new users
- **Guides**: In-depth tutorials and how-tos
- **Reference**: API and configuration reference
- **Advanced**: Advanced topics and patterns
- **Development**: Contributor documentation

### Building Documentation

Documentation is written in Markdown and hosted on GitHub. To preview locally:

```bash
# View docs in browser
open docs/README.md
```

## Submitting Changes

### Pull Request Process

1. **Update Documentation**
   - Update relevant documentation in `docs/`
   - Update `docs/CHANGELOG.md` with your changes
   - Update examples if applicable

2. **Ensure Quality**
   ```bash
   make check  # Run all quality checks
   ```

3. **Commit Changes**
   ```bash
   git add .
   git commit -m "feat: add custom check for XYZ"
   ```

   Follow [Conventional Commits](https://www.conventionalcommits.org/):
   - `feat:` new feature
   - `fix:` bug fix
   - `docs:` documentation changes
   - `refactor:` code refactoring
   - `test:` test changes
   - `chore:` maintenance tasks

4. **Push to Your Fork**
   ```bash
   git push origin feature/your-feature-name
   ```

5. **Create Pull Request**
   - Go to the repository on GitHub
   - Click "New Pull Request"
   - Select your branch
   - Fill out the PR template
   - Link related issues

### Pull Request Guidelines

- **Title**: Clear, descriptive title following conventional commits format
- **Description**: Explain what changes you made and why
- **Tests**: Include tests for new functionality
- **Documentation**: Update relevant documentation
- **Breaking Changes**: Clearly mark any breaking changes
- **Screenshots**: Include screenshots for UI changes

### PR Review Process

1. Automated checks must pass (CI/CD)
2. Code review by maintainers
3. Address review feedback
4. Maintainer merges PR

## Release Process

Releases are managed by project maintainers. The process includes:

1. **Version Bump**
   ```bash
   # Update version in pyproject.toml
   # Update CHANGELOG.md
   ```

2. **Build**
   ```bash
   make build
   ```

3. **Test Release** (optional)
   ```bash
   make publish-test
   ```

4. **Publish to PyPI**
   ```bash
   make publish
   ```

5. **GitHub Release**
   - Create a new release on GitHub
   - Tag the release (e.g., `v0.2.0`)
   - Include changelog in release notes

For detailed publishing instructions, see [docs/development/PUBLISHING.md](docs/development/PUBLISHING.md).

## Adding New Features

### Creating a New Check

See the comprehensive [Custom Checks Guide](docs/custom-checks.md) for detailed instructions on creating custom validation checks.

**Quick Example:**

1. **Create Check File**
   ```python
   # my_checks/mfa_check.py
   from typing import List
   from iam_validator.core.models import PolicyValidationIssue, PolicyStatement

   def execute(statement: PolicyStatement, policy_document: dict) -> List[PolicyValidationIssue]:
       """Ensure sensitive actions require MFA."""
       issues = []

       sensitive_actions = ["iam:CreateUser", "iam:DeleteUser"]
       actions = statement.action if isinstance(statement.action, list) else [statement.action]

       for action in actions:
           if action in sensitive_actions:
               # Check for MFA condition
               has_mfa = statement.condition and "aws:MultiFactorAuthPresent" in str(statement.condition)

               if not has_mfa:
                   issues.append(
                       PolicyValidationIssue(
                           check_name="mfa_required",
                           severity="high",
                           message=f"Action '{action}' requires MFA",
                           statement_index=statement.index,
                           action=action,
                           suggestion='Add: {"Bool": {"aws:MultiFactorAuthPresent": "true"}}'
                       )
                   )

       return issues
   ```

2. **Use the Check**
   ```bash
   iam-validator validate --path ./policies/ --custom-checks-dir ./my_checks
   ```

3. **Add Tests**
   ```python
   # tests/test_my_check.py
   def test_mfa_check():
       # Test your check
       pass
   ```

4. **Document the Check**
   - Add to `docs/custom-checks.md`
   - Add example to `examples/custom_checks/`

### Adding a New Formatter

1. **Create Formatter Class**
   ```python
   # iam_validator/core/formatters/my_formatter.py
   from iam_validator.core.formatters.base import Formatter

   class MyFormatter(Formatter):
       def format(self, report: ValidationReport) -> str:
           # Implement formatting logic
           pass
   ```

2. **Register in CLI**
   - Add to formatter registry in `cli.py`

3. **Add Tests and Documentation**

## Getting Help

- **Documentation**: Check [docs/](docs/)
- **Issues**: Search [existing issues](https://github.com/Boogy/iam-policy-auditor/issues)
- **Discussions**: Start a [discussion](https://github.com/Boogy/iam-policy-auditor/discussions)

## Recognition

Contributors will be:
- Listed in release notes
- Acknowledged in the README
- Given credit for their contributions

Thank you for contributing to IAM Policy Validator!
