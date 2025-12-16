---
title: Development Setup
description: Set up your development environment
---

# Development Setup

Set up your environment to contribute to IAM Policy Validator.

## Prerequisites

- Python 3.10+
- [uv](https://github.com/astral-sh/uv) (recommended) or pip
- Git

## Clone Repository

```bash
git clone https://github.com/boogy/iam-policy-validator.git
cd iam-policy-validator
```

## Install Dependencies

### With uv (Recommended)

```bash
# Install all dependencies including dev
uv sync --extra dev

# Install docs dependencies too
uv sync --extra dev --extra docs
```

### With pip

```bash
# Create virtual environment
python -m venv .venv
source .venv/bin/activate

# Install with dev dependencies
pip install -e ".[dev]"
```

## Verify Installation

```bash
# Run the CLI
uv run iam-validator --version

# Run tests
uv run pytest

# Run linting
uv run ruff check .
```

## Project Structure

```
iam-policy-validator/
├── iam_validator/           # Main package
│   ├── __version__.py      # Version (sync with pyproject.toml)
│   ├── core/               # Core validation engine
│   ├── checks/             # Built-in checks
│   ├── commands/           # CLI commands
│   ├── sdk/                # Public SDK
│   └── integrations/       # GitHub, Teams integrations
├── tests/                   # Test suite
├── docs/                    # Documentation
├── examples/                # Usage examples
└── pyproject.toml          # Project configuration
```

## Development Workflow

### 1. Create Branch

```bash
git checkout -b feature/my-feature
```

### 2. Make Changes

Edit code, add tests, update docs as needed.

### 3. Run Quality Checks

```bash
# Format code
uv run ruff format .

# Lint
uv run ruff check --fix .

# Type check
uv run mypy iam_validator/

# Run tests
uv run pytest
```

### 4. Commit Changes

```bash
git add .
git commit -m "feat: add my feature"
```

Use [Conventional Commits](https://www.conventionalcommits.org/):

- `feat:` — New feature
- `fix:` — Bug fix
- `docs:` — Documentation
- `refactor:` — Code refactoring
- `test:` — Test changes
- `chore:` — Build/tooling

### 5. Push and Create PR

```bash
git push origin feature/my-feature
```

Then open a pull request on GitHub.

## IDE Setup

### VS Code

Recommended extensions:

- Python (ms-python.python)
- Pylance (ms-python.vscode-pylance)
- Ruff (charliermarsh.ruff)

Settings (`.vscode/settings.json`):

```json
{
  "python.defaultInterpreterPath": ".venv/bin/python",
  "python.analysis.typeCheckingMode": "basic",
  "[python]": {
    "editor.formatOnSave": true,
    "editor.defaultFormatter": "charliermarsh.ruff"
  }
}
```

### PyCharm

1. Set interpreter to `.venv/bin/python`
2. Enable Ruff plugin for formatting
3. Configure pytest as test runner

## Useful Commands

```bash
# Run specific test
uv run pytest tests/test_specific.py -v

# Run tests with coverage
uv run pytest --cov=iam_validator --cov-report=html

# Validate a policy during development
uv run iam-validator validate --path examples/quick-start/

# Build docs locally
uv run mkdocs serve
```
