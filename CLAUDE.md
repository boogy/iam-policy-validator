# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

IAM Policy Validator is an AWS IAM policy validation tool with dual interfaces:
1. **GitHub Action** - Composite action for CI/CD validation
2. **Python CLI/Library** - Standalone tool with 18 built-in security checks

The tool validates policies against AWS Service Reference API and provides custom security checks for privilege escalation, wildcards, sensitive actions, and policy type requirements.

## Development Commands

### Environment Setup
```bash
# Install production dependencies
uv sync

# Install with dev dependencies
uv sync --extra dev

# Verify installation
uv run iam-validator --help
```

### Testing
```bash
# Run all tests
uv run pytest

# Run with coverage
uv run pytest --cov=iam_validator --cov-report=html

# Run specific test file
uv run pytest tests/test_policy_loader.py

# Run tests matching pattern
uv run pytest -k "test_wildcard"
```

### Code Quality
```bash
# Format code
uv run ruff format .

# Lint code
uv run ruff check .

# Auto-fix linting issues
uv run ruff check --fix .

# Type checking
uv run mypy iam_validator/

# Run all checks (via Makefile)
make check
```

### Running the Validator
```bash
# Validate single policy
uv run iam-validator validate --path policy.json

# Validate directory
uv run iam-validator validate --path ./policies/

# Validate with AWS Access Analyzer
uv run iam-validator analyze --path policy.json

# Read from stdin
cat policy.json | uv run iam-validator validate --stdin

# Custom checks directory
uv run iam-validator validate --path ./policies/ --custom-checks-dir ./my-checks

# Different policy types
uv run iam-validator validate --path ./policies/ --policy-type RESOURCE_POLICY
```

### Other Commands
```bash
# Download AWS service definitions (for offline validation)
uv run iam-validator download-services --output-dir ./aws_services

# Check cache status
uv run iam-validator cache status

# Clear cache
uv run iam-validator cache clear
```

## Architecture

### Core Components

**Command System** (`iam_validator/commands/`)
- Plugin-based command architecture
- Each command inherits from `Command` base class
- Commands: `validate`, `analyze`, `download-services`, `cache`, `post-to-pr`
- Registration happens via `ALL_COMMANDS` list in `__init__.py`

**Check Registry** (`iam_validator/core/check_registry.py`)
- Pluggable check system with parallel execution
- All checks inherit from `BaseCheck` ABC
- Checks registered via `CheckRegistry.register()` decorator
- Configuration-driven enabling/disabling of checks
- Support for custom checks via `--custom-checks-dir`

**Policy Processing Pipeline**
1. `PolicyLoader` (`core/policy_loader.py`) - Loads and auto-detects IAM policies from JSON/YAML
2. `validate_policies()` (`core/policy_checks.py`) - Orchestrates validation
3. Check execution - Parallel async execution of all enabled checks
4. `ReportGenerator` (`core/report.py`) - Formats output (console, JSON, markdown, SARIF, CSV, HTML)

**AWS Integration**
- `AWSServiceFetcher` (`core/aws_fetcher.py`) - Fetches AWS service definitions with caching
- `AccessAnalyzer` (`core/access_analyzer.py`) - Integrates with AWS IAM Access Analyzer
- Cache system with LRU memory cache and disk persistence

**Data Models** (`core/models.py`)
- Pydantic models for type safety
- Key models: `IAMPolicy`, `Statement`, `ValidationIssue`, `ValidationReport`
- Policy types: `IDENTITY_POLICY`, `RESOURCE_POLICY`, `SERVICE_CONTROL_POLICY`, `RESOURCE_CONTROL_POLICY`

### Built-in Checks (18 total)

Located in `iam_validator/checks/`:
- **AWS Validation**: action_validation, condition_key_validation, condition_type_mismatch, resource_validation, sid_uniqueness, policy_size, set_operator_validation, mfa_condition_check, principal_validation, policy_type_validation, action_resource_matching
- **Security**: wildcard_action, wildcard_resource, full_wildcard, service_wildcard, sensitive_action, action_condition_enforcement

### Configuration System

**Config Loading** (`core/config/config_loader.py`)
- YAML-based configuration
- Priority: CLI args > config file > defaults
- Per-check configuration with severity overrides
- Ignore patterns support (filepath, action, resource, SID matching)

**Config Modules** (`core/config/`)
- `defaults.py` - Default configuration values
- `sensitive_actions.py` - 490 actions requiring conditions (4 risk categories)
- `condition_requirements.py` - Action-specific required conditions
- `aws_global_conditions.py` - Global AWS condition keys
- `service_principals.py` - AWS service principals list

### GitHub Integration

**PR Commenter** (`core/pr_commenter.py`)
- Posts validation results as PR comments
- Three modes: summary comment, review comments, GitHub Actions summary
- Smart cleanup of old bot comments
- Streaming mode support

**GitHub Action** (`action.yaml`)
- Composite action with automatic setup
- No external dependencies required
- Uses GitHub token for PR comments

## Key Patterns

### Adding a New Check

1. Create check file in `iam_validator/checks/new_check.py`:
```python
from iam_validator.core.check_registry import BaseCheck, CheckRegistry

@CheckRegistry.register("new_check")
class NewCheck(BaseCheck):
    check_id = "new_check"
    description = "Description of what this checks"
    severity = "medium"

    async def check_policy(self, policy, statement=None):
        # Return list of ValidationIssue or empty list
        pass
```

2. Import in `iam_validator/checks/__init__.py`

3. Check auto-registers via decorator

### Custom Check Development

Custom checks follow same pattern as built-in checks. Place in directory and use `--custom-checks-dir`:
```python
from iam_validator.core.check_registry import BaseCheck

class MyCustomCheck(BaseCheck):
    check_id = "my_custom_check"
    description = "My custom validation"
    severity = "high"

    async def check_policy(self, policy, statement=None):
        issues = []
        # Validation logic
        return issues
```

### Working with AWS Service Data

```python
from iam_validator.core.aws_fetcher import AWSServiceFetcher

fetcher = AWSServiceFetcher()
await fetcher.fetch_service_definition("s3")
```

Service definitions cached in `aws_services/` directory and memory.

## Testing Guidelines

- Tests in `tests/` directory
- Use pytest fixtures for common setup
- Test files mirror source structure
- Mock AWS API calls using pytest-asyncio
- Example policies in `examples/iam-test-policies/`

## Git Commit Conventions

Don't add Claude co-author to commits. Use conventional commit format:
- `feat:` - New features
- `fix:` - Bug fixes
- `docs:` - Documentation changes
- `style:` - Code style changes
- `refactor:` - Code refactoring
- `test:` - Test additions/changes
- `chore:` - Build/tooling changes

## GitHub Actions Workflows

- `ci.yml` - Lint, test, build (runs on push/PR)
- `codeql.yml` - CodeQL security analysis (weekly + push/PR)
- `scorecard.yml` - OpenSSF Scorecard (weekly + push)
- `release.yml` - Build and publish to PyPI (on version tags)

All workflows use least-privilege permissions (read-all at top level, specific permissions at job level).

## Important Files

- `action.yaml` - GitHub Action definition (125 char description limit for marketplace)
- `pyproject.toml` - Python package config, dependencies, build settings
- `uv.lock` - Locked dependencies (don't edit manually)
- `Makefile` - Development commands
- `SECURITY.md` - Security policy (volunteer-maintained, realistic timelines)

## Releasing

1. Update version in `iam_validator/__version__.py`
2. Create git tag: `git tag -a v1.x.x -m "Release v1.x.x"`
3. Push tag: `git push origin v1.x.x`
4. GitHub Actions automatically builds and publishes to PyPI
5. Uses trusted publishing (no API tokens)

## AWS Service Definitions

- Stored in `aws_services/` directory
- Fetched on-demand or pre-downloaded via `download-services` command
- Used for action/condition validation
- LRU memory cache with disk fallback
