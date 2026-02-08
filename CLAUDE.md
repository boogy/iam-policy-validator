# IAM Policy Validator - Claude Code Instructions

## Overview

- **Type**: Python CLI tool + GitHub Action for AWS IAM policy validation
- **Stack**: Python 3.10-3.14, uv, Pydantic v2, httpx (HTTP/2), boto3, Rich, FastMCP
- **Architecture**: Plugin-based check system with async parallel execution
- **Interfaces**: CLI (`iam-validator` or `iam-policy-validator`), Python SDK, MCP Server, GitHub Action

This CLAUDE.md is the authoritative source for development guidelines.
Subdirectories contain specialized CLAUDE.md files that extend these rules.

---

## CRITICAL RULES (MUST)

- **MUST** write plans in .claude/plans/ folder
- **MUST** use `git push --force-with-lease` instead of `git push --force`
- **MUST** always format markdown files using prettier
- **MUST** use `rg` and `fd` for searching

### Git & Push Safety

- **MUST** ask for explicit user consent before `git push`
- **MUST** create pull requests instead of pushing to `main` directly
- **MUST** sign all commits with `-s -S` (sign-off + GPG/SSH)
- **MUST** sign all git tags with `-s` (never use `git tag -a`)
- **MUST NOT** add Claude as co-author (`Co-Authored-By: Claude`)
- **MUST NOT** add `Generated with [Claude Code]` footers
- **MUST NOT** use `git push --force` to main/master

### Documentation (MUST)

- **MUST** update `CHANGELOG.md` when making changes and committing
- **MUST** update relevant `CLAUDE.md` files when project structure, checks, or patterns change

### Version File Synchronization

- **MUST** update BOTH files when changing version:
  - `iam_validator/__version__.py` (line 6)
  - `pyproject.toml` (line 3 via hatch dynamic version)
- **MUST** use `/create-version-tag` slash command for version bumps

### Code Quality (MUST)

- **MUST** run `uv run ruff check` before committing
- **MUST** run `uv run pytest` for changes to core logic
- **MUST** use type hints for all public functions
- **MUST NOT** introduce `any` type without explicit justification

### Security (MUST NOT)

- **MUST NOT** commit secrets, API keys, or AWS credentials
- **MUST NOT** edit `.env*` files without explicit user consent
- **MUST NOT** disable security checks without documenting reason

---

## Slash Commands

### Commands (procedural workflows)

| Command               | Purpose                                          |
| --------------------- | ------------------------------------------------ |
| `/create-pr`          | Create PR with version bump workflow             |
| `/create-version-tag` | Bump version in both files, create signed tag    |
| `/update-changelog`   | Update CHANGELOG.md following Common Changelog   |
| `/run-check`          | Validate a policy file with the IAM validator    |
| `/test-check`         | Run tests for a specific check                   |
| `/benchmark`          | Run performance benchmarks                       |
| `/debug-check`        | Debug a specific check with verbose output       |
| `/generate-policy`    | Generate IAM policy from template or description |

### Skills (reasoning frameworks)

| Skill                 | Purpose                                          |
| --------------------- | ------------------------------------------------ |
| `/add-check`          | Check patterns, architecture, and templates      |
| `/review`             | Code review evaluation criteria and checklists   |
| `/fix-issue`          | Analyze and plan fixes for GitHub issues         |
| `/update-claude-md`   | CLAUDE.md quality and structure reasoning         |

---

## Development Commands

### Quick Reference

```bash
# Setup
uv sync                          # Install dependencies
uv sync --extra dev              # Install with dev deps
uv sync --extra mcp              # Install MCP server support

# Quality
uv run ruff format .             # Format code
uv run ruff check --fix .        # Lint + auto-fix
uv run mypy iam_validator/       # Type check
make check                       # All checks (lint + type + test)

# Testing
uv run pytest                    # Run all tests
uv run pytest -k "wildcard"      # Pattern match
uv run pytest -m "not slow"      # Skip slow tests
uv run pytest -m "not benchmark" # Skip benchmarks
uv run pytest --cov=iam_validator --cov-report=html  # Coverage

# Validation
uv run iam-validator validate --path policy.json
uv run iam-validator validate --path ./policies/ --config config.yaml
uv run iam-validator analyze --path policy.json   # AWS Access Analyzer

# MCP Server
iam-validator-mcp                # Start MCP server (stdio)
make mcp-inspector               # Debug MCP with inspector
```

### Test Markers

- `benchmark` - Performance tests (skip: `-m "not benchmark"`)
- `slow` - Long-running tests (skip: `-m "not slow"`)
- `integration` - External resource tests

---

## Project Structure

```
iam-policy-auditor/
├── iam_validator/               # Main package
│   ├── __version__.py          # Version (sync with pyproject.toml!)
│   ├── core/                   # Validation engine ([CLAUDE.md](iam_validator/core/CLAUDE.md))
│   │   ├── cli.py             # CLI entry point
│   │   ├── check_registry.py  # Check plugin system
│   │   ├── models.py          # Pydantic data models
│   │   ├── policy_loader.py   # JSON/YAML policy loading
│   │   ├── policy_checks.py   # Validation orchestrator
│   │   ├── pr_commenter.py    # PR comment posting + diff filtering
│   │   ├── report.py          # Report generation (summary, context issues)
│   │   ├── aws_service/       # AWS API integration
│   │   ├── config/            # Configuration system
│   │   └── formatters/        # Output formatters (7 formats)
│   ├── checks/                 # 21 built-in checks ([CLAUDE.md](iam_validator/checks/CLAUDE.md))
│   ├── commands/               # 8 CLI commands ([CLAUDE.md](iam_validator/commands/CLAUDE.md))
│   ├── mcp/                    # MCP server ([CLAUDE.md](iam_validator/mcp/CLAUDE.md))
│   ├── sdk/                    # Public SDK API ([CLAUDE.md](iam_validator/sdk/CLAUDE.md))
│   └── integrations/           # GitHub, MS Teams ([CLAUDE.md](iam_validator/integrations/CLAUDE.md))
├── tests/                       # Test suite ([CLAUDE.md](tests/CLAUDE.md))
├── examples/                    # Usage examples
│   ├── custom_checks/          # Example custom checks
│   ├── iam-test-policies/      # Test policies
│   └── configs/                # Example configs
├── docs/                        # MkDocs documentation ([CLAUDE.md](docs/CLAUDE.md))
└── .claude/                     # Claude Code config
    ├── settings.json           # Hooks configuration
    └── commands/               # Slash commands
```

### Key Files

| Purpose    | File                                         | Notes                                       |
| ---------- | -------------------------------------------- | ------------------------------------------- |
| CLI Entry  | `iam_validator/core/cli.py`                  | Argparse-based CLI                          |
| Check Base | `iam_validator/core/check_registry.py`       | `PolicyCheck` ABC                           |
| Models     | `iam_validator/core/models.py`               | `IAMPolicy`, `Statement`, `ValidationIssue` |
| SDK API    | `iam_validator/sdk/__init__.py`              | Public library interface                    |
| Version    | `iam_validator/__version__.py`               | Keep in sync with pyproject.toml            |
| Config     | `iam_validator/core/config/config_loader.py` | YAML config loader                          |
| MCP Server | `iam_validator/mcp/server.py`                | FastMCP server with 25+ tools               |
| Action     | `action.yaml`                                | GitHub Action definition                    |

---

## Architecture Patterns

### Check Plugin System

All checks inherit from `PolicyCheck` in `core/check_registry.py`:

```python
from typing import ClassVar
from iam_validator.core.check_registry import CheckConfig, PolicyCheck
from iam_validator.core.models import Statement, ValidationIssue

class MyCheck(PolicyCheck):
    check_id: ClassVar[str] = "my_check"
    description: ClassVar[str] = "What this check validates"
    default_severity: ClassVar[str] = "medium"  # low|medium|high|critical

    async def execute(
        self,
        statement: Statement,
        statement_idx: int,
        fetcher: AWSServiceFetcher,
        config: CheckConfig,
    ) -> list[ValidationIssue]:
        issues = []
        # Statement-level validation logic
        return issues
```

**Real example**: See `iam_validator/checks/wildcard_action.py`

### Policy Processing Pipeline

```
PolicyLoader.load_from_file()
    ↓
validate_policies() in policy_checks.py
    ↓
CheckRegistry.execute_policy_checks() [policy-level]
    ↓
CheckRegistry.execute_checks_parallel() [statement-level, parallel async]
    ↓
ReportGenerator.generate_report()
    ↓
Formatter output (console|json|markdown|sarif|csv|html)
```

### AWS Service Fetcher

```python
from iam_validator.core.aws_service import AWSServiceFetcher

async with AWSServiceFetcher() as fetcher:
    # Validate action exists
    is_valid, error, is_wildcard = await fetcher.validate_action("s3:GetObject")

    # Expand wildcards
    actions = await fetcher.expand_wildcard_action("s3:Get*")

    # Fetch service definition
    s3_service = await fetcher.fetch_service_by_name("s3")
```

**Caching**: Memory LRU + disk TTL (7 days). Platform-specific paths.

---

## Quick Search Commands

```bash
# Find check by ID
rg -n "check_id.*=.*\"wildcard" iam_validator/checks/

# Find where model is used
rg -n "ValidationIssue" iam_validator/

# Find CLI command handler
rg -n "class.*Command" iam_validator/commands/

# Find config option
rg -n "config.get\(" iam_validator/

# Find test for specific check
rg -n "test.*wildcard" tests/

# Find SDK function
rg -n "^def |^async def " iam_validator/sdk/

# Find MCP tools
rg -n "@mcp.tool" iam_validator/mcp/server.py
```

---

## Adding New Components

### New Check

1. Create `iam_validator/checks/my_check.py` (copy from `wildcard_action.py`)
2. Add import to `iam_validator/checks/__init__.py`
3. Register in `iam_validator/core/check_registry.py:create_default_registry()`
4. Add test in `tests/checks/test_my_check.py`

**Use**: `/add-check my_check_name` to scaffold automatically

### New CLI Command

1. Create `iam_validator/commands/my_command.py` (inherit from `Command`)
2. Add to `ALL_COMMANDS` list in `iam_validator/commands/__init__.py`
3. Add test in `tests/commands/test_my_command.py`
4. Add completions in `iam_validator/commands/completion.py`

### New Output Formatter

1. Create `iam_validator/core/formatters/my_format.py` (inherit from `BaseFormatter`)
2. Register in formatter selection logic

---

## Built-in Checks (21)

| Check ID                       | Category | Severity | Description                          |
| ------------------------------ | -------- | -------- | ------------------------------------ |
| `action_validation`            | AWS      | error    | Actions exist in AWS                 |
| `condition_key_validation`     | AWS      | error    | Condition keys are valid             |
| `condition_type_mismatch`      | AWS      | error    | Operator-value type match            |
| `resource_validation`          | AWS      | error    | Resource ARN format                  |
| `principal_validation`         | AWS      | high     | Principal format (resource policies) |
| `policy_structure`             | AWS      | error    | Required fields, valid values        |
| `policy_size`                  | AWS      | error    | Character size limits                |
| `sid_uniqueness`               | AWS      | warning  | Unique SIDs across statements        |
| `set_operator_validation`      | AWS      | error    | ForAllValues/ForAnyValue usage       |
| `ifexists_condition_usage`     | AWS      | warning  | IfExists condition validation        |
| `mfa_condition_antipattern`    | AWS      | warning  | MFA anti-pattern detection           |
| `trust_policy_validation`      | AWS      | high     | Trust policy + confused deputy       |
| `not_principal_validation`     | AWS      | warning  | NotPrincipal usage patterns          |
| `action_resource_matching`     | AWS      | medium   | Actions match resource types         |
| `wildcard_action`              | Security | medium   | `Action: "*"` detection              |
| `wildcard_resource`            | Security | medium   | `Resource: "*"` detection            |
| `full_wildcard`                | Security | critical | `Action + Resource: "*"` detection   |
| `service_wildcard`             | Security | high     | `s3:*` style wildcards               |
| `sensitive_action`             | Security | medium   | 490+ privilege escalation actions    |
| `not_action_not_resource`      | Security | high     | Dangerous NotAction/NotResource      |
| `action_condition_enforcement` | Security | error    | Sensitive actions require conditions |

---

## CLI Commands (8)

| Command             | Purpose                            |
| ------------------- | ---------------------------------- |
| `validate`          | Validate IAM policies              |
| `analyze`           | AWS Access Analyzer integration    |
| `post-to-pr`        | Post results to GitHub PR          |
| `cache`             | Manage AWS service cache           |
| `download-services` | Download AWS definitions offline   |
| `query`             | Query AWS service definitions      |
| `completion`        | Shell completion scripts           |
| `mcp`               | Start MCP server for AI assistants |

---

## Testing Guidelines

- Tests mirror source structure in `tests/`
- Use `pytest-asyncio` for async tests (`asyncio_mode = "auto"`)
- Mock AWS API calls - don't make real requests
- Example policies in `examples/iam-test-policies/`
- Colocate fixtures with test files or in `conftest.py`

```python
# Test pattern
import pytest
from iam_validator.checks.my_check import MyCheck

@pytest.mark.asyncio
async def test_my_check_detects_issue():
    check = MyCheck()
    statement = Statement(...)
    issues = await check.execute(statement, 0, mock_fetcher, config)
    assert len(issues) == 1
    assert issues[0].severity == "high"
```

---

## Git Conventions

**Commit format** (Conventional Commits):

- `feat:` New features
- `fix:` Bug fixes
- `docs:` Documentation
- `refactor:` Code refactoring
- `test:` Test changes
- `chore:` Build/tooling

**Branch naming**:

- `feature/description`
- `fix/issue-number-description`
- `docs/what-changed`

---

## CI/CD Workflows

| Workflow                  | Trigger         | Purpose                            |
| ------------------------- | --------------- | ---------------------------------- |
| `ci.yml`                  | push/PR         | Lint, test (3.10-3.14), build      |
| `release.yml`             | tag v\*.\*.\*   | Build + publish to PyPI            |
| `pre-release.yml`         | manual dispatch | Create alpha/beta/rc pre-releases  |
| `cleanup-prereleases.yml` | daily / manual  | Delete pre-releases older than 30d |
| `docs.yml`                | push to main    | Build + deploy MkDocs to Pages     |
| `codeql.yml`              | weekly + push   | Security analysis                  |
| `scorecard.yml`           | weekly          | OpenSSF Scorecard                  |

---

## Releasing

Use `/create-version-tag` command, or manually:

1. Update both version files
2. `git tag -s v1.x.x -m "Release v1.x.x"`
3. `git push origin v1.x.x`
4. GitHub Actions auto-publishes to PyPI (trusted publishing)

---

## Security

- Never commit secrets or credentials
- `.env*` files are gitignored
- Use AWS IAM roles in CI, not access keys
- Trusted publishing for PyPI (no stored tokens)
- CodeQL + Scorecard run weekly

---

## MCP Server Integration

```bash
# Quick start with uvx (recommended)
uvx --from "iam-policy-validator[mcp]" iam-validator-mcp

# Local development
uv sync --extra mcp && iam-validator-mcp

# Debug with MCP Inspector
make mcp-inspector
```

**25+ tools** across validation, generation, query, and org config categories.
See [iam_validator/mcp/CLAUDE.md](iam_validator/mcp/CLAUDE.md) for full tool reference, Claude Desktop config, and development guide.

---

## Tool Permissions

| Tool               | Permission | Notes                     |
| ------------------ | ---------- | ------------------------- |
| Read any file      | ✅ Allowed | Full codebase access      |
| Write Python files | ✅ Allowed | Auto-formatted with ruff  |
| Run tests/linting  | ✅ Allowed | `pytest`, `ruff`, `mypy`  |
| Edit .env files    | ❌ Blocked | Requires explicit consent |
| Force push         | ❌ Blocked | Safety hook prevents      |
| Push to main       | ⚠️ Warning | Prompts for PR creation   |
| Delete files       | ⚠️ Caution | `rm -rf /` blocked        |

---

## Subdirectory Context

| Directory                     | CLAUDE.md Purpose                    |
| ----------------------------- | ------------------------------------ |
| `iam_validator/core/`         | Core architecture details            |
| `iam_validator/checks/`       | Check development patterns           |
| `iam_validator/mcp/`          | MCP server tools and templates       |
| `iam_validator/sdk/`          | SDK usage and extension              |
| `iam_validator/commands/`     | CLI command patterns                 |
| `iam_validator/integrations/` | GitHub PR posting, MS Teams          |
| `tests/`                      | Testing patterns and fixtures        |
| `docs/`                       | MkDocs documentation and conventions |

When working in these directories, their CLAUDE.md files provide specific guidance.
