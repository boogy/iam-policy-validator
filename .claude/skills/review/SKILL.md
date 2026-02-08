---
name: review
description: Comprehensive code review of recent changes in the iam-policy-validator project. Use when the user wants a code review, quality check, or audit of recent changes. Triggers on "/review", "review my changes", "code review", or "check code quality".
---

# Review

Perform a comprehensive code review of recent changes.

## Workflow

### 1. Gather Changes

```bash
git status
git diff --name-only HEAD~5
git log --oneline -10
```

Categorize modified files by type (check, command, core, tests, docs).

### 2. Review Against Project Standards

**Python code**: Type hints on public functions? Async patterns correct? Pydantic models proper? Error handling appropriate?

**Checks** (`iam_validator/checks/`): Inherits `PolicyCheck`? Has `check_id`, `description`, `default_severity` ClassVars? Uses `self.get_severity(config)`? Returns `list[ValidationIssue]`?

**Tests**: Uses `@pytest.mark.asyncio`? Mock fixtures for AWS calls? Both positive and negative cases? Config overrides tested?

**Security**: No secrets/credentials? No overly permissive file operations? Input validation present?

**Documentation**: CHANGELOG.md updated? CLAUDE.md files updated if structure changed? Commits signed?

### 3. Run Quality Checks

```bash
uv run ruff check iam_validator/
uv run mypy iam_validator/ --ignore-missing-imports
uv run pytest tests/ -v --tb=short
```

### 4. Output Format

```
### Summary
- X files reviewed
- Y issues found (X critical, Y high, Z medium)

### Critical Issues
- [file:line] Description and fix

### High Issues
- [file:line] Description and fix

### Recommendations
- General improvements

### Tests
- Pass/fail status
- Coverage changes
```
