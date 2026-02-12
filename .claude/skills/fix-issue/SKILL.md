---
name: fix-issue
description: Analyze and fix a GitHub issue for the iam-policy-validator project. Use when the user wants to fix a GitHub issue, resolve a bug report, or implement a feature request from an issue. Triggers on "/fix-issue", "fix issue #42", "resolve this GitHub issue", or "work on issue".
---

# Fix Issue

Analyze and fix a GitHub issue end-to-end.

## Workflow

Given the issue number: $ARGUMENTS

### 1. Get Issue Details

```bash
gh issue view $ARGUMENTS
```

Understand: problem/feature, expected vs actual behavior, reproduction steps.

### 2. Search Relevant Code

```bash
rg -n "relevant_keyword" iam_validator/
rg -n "relevant_keyword" tests/
```

Read the CLAUDE.md in relevant directories for patterns.

### 3. Plan the Fix

Identify files to modify, new tests needed, breaking changes.

### 4. Implement

Follow patterns from CLAUDE.md files. Add/update tests. Update docs if needed.

### 5. Update Documentation

- **CHANGELOG.md** — MUST add entry under appropriate section (Added/Changed/Fixed)
- **CLAUDE.md** — Update if fix changes project structure, check behavior, or patterns

### 6. Verify

```bash
uv run ruff check --fix iam_validator/
uv run pytest tests/ -k "relevant_pattern" -v
uv run pytest tests/ -v --tb=short
```

### 7. Commit

Use conventional commits, reference the issue, sign the commit:

```bash
git commit -s -S -m "fix: description (#$ARGUMENTS)"
```

### 8. Offer PR Creation

Ask if the user wants to create a PR using `/create-pr`.

## Rules

- Always run tests before considering fix complete
- Bugs: add regression test. Features: add feature tests
- ALWAYS update CHANGELOG.md
- ALWAYS sign commits with `-s -S`
- Don't push directly to main — use feature branch

## Examples

- `/fix-issue 42`
- `/fix-issue 123`
