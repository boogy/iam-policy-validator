---
description: Create a pull request with current changes
---

You are creating a pull request for the iam-policy-validator repository.

Optional argument: $ARGUMENTS (can be a PR title or description hint)

## Pre-flight Checks

1. **Verify gh CLI is authenticated**:

   ```bash
   gh auth status
   ```

   If not authenticated, instruct user to run `gh auth login`

2. **Check git status**:

   ```bash
   git status
   git branch --show-current
   ```

3. **Verify NOT on main/master branch**:
   - If on main/master, STOP and ask user to create a feature branch first
   - Suggest: `git checkout -b feature/description`

## Steps

### 1. Gather Context

```bash
# See uncommitted changes
git diff --stat

# See commits not yet pushed (compared to main)
git log --oneline main..HEAD

# See recent commits for style reference
git log --oneline -5 main
```

### 2. Handle Uncommitted Changes

If there are uncommitted changes:

- Show the user what's uncommitted
- Ask if they want to:
  a) Commit these changes (suggest a message following conventional commits)
  b) Stash them for later
  c) Abort the PR creation

If committing:

```bash
git add -A
git commit -s -S -m "type: description"
```

**Signing is mandatory**: Use `-s` for sign-off (DCO) and `-S` for GPG/SSH signing. All commits MUST be signed.

### 3. Version Increment (Optional)

Ask the user: **"Does this PR require a version increment?"**

- If **NO**, skip to step 4
- If **YES**, ask which type:
  - **patch** (x.y.Z) - Bug fixes, small changes, documentation updates
  - **minor** (x.Y.0) - New features, backward compatible changes
  - **major** (X.0.0) - Breaking changes

If version increment is needed:

```bash
# Read current versions (must match!)
cat iam_validator/__version__.py | grep __version__
cat pyproject.toml | head -5 | grep version
```

a. Verify both files have the **same** version
b. Calculate next version
c. Update BOTH files:

- `iam_validator/__version__.py` (line 6): `__version__ = "X.Y.Z"`
- `pyproject.toml` (line 3): `version = "X.Y.Z"`
  d. Update `CHANGELOG.md` with new version section
  e. Show changes for user confirmation
  f. Create version bump commit:

```bash
git add iam_validator/__version__.py pyproject.toml CHANGELOG.md
git commit -s -S -m "chore: bump version to X.Y.Z"
```

### 4. Update CHANGELOG.md and CLAUDE.md

**CHANGELOG.md** — MUST be updated for every PR. Follow the `/update-changelog` format rules to update it following the project's Keep a Changelog format.

**CLAUDE.md** — Update if the PR changes project structure, patterns, or conventions:

- New checks → update root `CLAUDE.md` check table and `iam_validator/checks/CLAUDE.md`
- New commands → update root `CLAUDE.md` command table and `iam_validator/commands/CLAUDE.md`
- Architecture changes → update relevant subdirectory `CLAUDE.md`
- New dependencies → update root `CLAUDE.md` stack description

If files were updated, stage them:

```bash
git add CHANGELOG.md **/CLAUDE.md
git commit -s -S -m "docs: update changelog and project documentation"
```

### 5. Run Quality Checks

```bash
# Format code
uv run ruff format .

# Lint
uv run ruff check .

# Run tests (ask user if they want full test suite or quick check)
uv run pytest -x -q  # Quick: stop on first failure
# OR
uv run pytest        # Full suite
```

If checks fail:

- Show the errors
- Ask user if they want to fix them before proceeding
- Do NOT create PR with failing checks

### 6. Push Branch

```bash
# Push with upstream tracking
git push -u origin $(git branch --show-current)
```

### 7. Create Pull Request

Determine PR details:

- **Title**: Use conventional commit format based on changes

  - `feat:` - New features
  - `fix:` - Bug fixes
  - `docs:` - Documentation only
  - `refactor:` - Code refactoring
  - `chore:` - Maintenance tasks
  - `test:` - Test additions/changes

- **Labels**: Suggest based on files changed:
  - Python code → `python`
  - Dependencies → `dependencies`
  - Documentation → `documentation`
  - Checks → `checks`

```bash
gh pr create \
  --title "type: descriptive title" \
  --body "$(cat <<'EOF'
## Summary

- Brief description of what this PR does
- Key changes made
- Any important context

## Changes

- `file1.py`: Description of change
- `file2.py`: Description of change

## Testing

- [ ] All existing tests pass
- [ ] New tests added (if applicable)
- [ ] Manually tested with sample policies

## Checklist

- [ ] Code follows project style guidelines
- [ ] All commits are signed (GPG/SSH)
- [ ] CHANGELOG.md updated
- [ ] CLAUDE.md files updated (if project structure/patterns changed)
- [ ] Documentation updated (if needed)
EOF
)" \
  --label "python"
```

### 8. Return Results

Show the user:

- PR URL
- PR number
- Any warnings or notes

```bash
# Get PR URL
gh pr view --web
```

## Important Rules

- **NEVER** push directly to main/master
- **ALWAYS** sign commits with `-s -S` flags (sign-off + GPG/SSH)
- **ALWAYS** update CHANGELOG.md before creating PR
- **ALWAYS** update CLAUDE.md files if project structure, patterns, or checks changed
- **ALWAYS** keep version files in sync (`__version__.py` AND `pyproject.toml`)
- **ALWAYS** run `ruff check` before creating PR
- **NEVER** force push without explicit user consent
- Version bump commit should be **separate** from feature commits
- Ask for confirmation before any destructive or push operations

## Example Workflow

```bash
# Typical PR creation flow
git status                          # Check state
git diff --stat                     # Review changes
git add -A && git commit -s -S -m "feat: add new validation check"
uv run ruff format . && uv run ruff check .
uv run pytest -x -q
git push -u origin feature/new-check
gh pr create --title "feat: add new validation check" --body "..."
```
