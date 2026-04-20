---
description: Create a pull request with current changes
---

Prepare and push a branch so the user can open a pull request for the iam-policy-validator repository.

Optional argument: `$ARGUMENTS` (PR title or description hint).

## Pre-flight

1. **Check git state**:

   ```bash
   git status
   git branch --show-current
   ```

2. **Verify NOT on main/master** — if on main, stop and ask the user to create a feature branch first.

3. **Prefer raw `git`**. Do NOT invoke `gh` in this repo — its auth is scoped to the wrong identity for `boogy/*` personal repos. If the repo owner is a Nexthink/other org, `gh` is fine; if uncertain, use the browser URL approach described in step 5.

## Steps

### 1. Gather context

```bash
git diff --stat                               # uncommitted changes
git log --oneline main..HEAD                  # commits not yet pushed
git log --oneline -5 main                     # recent commit style
```

### 2. Handle uncommitted changes

If there are uncommitted changes, ask the user: commit, stash, or abort. If committing:

```bash
git add <files>
git commit -s -S -m "type: description"
```

**Signing is mandatory**: `-s` (DCO sign-off) + `-S` (GPG/SSH). Never skip.

### 3. Version increment (optional)

Ask: "Does this PR require a version increment?"

- If yes, use `/create-version-tag` with `patch`/`minor`/`major` to bump both `iam_validator/__version__.py` and `pyproject.toml` together, then return here.

### 4. Update CHANGELOG.md and CLAUDE.md

- **CHANGELOG.md** — add an entry under the current in-progress version following `/update-changelog` rules. Do not open an `[Unreleased]` section.
- **CLAUDE.md** — update when project structure/patterns changed:
  - New checks → root `CLAUDE.md` table + `iam_validator/checks/CLAUDE.md`
  - New commands → root `CLAUDE.md` table + `iam_validator/commands/CLAUDE.md`
  - Architecture changes → relevant subdirectory `CLAUDE.md`

If updated:

```bash
git add CHANGELOG.md **/CLAUDE.md
git commit -s -S -m "docs: update changelog and project documentation"
```

### 5. Run quality checks

```bash
uv run ruff format --check .
uv run ruff check .
uv run pytest -x -q                           # quick: stop on first failure
```

Do NOT proceed if any check fails. Fix first.

### 6. Push the branch

Ask for explicit user consent before pushing. Then:

```bash
git push -u origin "$(git branch --show-current)"
```

### 7. Surface the PR-creation URL

After `git push` the remote prints a "Create a pull request for …" URL. Print it for the user.

If the URL isn't printed (e.g. the branch was already pushed), build it manually:

```bash
BRANCH="$(git branch --show-current)"
ORIGIN_URL="$(git remote get-url origin)"
echo "Open: ${ORIGIN_URL%.git}/compare/main...${BRANCH}?expand=1"
```

Remind the user to set a conventional-commits title (`feat:`, `fix:`, `docs:`, `refactor:`, `chore:`, `test:`) and use the body template below. Do NOT create the PR via `gh` — the user opens it in the browser.

### 8. PR body template

```markdown
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
```

## Important rules

- **NEVER** push to main/master directly
- **ALWAYS** sign commits with `-s -S`
- **ALWAYS** update CHANGELOG.md before pushing
- **ALWAYS** keep version files in sync (`__version__.py` + `pyproject.toml`)
- **ALWAYS** run `ruff check` and `pytest` before pushing
- **ALWAYS** ask before pushing
- **NEVER** force push without explicit user consent
- **NEVER** use `gh` for `boogy/*` personal repos (wrong auth identity)
- Version bump commit should be **separate** from feature commits
