---
description: Create the next version tag for the project
---

You are creating a new version tag for the iam-policy-validator project.

Optional argument: $ARGUMENTS (can be `patch`, `minor`, or `major` to skip the prompt)

## Pre-flight Checks

1. **Verify on main branch**:

   ```bash
   git branch --show-current
   ```

   - If NOT on main, STOP and ask user to switch: `git checkout main && git pull`
   - Tags should only be created from main branch

2. **Verify working tree is clean**:

   ```bash
   git status --porcelain
   ```

   - If there are uncommitted changes, STOP and ask user to commit or stash them

3. **Verify up to date with remote**:

   ```bash
   git fetch origin main
   git status -uno
   ```

   - If behind remote, ask user to pull first: `git pull origin main`

## Steps

### 1. Get Current Version

```bash
# Read from both files - they MUST match
grep "__version__" iam_validator/__version__.py
grep "^version" pyproject.toml | head -1
```

If versions don't match:

- STOP immediately
- Show both versions
- Ask user to fix the inconsistency before proceeding

### 2. Check Existing Tags

```bash
# Show recent tags for context
git tag --sort=-v:refname | head -10
```

### 3. Determine Version Bump

If `$ARGUMENTS` is `patch`, `minor`, or `major`, use that directly.

Otherwise, ask the user:

**"What type of version bump is this?"**

| Type      | Format            | Use Case                                |
| --------- | ----------------- | --------------------------------------- |
| **patch** | x.y.Z → x.y.(Z+1) | Bug fixes, documentation, small changes |
| **minor** | x.Y.z → x.(Y+1).0 | New features, backward compatible       |
| **major** | X.y.z → (X+1).0.0 | Breaking changes                        |

### 4. Calculate New Version

Example calculations:

- Current: `1.15.5`
  - patch → `1.15.6`
  - minor → `1.16.0`
  - major → `2.0.0`

### 5. Update Version Files

Update **BOTH** files with the new version:

**`iam_validator/__version__.py`** (line 6):

```python
__version__ = "X.Y.Z"
```

**`pyproject.toml`** (line 3):

```toml
version = "X.Y.Z"
```

Show the diff for user confirmation:

```bash
git diff iam_validator/__version__.py pyproject.toml
```

### 6. Update CHANGELOG.md

Follow the `/update-changelog` format rules to add a new version section `## [X.Y.Z] - YYYY-MM-DD` with entries gathered from git history since the last tag. It handles categorization, entry formatting, supported versions table, and comparison links.

### 7. Run Quality Checks

```bash
# Ensure everything passes before tagging
uv run ruff check .
uv run pytest -x -q
```

If checks fail, STOP and fix issues before proceeding.

### 8. Commit Version Bump

```bash
git add iam_validator/__version__.py pyproject.toml CHANGELOG.md
git commit -s -S -m "chore: bump version to X.Y.Z"
```

**Signing is mandatory**: Use `-s` for sign-off (DCO) and `-S` for GPG/SSH signing. All commits MUST be signed.

### 9. Create Signed Tag

**All tags MUST be signed with `-s` flag. No exceptions. NEVER use `git tag -a` (annotated only).**

```bash
# Create GPG/SSH-signed tag with release message
git tag -s vX.Y.Z -m "Release vX.Y.Z

Highlights:
- Key change 1
- Key change 2
"
```

### 10. Push Changes (WITH USER CONSENT)

**IMPORTANT**: Ask user for explicit consent before pushing!

Show what will be pushed:

```bash
echo "Will push:"
echo "  - Commit: $(git log -1 --oneline)"
echo "  - Tag: vX.Y.Z"
echo "  - To: origin/main"
```

Ask: **"Ready to push the version bump commit and tag to origin? (yes/no)"**

If user confirms:

```bash
git push origin main
git push origin vX.Y.Z
```

### 11. Verify

```bash
# Confirm tag exists locally and remotely
git tag --sort=-v:refname | head -5
git ls-remote --tags origin | grep vX.Y.Z
```

### 12. Post-Release

Inform user:

- Tag `vX.Y.Z` has been created and pushed
- GitHub Actions will automatically:
  - Build the package
  - Publish to PyPI (via trusted publishing)
  - Create a GitHub Release (if configured)

```bash
# Check release workflow status
gh run list --workflow=release.yml --limit=1
```

## Important Rules

- **MUST** update BOTH `__version__.py` AND `pyproject.toml`
- **MUST** keep version files in sync at all times
- **MUST** only create tags from main branch
- **MUST** ask user consent before pushing to remote
- **MUST** use signed tags (`git tag -s`). NEVER use `git tag -a`
- **MUST** sign all commits (`git commit -s -S`)
- **MUST** use `v` prefix for tags (e.g., `v1.15.6`)
- **MUST** update CHANGELOG.md in the version bump commit
- **NEVER** force push tags
- **NEVER** delete/recreate existing tags without explicit user request

## Quick Reference

```bash
# Full flow example for patch release
git checkout main && git pull
# ... update version files and CHANGELOG.md ...
git add iam_validator/__version__.py pyproject.toml CHANGELOG.md
git commit -s -S -m "chore: bump version to 1.15.6"
git tag -s v1.15.6 -m "Release v1.15.6"
git push origin main
git push origin v1.15.6
```

## Version File Locations

| File                           | Line | Format                  |
| ------------------------------ | ---- | ----------------------- |
| `iam_validator/__version__.py` | 6    | `__version__ = "X.Y.Z"` |
| `pyproject.toml`               | 3    | `version = "X.Y.Z"`     |
