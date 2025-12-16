---
title: Releasing
description: Release process for maintainers
---

# Releasing

Release process for IAM Policy Validator maintainers.

## Version Numbering

We use [Semantic Versioning](https://semver.org/):

- **MAJOR** (1.0.0) — Breaking changes
- **MINOR** (1.1.0) — New features, backward compatible
- **PATCH** (1.1.1) — Bug fixes

## Release Process

### 1. Update Version

**Important:** Update version in BOTH files:

- `iam_validator/__version__.py` (line 6)
- `pyproject.toml` (via hatch dynamic version)

Or use the slash command:

```bash
/create-version-tag
```

### 2. Update Changelog

Add release notes to `CHANGELOG.md`:

```markdown
## [1.2.0] - 2024-01-15

### Added
- New feature X
- Support for Y

### Changed
- Improved Z performance

### Fixed
- Bug in A
```

### 3. Create Release Commit

```bash
git add iam_validator/__version__.py CHANGELOG.md
git commit -m "chore: release v1.2.0"
```

### 4. Create Tag

```bash
git tag -a v1.2.0 -m "Release v1.2.0"
git push origin main
git push origin v1.2.0
```

### 5. GitHub Actions Handles the Rest

The `release.yml` workflow automatically:

1. Builds the package
2. Publishes to PyPI (trusted publishing)
3. Creates GitHub Release with notes

## Pre-release Versions

For pre-releases:

```bash
# Beta
git tag -a v1.2.0-beta.1 -m "Beta release v1.2.0-beta.1"

# Release candidate
git tag -a v1.2.0-rc.1 -m "Release candidate v1.2.0-rc.1"
```

## Hotfix Process

For critical fixes:

1. Create branch from tag: `git checkout -b hotfix/v1.1.1 v1.1.0`
2. Apply fix
3. Update version to patch level
4. Tag and release

## PyPI Publishing

Publishing uses [trusted publishing](https://docs.pypi.org/trusted-publishers/) — no tokens needed.

The workflow in `.github/workflows/release.yml` handles everything automatically when a version tag is pushed.

## Rollback

If a release needs to be rolled back:

1. Yank the PyPI release (don't delete)
2. Create a new patch release with the fix
3. Document in CHANGELOG

```bash
# Yank from PyPI (requires twine)
twine yank iam-policy-validator 1.2.0
```
