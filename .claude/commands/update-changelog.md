---
description: Update CHANGELOG.md with recent changes following Common Changelog format
---

You are updating `CHANGELOG.md` for the iam-policy-validator project following the [Common Changelog](https://common-changelog.org/) specification.

Optional argument: $ARGUMENTS (can be a check name, issue number, PR number, or description of what changed)

## Format Rules (MUST follow)

### Categories — only these four, in this exact order

| Category      | Use For                                                  |
| ------------- | -------------------------------------------------------- |
| `### Changed` | Modifications to existing functionality, refactors, deps |
| `### Added`   | New checks, features, commands, SDK functions, CLI opts  |
| `### Removed` | Deleted features, deprecated functionality               |
| `### Fixed`   | Bug fixes, corrected behavior                            |

**MUST NOT** use non-standard categories like `Improved`, `Documentation`, `Security`, or `Dependencies`. Merge those entries into the four standard categories above:

- Enhancements to existing checks → `Changed`
- Documentation for new features → `Added`
- Doc-only formatting fixes → omit (noise)
- Dependency updates → `Changed`
- Vulnerability fixes → `Fixed`

### Entry format

Every entry **MUST** follow this structure:

```
- <Imperative-mood verb> <description> ([#PR])
```

Rules:

1. **Imperative mood, present tense** — "Add", "Fix", "Remove", "Change", "Detect", "Warn", "Use", "Replace", "Extract", "Consolidate" — NOT past tense ("Added", "Fixed") or noun phrases ("New check for X")
2. **Self-describing** — readable without the category heading for context
3. **Single line** preferred — use sub-bullets only when a change has multiple distinct aspects
4. **References required** — append PR or commit link in parentheses: `([#73])`. Define link references at the bottom of the version section: `[#73]: https://github.com/boogy/iam-policy-validator/pull/73`. Omit references only for uncommitted changes that have no PR yet
5. **Be specific** — "Add CIDR validation for `IpAddress` operator" not "Improve validation"

### What to include and exclude

**Include:**

- New features, checks, commands, SDK functions
- Bug fixes
- Behavioral changes to existing functionality
- Refactorings (potential side effects)
- New documentation for features
- Runtime environment / dependency changes

**Exclude (noise):**

- Dotfile changes (`.gitignore`, `.github`)
- Dev-only dependency bumps
- Minor code style tweaks
- Documentation formatting adjustments (count updates, typo fixes)
- CI-only changes unless they affect users

### Version sections

Format: `## [X.Y.Z] - YYYY-MM-DD`

- No `v` prefix on version numbers
- ISO 8601 dates only
- First release gets a `_First release._` notice
- No `## Unreleased` section (impractical per Common Changelog — references can't be added pre-release)

### Comparison links

Maintain reference-style links at the very bottom of the file:

```markdown
[1.18.0]: https://github.com/boogy/iam-policy-validator/compare/v1.17.0...v1.18.0
[1.17.0]: https://github.com/boogy/iam-policy-validator/compare/v1.16.0...v1.17.0
```

### No non-release content

The changelog **MUST NOT** contain versioning policy, supported versions tables, deprecation policy, or migration guides. Those belong in `CONTRIBUTING.md`, `SECURITY.md`, or `UPGRADING.md`.

## Steps

### 1. Gather Changes

Determine what changed since the last changelog entry:

```bash
# Find the last tagged version
git describe --tags --abbrev=0

# Commits since last tag (with PR references)
git log $(git describe --tags --abbrev=0)..HEAD --oneline

# Files changed
git diff --name-only $(git describe --tags --abbrev=0)..HEAD

# Uncommitted changes (also need changelog entries)
git diff --name-only
git diff --name-only --cached
```

If `$ARGUMENTS` is provided, use it as context for what changed (e.g., a check name, issue number, or description).

### 2. Categorize Changes

Assign each change to one of the four standard categories (Changed → Added → Removed → Fixed). When in doubt:

- New validation logic added to an existing check → `Added`
- Existing validation logic changed in behavior → `Changed`
- Internal refactoring with no user-facing change → `Changed`
- Bug that produced wrong results now fixed → `Fixed`

### 3. Write Entries

Write each entry in imperative mood with a present-tense verb. Append PR references.

### 4. Determine Version Section

**If a version section for the current version already exists** (e.g., `## [1.17.0] - 2026-02-08`):

- Add entries under the existing section in the appropriate category

**If creating a new version section**:

- Insert after the header block and before the previous version
- Use format: `## [X.Y.Z] - YYYY-MM-DD`
- Add the comparison link at the bottom of the file

**If changes are unreleased** (no version bump planned yet):

- Add under the existing latest version section, or ask the user

### 5. Update Comparison Links

If a new version was added, add a new comparison link at the bottom and update the previous latest link:

```markdown
[X.Y.Z]: https://github.com/boogy/iam-policy-validator/compare/vPREV...vX.Y.Z
```

### 6. Format

```bash
npx prettier --write CHANGELOG.md
```

## Entry Examples

```markdown
### Changed

- Use maximum severity across all matched actions in `sensitive_action` instead of first match ([#80])
- Remove `PolicyValidationLimits` class from `PolicyLoader`; size validation now handled by dedicated checks ([#80])
- Extract `format_list_with_backticks()` utility to `checks/utils/formatting.py` for reuse across checks ([#80])

### Added

- Add `not_principal_validation` check detecting dangerous `NotPrincipal` usage patterns ([#80]):
  - Flag `NotPrincipal` with `Effect: Allow` as error (not supported by AWS)
  - Flag `NotPrincipal` with `Effect: Deny` as warning (deprecated pattern)
  - Suggest using `Principal: "*"` with condition operators (`ArnNotEquals`) instead
- Add SCP-specific size limit validation (5,120 bytes) in `policy_type_validation` ([#80])
- Add operator-specific value format validation in `condition_type_mismatch` ([#80]):
  - Validate CIDR notation for `IpAddress`/`NotIpAddress` (IPv4/IPv6)
  - Validate ARN format for `ArnEquals`/`ArnLike` (`arn:` prefix or template variables)

### Fixed

- Fix `aws:ResourceOrgPaths` condition example in `action_condition_enforcement` to use `ForAnyValue:StringLike` instead of `StringEquals` ([#80])
- Replace deprecated `asyncio.get_event_loop()` with `asyncio.get_running_loop()` in AWS service client ([#80])

[#80]: https://github.com/boogy/iam-policy-validator/pull/80
```

## Anti-Patterns (MUST NOT)

- **MUST NOT** copy verbatim git log entries — curate for consumers
- **MUST NOT** use past-tense verbs — "Add" not "Added", "Fix" not "Fixed"
- **MUST NOT** start entries with noun phrases — "New check for X" → "Add check for X"
- **MUST NOT** use `### Improved`, `### Documentation`, `### Security`, or `### Dependencies`
- **MUST NOT** use bold sub-headings within lists (e.g., `**Shell Completions**`)
- **MUST NOT** include an `[Unreleased]` section or link
- **MUST NOT** include non-release content (versioning policy, migration guides, supported versions)

## Integration

This command is invoked by other workflows:

- `/create-pr` — changelog update before creating the PR
- `/create-version-tag` — changelog update as part of version bump
- `/add-check` — add entry for new check under `### Added`
- `/fix-issue` — add entry for the fix under `### Fixed`

## Important Rules

- **MUST** follow the four standard categories in exact order
- **MUST** use imperative mood, present tense for all entries
- **MUST** append PR/commit references where available
- **MUST** run prettier after editing
- **MUST NOT** add non-standard categories or non-release content
