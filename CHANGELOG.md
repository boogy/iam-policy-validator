# Changelog

All notable changes to IAM Policy Validator are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Planned

- Enhanced PR comment management with configurable limits

---

## [1.15.0] - 2025-01-22

### Added

**MCP Server Integration**

- Full FastMCP server with 25+ tools for AI assistants (`iam-validator mcp` command)
- Standalone `iam-validator-mcp` entry point for easy integration
- Policy validation, generation, and AWS service querying tools
- 15 built-in secure policy templates for common use cases
- Session-wide organization configuration management
- MCP Prompts for guided workflows (generate_secure_policy, fix_policy_issues_workflow, review_policy_security)
- Custom instructions support via YAML config, environment variable, CLI, or MCP tools
- Comprehensive MCP documentation with usage examples

**New Security Check**

- `not_action_not_resource` check for detecting dangerous NotAction/NotResource patterns (high severity)

**Query Command Enhancements**

- Support multiple actions in single query (`--name s3:GetObject dynamodb:Query`)
- Wildcard pattern expansion (`--name "iam:Get*"` or `--name "s3:*Object*"`)
- Field filter options: `--show-condition-keys`, `--show-resource-types`, `--show-access-level`
- Allow service prefix in `--name`, making `--service` optional (`--name s3:GetObject`)
- Deduplicate results when querying overlapping patterns

**Validation Improvements**

- `action_validation` now validates wildcard patterns (e.g., `s3:Get*`) to ensure they match real AWS actions
- `action_validation` now validates NotAction field
- `resource_validation` now validates NotResource field
- `wildcard_resource` check has condition-aware severity adjustment:
  - MEDIUM → LOW when global resource-scoping conditions present (aws:ResourceAccount, aws:ResourceOrgID, aws:ResourceOrgPaths)
  - MEDIUM → LOW when aws:ResourceTag/\* conditions are used AND all actions support the condition key

**Configuration**

- Add `hide_severities` option for severity-based finding filtering (global and per-check)
- Add `iam-policy-validator` CLI alias matching PyPI package name

**Cache Improvements**

- Cache refresh now updates all cached services (not just common ones)
- Expired cache files are kept for refresh instead of deleted
- Stale cache fallback when AWS API fails for graceful degradation

**SDK**

- Export `extract_condition_keys_from_statement()` in public API
- Add `is_condition_key_supported()` to AWSServiceFetcher

### Changed

- Development status upgraded to Production/Stable
- Batch operations use `asyncio.gather()` for parallel execution
- Template listing includes full variable metadata (name, description, required)
- Simplified condition key pattern matching for tag-key placeholders (forward-compatible)
- Test suite consolidated using `@pytest.mark.parametrize` (919 → 850 tests)

### Fixed

- Support parameterized condition key patterns like `s3:RequestObjectTag/<key>`
- MCP tests skip properly when fastmcp is not installed
- Improved loop prevention guidance for LLM clients

### Dependencies

- fastmcp as optional dependency (install with `[mcp]` extra)
- Updated CI dependencies (actions/cache, codeql-action, setup-uv, upload-pages-artifact)

---

## [1.14.7] - 2025-12-17

### Added

- MkDocs documentation site deployed to GitHub Pages
- Comprehensive SDK API reference documentation

### Fixed

- Correct repository name in all documentation links (iam-policy-auditor → iam-policy-validator)
- Fix SDK docstring formatting for proper mkdocstrings rendering
- Update PyPI metadata with correct documentation and changelog URLs

---

## [1.14.6] - 2025-12-15

### Fixed

- Separate security findings from validity errors in PR comments
- Respect ignored findings when managing PR labels and review state

---

## [1.14.5] - 2025-12-15

### Fixed

- Respect ignored findings when managing PR labels and review state

---

## [1.14.4] - 2025-12-12

### Fixed

- Show pass status and list ignored findings in summary when all blocking issues are ignored

---

## [1.14.3] - 2025-12-12

### Fixed

- Add pattern matching for service-specific condition keys with tag validation

---

## [1.14.2] - 2025-12-12

### Fixed

- Use APPROVE review event when validation passes to dismiss REQUEST_CHANGES

---

## [1.14.1] - 2025-12-11

### Fixed

- Enhanced SARIF formatter with dynamic rules and rich context
- Improved finding fingerprints for better PR comment deduplication

### Changed

- Updated dependencies (setup-uv, actions/checkout, codeql-action)

---

## [1.14.0] - 2024-12-10

### Added

- Enhanced PR comments with fingerprint-based matching
- Finding ignore system via PR comment replies
- Improved review comment deduplication

### Changed

- Better production readiness for GitHub Action integration

---

## [1.13.1] - 2024-12

### Fixed

- Bug fixes and stability improvements

---

## [1.13.0] - 2024-12

### Added

- Query command for exploring AWS service definitions
- Shell completion support (bash, zsh, fish)

---

## [1.12.0] - 2024-11

### Added

- Trust policy validation check
- Enhanced condition type mismatch detection

### Changed

- Improved AWS service fetcher performance

---

## [1.11.0] - 2024-11

### Added

- Action-resource matching validation
- Set operator validation for conditions (ForAllValues/ForAnyValue)

### Changed

- Expanded sensitive actions database (490+ actions)

---

## [1.10.0] - 2024-10

### Added

- MFA condition check for sensitive operations
- Condition key validation improvements

### Changed

- Better error messages for validation failures

---

## [1.9.0] - 2024-10

### Added

- GitHub PR review comments (inline comments on changed lines)
- Multiple output formats (JSON, SARIF, CSV, HTML, Markdown)

---

## [1.8.0] - 2024-09

### Added

- AWS Access Analyzer integration
- Offline validation mode with pre-downloaded service definitions

---

## [1.7.0] - 2024-09

### Added

- Custom checks support via `--custom-checks-dir`
- Configuration file support (`iam-validator.yaml`)

### Changed

- Modular check architecture

---

## [1.6.0] - 2024-08

### Added

- Service Control Policy (SCP) validation
- Principal validation for resource policies

---

## [1.5.0] - 2024-08

### Added

- Modular Python configuration system (5-10x faster startup)
- Split security checks into individual modules:
  - `wildcard_action` - Wildcard actions (Action: "\*")
  - `wildcard_resource` - Wildcard resources (Resource: "\*")
  - `service_wildcard` - Service-level wildcards (e.g., "s3:\*")
  - `sensitive_action` - Sensitive actions without conditions
  - `full_wildcard` - Action:_ + Resource:_ (critical)
- GitHub Action RESOURCE_CONTROL_POLICY support
- GitHub Actions job summary output

### Changed

- Comprehensive documentation overhaul

---

## [1.4.0] - 2024-07

### Added

- Resource Control Policy (RCP) support with 8 validation checks
- Enhanced principal validation:
  - Blocked principals (e.g., public access "\*")
  - Allowed principals whitelist
  - Required conditions for specific principals
  - Service principal validation
- SID format validation
- Policy type validation for all 4 policy types

---

## [1.3.0] - 2024-06

### Added

- Modular Python configuration system
- Condition requirement templates
- Action condition enforcement check

---

## [1.2.0] - 2024-05

### Added

- Smart IAM policy detection and filtering
- YAML policy support
- Streaming mode for large policy sets

---

## [1.1.0] - 2024-04

### Added

- Split security checks into individual modules
- Configurable check system
- Per-check severity overrides

---

## [1.0.0] - 2024-03

### Added

- Initial release
- Core IAM policy validation engine
- AWS service definition fetching with caching
- GitHub Action for CI/CD integration
- CLI tool with rich console output
- Python library API

---

## Versioning Policy

This project follows [Semantic Versioning](https://semver.org/):

- **MAJOR** (X.0.0): Breaking changes to CLI, configuration, or library API
- **MINOR** (0.X.0): New features, new checks, backwards-compatible enhancements
- **PATCH** (0.0.X): Bug fixes, documentation updates, dependency updates

### Supported Versions

| Version | Support Status         |
| ------- | ---------------------- |
| 1.15.x  | ✅ Active development  |
| 1.14.x  | ⚠️ Critical fixes only |
| < 1.14  | ❌ End of life         |

### Deprecation Policy

- Deprecated features are announced at least one minor version before removal
- Deprecated features emit warnings when used
- Breaking changes are documented in the MAJOR version release notes

---

## Migration Guides

### Migrating to v1.5.0+

The modular configuration system introduced in v1.5.0 changed how checks are configured:

**Before (v1.4.x):**

```yaml
checks:
  wildcard: high
  sensitive_actions: medium
```

**After (v1.5.0+):**

```yaml
wildcard_action:
  enabled: true
  severity: high

sensitive_action:
  enabled: true
  severity: medium
```

### Migrating to v1.4.0+

Resource Control Policy (RCP) support requires specifying policy type:

```bash
# Explicit policy type for RCPs
iam-validator validate --policy-type RESOURCE_CONTROL_POLICY policies/
```

---

[Unreleased]: https://github.com/boogy/iam-policy-validator/compare/v1.15.0...HEAD
[1.15.0]: https://github.com/boogy/iam-policy-validator/compare/v1.14.7...v1.15.0
[1.14.7]: https://github.com/boogy/iam-policy-validator/compare/v1.14.6...v1.14.7
[1.14.6]: https://github.com/boogy/iam-policy-validator/compare/v1.14.5...v1.14.6
[1.14.5]: https://github.com/boogy/iam-policy-validator/compare/v1.14.4...v1.14.5
[1.14.4]: https://github.com/boogy/iam-policy-validator/compare/v1.14.3...v1.14.4
[1.14.3]: https://github.com/boogy/iam-policy-validator/compare/v1.14.2...v1.14.3
[1.14.2]: https://github.com/boogy/iam-policy-validator/compare/v1.14.1...v1.14.2
[1.14.1]: https://github.com/boogy/iam-policy-validator/compare/v1.14.0...v1.14.1
[1.14.0]: https://github.com/boogy/iam-policy-validator/compare/v1.13.1...v1.14.0
[1.13.1]: https://github.com/boogy/iam-policy-validator/compare/v1.13.0...v1.13.1
[1.13.0]: https://github.com/boogy/iam-policy-validator/compare/v1.12.0...v1.13.0
[1.12.0]: https://github.com/boogy/iam-policy-validator/compare/v1.11.0...v1.12.0
[1.11.0]: https://github.com/boogy/iam-policy-validator/compare/v1.10.0...v1.11.0
[1.10.0]: https://github.com/boogy/iam-policy-validator/compare/v1.9.0...v1.10.0
[1.9.0]: https://github.com/boogy/iam-policy-validator/compare/v1.8.0...v1.9.0
[1.8.0]: https://github.com/boogy/iam-policy-validator/compare/v1.7.0...v1.8.0
[1.7.0]: https://github.com/boogy/iam-policy-validator/compare/v1.6.0...v1.7.0
[1.6.0]: https://github.com/boogy/iam-policy-validator/compare/v1.5.0...v1.6.0
[1.5.0]: https://github.com/boogy/iam-policy-validator/compare/v1.4.0...v1.5.0
[1.4.0]: https://github.com/boogy/iam-policy-validator/compare/v1.3.0...v1.4.0
[1.3.0]: https://github.com/boogy/iam-policy-validator/compare/v1.2.0...v1.3.0
[1.2.0]: https://github.com/boogy/iam-policy-validator/compare/v1.1.0...v1.2.0
[1.1.0]: https://github.com/boogy/iam-policy-validator/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/boogy/iam-policy-validator/releases/tag/v1.0.0
