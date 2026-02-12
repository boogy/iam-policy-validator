# Changelog

All notable changes to IAM Policy Validator are documented in this file.

The format is based on [Common Changelog](https://common-changelog.org/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.17.0] - 2026-02-08

### Changed

- Align SID format validation to AWS spec — alphanumeric only, no hyphens or underscores ([#79])
- Accept single `Statement` object (dict) in addition to array in `policy_structure`, matching AWS behavior ([#79])
- Suppress duplicate `NotAction`/`NotResource` findings when the combined critical finding is already emitted ([#79])
- Replace MD5 with SHA-256 for cache path generation ([#79])
- Consolidate GitHub Actions examples from 6 workflow files to 2 ([#79])

### Added

- Add `not_principal_validation` check — flag `NotPrincipal` with `Allow` as error, with `Deny` as warning ([#79])
- Add confused deputy detection in `trust_policy_validation` — detect service principals without `aws:SourceArn`/`aws:SourceAccount`, exempt 3 compute-bound safe services ([#79])
- Add off-diff PR comment pipeline — cascading fallback from inline to file-level to summary table for issues on unchanged lines ([#79])
- Add operator-specific value format validation in `condition_type_mismatch` — CIDR for `IpAddress`, ARN format for `ArnLike`, boolean for `Bool` ([#79])
- Add SCP-specific size limit validation (5,120 bytes) and `Principal`/`NotPrincipal` error messages ([#79])
- Add outdated policy version warning for `Version` `2008-10-17` ([#79])
- Add implicit grant analysis and remediation suggestions in `not_action_not_resource` ([#79])
- Add `--has-condition-key` filter and `--show-condition-keys`/`--show-arn-format`/`--show-resource-type` flags to `query` subcommands ([#79])
- Add SDK improvements: TypedDicts for query results, `filter_issues_by_check_id`/`filter_issues_by_severity`, `str | dict` in `validate_json()`, ARN utility exports, usage examples and test suite ([#79])

### Fixed

_Security:_

- Fix `is_glob_match()` unbounded recursion — add memoization to bound complexity
- Fix non-atomic disk cache writes — use temp file + `os.replace()`
- Fix CSV formula injection — sanitize all user-controlled fields including pivot table
- Fix thread-unsafe singletons (`CompiledPatterns`, `AWSGlobalConditions`, `SessionConfigManager`) — add `threading.Lock`

_Logic errors:_

- Fix `condition_key_validation` false positives for wildcard actions — `iam:Tag*`, `s3:Get*`, etc. now expand to matching actions before validating condition keys
- Fix `sensitive_action.execute_policy()` not expanding wildcard actions — `iam:Create*` now properly expanded before privilege escalation detection
- Fix `Action: "*"` bypassing all condition enforcement requirements
- Fix `sts:*` skipped in `trust_policy_validation` — now validates against all STS assume-role rules
- Fix case-sensitive comparisons in `service_wildcard` and `IfExists` null-check suppression — normalize to lowercase
- Fix `operator_type` variable mutation in `condition_type_mismatch` inner loop
- Fix `policy_size` stripping whitespace inside JSON string values
- Fix `not_action_not_resource` false positive on trust policies that validly omit `Resource`
- Fix `lstrip("./")` stripping individual chars in `codeowners.py` — use `removeprefix()`

_Bugs:_

- Fix regex caching in `regex.py` — `compile_and_cache()` was creating a new LRU on every call; `_pattern_cache` was unbounded
- Fix `LRUCache.__contains__` and `__len__` ignoring TTL on expired entries
- Fix index mismatch in `execute_checks_parallel()` when checks without configs are skipped
- Sync `KNOWN_CHECK_IDS` with all 21 registered check IDs
- Fix `_delete_comments_with_identifier()` not paginating ([#79])
- Fix `_strip_variables_from_arn()` to also handle Terraform and CloudFormation variables
- Fix bash/zsh shell completions: missing options, unreachable cases, command detection ([#79])
- Fix GitHub Action broken pipe error in cache status step — `ls | head` causes SIGPIPE exit code 2 under `pipefail`, preventing validation from running
- Fix `deep_merge` sharing list references between configs
- Add bounded cache eviction to `wildcard_resource.py` module-level caches

[#79]: https://github.com/boogy/iam-policy-validator/pull/79

---

## [1.16.0] - 2026-02-05

### Added

- Add `ifexists_condition_usage` check validating proper usage of the `IfExists` suffix on condition operators ([#77])
  - Detect `IfExists` on security-sensitive keys in Allow statements (may bypass controls)
  - Warn about non-negated `IfExists` weakening Deny statements
  - Flag redundant `IfExists` on always-present keys (e.g., `aws:SecureTransport`)
  - Optionally suggest `IfExists` for negated operators in Deny statements
- Add security-sensitive and always-present condition key constants in `condition_validators` module ([#77])
- Suppress false positive errors in `condition_key_validation` when `IfExists` is used with keys valid for some but not all actions ([#77])
- Detect `NullIfExists` as invalid syntax in `condition_type_mismatch` (the `Null` operator already checks for key existence) ([#77])
- Warn about compound `ForAllValues` + `IfExists` pattern in `set_operator_validation` (doubly permissive) ([#77])

[#77]: https://github.com/boogy/iam-policy-validator/pull/77

---

## [1.15.5] - 2025-01-28

### Fixed

- Remove `--instructions` and `--instructions-file` from `iam-validator mcp` subcommand completions; these options only exist in the standalone `iam-validator-mcp` command ([#73])
- Fix `validator()` and `validator_from_config()` to properly initialize and cleanup `AWSServiceFetcher` using `async with` for correct HTTP client lifecycle management ([#73])
- Remove unused `config` parameter from SDK validation functions (`validate_file`, `validate_directory`, `validate_json`, `quick_validate`, `get_issues`, `count_issues_by_severity`) ([#73])
- Fix `recursive` parameter in `validate_directory()` to actually pass through to `PolicyLoader.load_from_path()` ([#73])
- Expand SDK API reference with ARN utilities, query utilities, and policy utilities ([#72])

[#73]: https://github.com/boogy/iam-policy-validator/pull/73
[#72]: https://github.com/boogy/iam-policy-validator/pull/72

---

## [1.15.4] - 2025-01-27

### Fixed

- Remove duplicate `asyncio` import in query command (CodeQL: py/repeated-import) ([#71])
- Fix unused `action_list` variable in wildcard resource check; now include the action list in error messages for better context (CodeQL: py/unused-local-variable) ([#71])

[#71]: https://github.com/boogy/iam-policy-validator/pull/71

---

## [1.15.3] - 2025-01-27

### Added

- Add **critical** severity check for combined `NotAction` + `NotResource` with `Allow` effect, detecting near-administrator access patterns ([#69])
- Detect `BoolIfExists` with `aws:MultiFactorAuthPresent = false` as **high** severity (matches when key is missing entirely, more dangerous than `Bool`) ([#69])
- Detect `Null` with `aws:MultiFactorAuthPresent = true` as warning (checks if key doesn't exist, meaning no MFA) ([#69])
- Improve message formatting with markdown backticks for better GitHub PR comment rendering ([#69])

[#69]: https://github.com/boogy/iam-policy-validator/pull/69

---

## [1.15.2] - 2025-01-26

### Changed

- Change `principal_validation` default behavior to allow `*` with conditions; use `block_wildcard_principal: true` to restore strict blocking ([#66])
- Avoid duplicate findings when service principal wildcard is detected ([#66])

### Added

- Detect service principal wildcard (`{"Service": "*"}`) as critical severity in `principal_validation` ([#66])
- Add `block_wildcard_principal` and `block_service_principal_wildcard` configuration options for `principal_validation` ([#66])
- Require source verification conditions (`aws:SourceArn`, `aws:SourceAccount`, `aws:SourceVpce`, or `aws:SourceIp`) for `Principal: "*"` by default ([#66])
- Enhance ISO 8601 date validation with month/day range checks, leap year detection, and timezone offset validation ([#66])

[#66]: https://github.com/boogy/iam-policy-validator/pull/66

---

## [1.15.1] - 2025-01-24

### Fixed

- Validate `aws:RequestTag/${TagKey}` and `aws:ResourceTag/${TagKey}` as action/resource-specific condition keys, not global ([#65])
- Flag invalid usage of tag condition keys with descriptive error messages explaining the key is only for tagging operations ([#65])

[#65]: https://github.com/boogy/iam-policy-validator/pull/65

---

## [1.15.0] - 2025-01-22

### Changed

- Upgrade development status to Production/Stable ([#61])
- Use `asyncio.gather()` for parallel batch operations ([#61])
- Include full variable metadata (name, description, required) in template listing ([#61])
- Simplify condition key pattern matching for tag-key placeholders (forward-compatible) ([#61])
- Consolidate test suite using `@pytest.mark.parametrize` (919 → 850 tests) ([#61])
- Add fastmcp as optional dependency (install with `[mcp]` extra) ([#61])

### Added

- Add FastMCP server with 25+ tools for AI assistants (`iam-validator mcp` command and standalone `iam-validator-mcp` entry point) ([#61])
- Add 15 built-in secure policy templates for common use cases ([#61])
- Add session-wide organization configuration management ([#61])
- Add MCP Prompts for guided workflows (generate_secure_policy, fix_policy_issues_workflow, review_policy_security) ([#61])
- Add custom instructions support via YAML config, environment variable, CLI, or MCP tools ([#61])
- Add `not_action_not_resource` check for detecting dangerous NotAction/NotResource patterns (high severity) ([#61])
- Support multiple actions in single query (`--name s3:GetObject dynamodb:Query`) ([#61])
- Add wildcard pattern expansion in query command (`--name "iam:Get*"`) ([#61])
- Add field filter options: `--show-condition-keys`, `--show-resource-types`, `--show-access-level` ([#61])
- Validate wildcard patterns in `action_validation` to ensure they match real AWS actions ([#61])
- Validate NotAction and NotResource fields in `action_validation` and `resource_validation` ([#61])
- Add condition-aware severity adjustment in `wildcard_resource` (MEDIUM → LOW with global resource-scoping conditions) ([#61])
- Add `hide_severities` option for severity-based finding filtering (global and per-check) ([#61])
- Add `iam-policy-validator` CLI alias matching PyPI package name ([#61])
- Add cache refresh for all cached services, stale cache fallback when AWS API fails ([#61])
- Export `extract_condition_keys_from_statement()` and add `is_condition_key_supported()` to SDK ([#61])

### Fixed

- Support parameterized condition key patterns like `s3:RequestObjectTag/<key>` ([#61])
- Skip MCP tests properly when fastmcp is not installed ([#61])
- Improve loop prevention guidance for LLM clients ([#61])

[#61]: https://github.com/boogy/iam-policy-validator/pull/61

---

## [1.14.7] - 2025-12-17

### Added

- Deploy MkDocs documentation site to GitHub Pages ([#56])

### Fixed

- Correct repository name in all documentation links (iam-policy-auditor → iam-policy-validator) ([#57])
- Fix SDK docstring formatting for proper mkdocstrings rendering ([#57])
- Update PyPI metadata with correct documentation and changelog URLs ([#57])

[#57]: https://github.com/boogy/iam-policy-validator/pull/57
[#56]: https://github.com/boogy/iam-policy-validator/pull/56

---

## [1.14.6] - 2025-12-15

### Fixed

- Separate security findings from validity errors in PR comments ([#51])
- Respect ignored findings when managing PR labels and review state ([#51])

[#51]: https://github.com/boogy/iam-policy-validator/pull/51

---

## [1.14.5] - 2025-12-15

### Fixed

- Respect ignored findings when managing PR labels and review state ([#50])

[#50]: https://github.com/boogy/iam-policy-validator/pull/50

---

## [1.14.4] - 2025-12-12

### Fixed

- Show pass status and list ignored findings in summary when all blocking issues are ignored ([#48])

[#48]: https://github.com/boogy/iam-policy-validator/pull/48

---

## [1.14.3] - 2025-12-12

### Fixed

- Add pattern matching for service-specific condition keys with tag validation ([#47])

[#47]: https://github.com/boogy/iam-policy-validator/pull/47

---

## [1.14.2] - 2025-12-12

### Fixed

- Use APPROVE review event when validation passes to dismiss REQUEST_CHANGES ([#46])

[#46]: https://github.com/boogy/iam-policy-validator/pull/46

---

## [1.14.1] - 2025-12-11

### Changed

- Update dependencies (setup-uv, actions/checkout, codeql-action)

### Fixed

- Enhance SARIF formatter with dynamic rules and rich context
- Improve finding fingerprints for better PR comment deduplication

---

## [1.14.0] - 2024-12-10

### Changed

- Improve production readiness for GitHub Action integration

### Added

- Add PR comments with fingerprint-based matching
- Add finding ignore system via PR comment replies
- Improve review comment deduplication

---

## [1.13.1] - 2024-12

### Fixed

- Fix typo in action condition enforcement message ([#39])

[#39]: https://github.com/boogy/iam-policy-validator/pull/39

---

## [1.13.0] - 2024-12

### Added

- Add query command for exploring AWS service definitions
- Add shell completion support (bash, zsh, fish)

---

## [1.12.0] - 2024-11

### Changed

- Improve AWS service fetcher performance

### Added

- Add trust policy validation check
- Enhance condition type mismatch detection

---

## [1.11.0] - 2024-11

### Changed

- Expand sensitive actions database (490+ actions)

### Added

- Add action-resource matching validation
- Add set operator validation for conditions (ForAllValues/ForAnyValue)

---

## [1.10.0] - 2024-10

### Changed

- Improve error messages for validation failures

### Added

- Add MFA condition check for sensitive operations
- Improve condition key validation

---

## [1.9.0] - 2024-10

### Added

- Add GitHub PR review comments (inline comments on changed lines)
- Add multiple output formats (JSON, SARIF, CSV, HTML, Markdown)

---

## [1.8.0] - 2024-09

### Added

- Add AWS Access Analyzer integration
- Add offline validation mode with pre-downloaded service definitions

---

## [1.7.0] - 2024-09

### Changed

- Adopt modular check architecture

### Added

- Add custom checks support via `--custom-checks-dir`
- Add configuration file support (`iam-validator.yaml`)

---

## [1.6.0] - 2024-08

### Added

- Add Service Control Policy (SCP) validation
- Add principal validation for resource policies

---

## [1.5.0] - 2024-08

### Changed

- Overhaul documentation

### Added

- Add modular Python configuration system (5-10x faster startup)
- Split security checks into individual modules:
  - `wildcard_action` - Wildcard actions (Action: "\*")
  - `wildcard_resource` - Wildcard resources (Resource: "\*")
  - `service_wildcard` - Service-level wildcards (e.g., "s3:\*")
  - `sensitive_action` - Sensitive actions without conditions
  - `full_wildcard` - Action:\* + Resource:\* (critical)
- Add GitHub Action RESOURCE_CONTROL_POLICY support
- Add GitHub Actions job summary output

---

## [1.4.0] - 2024-07

### Added

- Add Resource Control Policy (RCP) support with 8 validation checks
- Enhance principal validation:
  - Blocked principals (e.g., public access "\*")
  - Allowed principals whitelist
  - Required conditions for specific principals
  - Service principal validation
- Add SID format validation
- Add policy type validation for all 4 policy types

---

## [1.3.0] - 2024-06

### Added

- Add modular Python configuration system
- Add condition requirement templates
- Add action condition enforcement check

---

## [1.2.0] - 2024-05

### Added

- Add smart IAM policy detection and filtering
- Add YAML policy support
- Add streaming mode for large policy sets

---

## [1.1.0] - 2024-04

### Added

- Split security checks into individual modules
- Add configurable check system
- Add per-check severity overrides

---

## [1.0.0] - 2024-03

_First release._

### Added

- Add core IAM policy validation engine
- Add AWS service definition fetching with caching
- Add GitHub Action for CI/CD integration
- Add CLI tool with rich console output
- Add Python library API

---

[1.17.0]: https://github.com/boogy/iam-policy-validator/compare/v1.16.0...v1.17.0
[1.16.0]: https://github.com/boogy/iam-policy-validator/compare/v1.15.5...v1.16.0
[1.15.5]: https://github.com/boogy/iam-policy-validator/compare/v1.15.4...v1.15.5
[1.15.4]: https://github.com/boogy/iam-policy-validator/compare/v1.15.3...v1.15.4
[1.15.3]: https://github.com/boogy/iam-policy-validator/compare/v1.15.2...v1.15.3
[1.15.2]: https://github.com/boogy/iam-policy-validator/compare/v1.15.1...v1.15.2
[1.15.1]: https://github.com/boogy/iam-policy-validator/compare/v1.15.0...v1.15.1
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
