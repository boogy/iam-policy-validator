# Checks Module

22 built-in IAM policy validation checks, plugin-based via `PolicyCheck`.
Extends [../../CLAUDE.md](../../CLAUDE.md).

---

## Adding a check

Use `/add-check my_check_name` to scaffold automatically. Manual steps:

1. Copy `wildcard_action.py` as the canonical small example.
2. Add to `iam_validator/checks/__init__.py`.
3. Register in `iam_validator/core/check_registry.py:create_default_registry()`.
4. Test in `tests/checks/test_my_check.py` (see `tests/checks/conftest.py` for `mock_fetcher`).

Required `ClassVar`s on the subclass:

- `check_id: str` — unique snake_case id
- `description: str` — short help text
- `default_severity: str` — `low|medium|high|critical|error|warning|none`
  (`none` suppresses output entirely)

---

## Check kinds

| Method                          | When called        | Use for                                  |
| ------------------------------- | ------------------ | ---------------------------------------- |
| `async def execute(...)`        | once per statement | most checks                              |
| `async def execute_policy(...)` | once per policy    | cross-statement (duplicate SIDs, totals) |

A single class may implement both (see `action_condition_enforcement.py`).

`statement.get_actions() / get_resources() / get_principals()` return `list[str]`.
`config.config.get("key", default)` reads check-specific YAML config.
`self.get_severity(config)` honours severity overrides.

---

## AWS data via `fetcher: AWSServiceFetcher`

```python
is_valid, err, is_wildcard = await fetcher.validate_action("s3:GetObject")
expanded = await fetcher.expand_wildcard_action("s3:Get*")
service = await fetcher.fetch_service_by_name("s3")  # .actions, .resources, .condition_keys
result = await fetcher.validate_condition_key("s3:GetObject", "s3:prefix")
```

Cached: memory LRU + disk TTL (7 days). Tests must mock — never hit the real API.

---

## Severity levels

| Level      | Meaning                                                |
| ---------- | ------------------------------------------------------ |
| `critical` | Immediate security risk (public access, admin privesc) |
| `high`     | Significant security concern                           |
| `medium`   | Best-practice violation (default for new checks)       |
| `low`      | Minor improvement                                      |
| `error`    | AWS will reject the policy                             |
| `warning`  | Valid but problematic                                  |
| `none`     | Suppressed                                             |

---

## Common `issue_type` values

`invalid_action`, `invalid_resource`, `invalid_condition_key`, `overly_permissive`,
`missing_condition`, `privilege_escalation`, `public_access`, `policy_structure`,
`resource_mismatch`.

---

## Built-in checks

| File                              | Check ID                       | Severity | Notes                                              |
| --------------------------------- | ------------------------------ | -------- | -------------------------------------------------- |
| `action_validation.py`            | `action_validation`            | error    | actions exist                                      |
| `condition_key_validation.py`     | `condition_key_validation`     | error    | per-action condition keys                          |
| `condition_type_mismatch.py`      | `condition_type_mismatch`      | error    | operator–value type match                          |
| `resource_validation.py`          | `resource_validation`          | error    | ARN format (uses `DEFAULT_ARN_VALIDATION_PATTERN`) |
| `principal_validation.py`         | `principal_validation`         | high     | resource policies                                  |
| `policy_structure.py`             | `policy_structure`             | error    | required fields                                    |
| `policy_size.py`                  | `policy_size`                  | error    | per-type byte limits                               |
| `policy_type_validation.py`       | `policy_type_validation`       | error    | type-specific rules                                |
| `sid_uniqueness.py`               | `sid_uniqueness`               | warning  | policy-level                                       |
| `set_operator_validation.py`      | `set_operator_validation`      | error    | ForAllValues/ForAnyValue                           |
| `ifexists_condition_check.py`     | `ifexists_condition_usage`     | warning  | IfExists patterns                                  |
| `mfa_condition_check.py`          | `mfa_condition_antipattern`    | warning  | MFA anti-patterns                                  |
| `trust_policy_validation.py`      | `trust_policy_validation`      | high     | + confused deputy                                  |
| `not_principal_validation.py`     | `not_principal_validation`     | warning  | NotPrincipal usage                                 |
| `action_resource_matching.py`     | `action_resource_matching`     | medium   | actions ↔ resource types                           |
| `wildcard_action.py`              | `wildcard_action`              | medium   | `Action: "*"`                                      |
| `wildcard_resource.py`            | `wildcard_resource`            | medium   | `Resource: "*"`                                    |
| `full_wildcard.py`                | `full_wildcard`                | critical | Action+Resource `*`                                |
| `service_wildcard.py`             | `service_wildcard`             | high     | `s3:*`                                             |
| `sensitive_action.py`             | `sensitive_action`             | medium   | 490+ privesc actions                               |
| `not_action_not_resource.py`      | `not_action_not_resource`      | high     |                                                    |
| `action_condition_enforcement.py` | `action_condition_enforcement` | high     | sensitive actions need conds                       |

Custom-check examples: `examples/custom_checks/`.

---

## Utilities (`utils/`)

Use these instead of reimplementing:

- `action_parser.py` — `parse_action()`, `is_wildcard_action()`, `extract_service()`
- `wildcard_expansion.py` — `compile_wildcard_pattern()`, `expand_wildcard_actions()`
- `sensitive_action_matcher.py` — `get_sensitive_actions_by_categories()`, `check_sensitive_actions()`
- `policy_level_checks.py` — `check_policy_level_actions()`, `_check_all_of_pattern()`
- `formatting.py` — `format_list_with_backticks()`
