# Checks Module

23 built-in IAM policy validation checks, plugin-based via `PolicyCheck`.
Extends [../../CLAUDE.md](../../CLAUDE.md).

---

## Adding a check

Use `/add-check my_check_name` to scaffold automatically. Manual steps:

1. Copy `wildcard_action.py` as the canonical small example.
2. Add to `iam_validator/checks/__init__.py`.
3. Register in `iam_validator/core/check_registry.py:create_default_registry()`.
4. Test in `tests/checks/test_my_check.py` (see `tests/checks/conftest.py` for `mock_fetcher`).

Required `ClassVar`s on the subclass (enforced by `CheckRegistry.register()`, which
raises `NotImplementedError` for a missing or empty one — `PolicyCheck.__init_subclass__`
only enforces that a subclass overrides `execute()` or `execute_policy()`, raising
`TypeError` when neither is):

- `check_id: str` — unique snake_case id
- `description: str` — short help text

Optional `ClassVar`s:

- `default_severity: str` — `low|medium|high|critical|error|warning|none`
  (`none` suppresses output entirely). Defaults to `"warning"` when omitted and is
  never enforced, so set it explicitly whenever `"warning"` isn't the intended
  severity.
- `applies_to_policy_types: frozenset[str] | None` — policy types the check runs on;
  `None` (the default) means all, as does an unresolved policy type. `register()` raises
  `ValueError` on a value that is not a `PolicyType`. In an SCP or RCP an
  `Allow` declines to restrict and never grants access, so grant-shaped checks exclude
  `SERVICE_CONTROL_POLICY` and `RESOURCE_CONTROL_POLICY`. `principal_validation`
  excludes only RCP, where `Principal: "*"` is required by AWS syntax.
- `supersedes: frozenset[str]` — check ids made redundant when this check both
  `matches()` the statement and reports a finding. Only the ids named here are ever
  suppressed.

Third-party checks skip steps 2-3 and advertise themselves under the
`iam_validator.checks` entry-point group instead; see `core/CLAUDE.md`.

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

`invalid_action`, `invalid_resource`, `invalid_condition_key`, `invalid_operator`,
`overly_permissive`, `missing_condition`, `privilege_escalation`, `public_access`,
`policy_structure`, `resource_mismatch`, `check_execution_error` (emitted by the registry
when a check raises, never by a check itself).

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
| `policy_size.py`                  | `policy_size`                  | error    | per-type byte limits; warns on inferred type       |
| `policy_type_validation.py`       | `policy_type_validation`       | error    | type-specific rules + RCP shape hint               |
| `rcp_best_practices.py`           | `rcp_best_practices`           | medium   | RCP blanket denies + service carve-outs            |
| `sid_uniqueness.py`               | `sid_uniqueness`               | error    | policy-level                                       |
| `set_operator_validation.py`      | `set_operator_validation`      | warning  | ForAllValues/ForAnyValue                           |
| `ifexists_condition_check.py`     | `ifexists_condition_usage`     | warning  | IfExists patterns                                  |
| `mfa_condition_check.py`          | `mfa_condition_antipattern`    | warning  | anti-patterns #2 and #4 are `Allow`-only           |
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

## Policy-level findings (gotcha)

A finding with `statement_index=-1` belongs to the document, not a statement.
`PRCommenter._find_issue_line` anchors those at line 1 so the policy-level branch in
`_post_review_comments` can relocate the comment to a changed line — before that
fallback existed they resolved to `None` and were dropped from the inline review
entirely (they still reached the summary comment and the exit code).

## Policy size measurement (gotcha)

Whitespace counting differs by service, so `policy_size` measures two ways:

- **IAM** (managed, inline, trust) ignores whitespace -> compact JSON.
- **Organizations** (`scp`, `rcp` -> `_WHITESPACE_COUNTING_LIMITS`) strips whitespace
  only on a console save; a CLI/SDK/Terraform deploy stores the document verbatim ->
  measured **as written** from the `.json` file (~1.7x compact for 2-space indent),
  excluding a UTF-8 BOM. No `.json` file (a dict from the SDK, or a YAML source) or
  `organizations_measurement: compact` falls back to compact.

SCP is 10,240 bytes since 2026-05-15, RCP still 5,120 — they are no longer equal.
Inline limits are AWS aggregates per entity; this check only sees one policy.

`--log-level debug` emits `policy_size=… measured=… limit_key=… limit=… limit_source=…`
per policy — start there when a size finding is missing.

Setting `policy_size.policy_type` (directly under the check id — options nested
under a `config:` key are never read; `apply_config_to_registry` warns once per config)
pins every policy in the run to one limit and makes the runtime type irrelevant to this check, so nothing in
`defaults.py` or the example configs may set it (see CHANGELOG 1.19.0 and 1.28.0).

---

`policy_size` additionally reads the `policy_type_source` kwarg
(`cli-flag` | `config-glob` | `auto-detect` | `default`, forwarded by
`_validate_policy_with_registry`; default `"cli-flag"` = treat as declared). When the
type was _not_ declared it compares against the one Organizations type the document is
indistinguishable from — `IDENTITY_POLICY` → `scp`, `RESOURCE_POLICY` that
`policy_type_validation.looks_like_rcp` accepts → `rcp` — measured the way that type is
measured, and emits `policy_size_type_ambiguous` at `warning` when that limit is exceeded.
Inline limits are never candidates: they are per-entity aggregates and opt-in via
`policy_size.policy_type`. The severity is deliberately hardcoded, not
`get_severity(config)`: the advisory must not inherit the check's `error` severity and
fail the run.

---

## Utilities (`utils/`)

Use these instead of reimplementing:

- `action_parser.py` — `parse_action()`, `is_wildcard_action()`, `extract_service()`
- `wildcard_expansion.py` — `compile_wildcard_pattern()` (alias of `compile_iam_glob`),
  `expand_wildcard_actions()`
- `aws_matching.py` — `action_matches()`, `compile_iam_glob()`, `iam_glob_match()`
- `condition_matching.py` — `is_deny()`, `has_condition_key()`; re-exports
  `base_operator()`, `is_negated_operator()`, `NEGATED_OPERATORS` from
  `core/condition_validators.py` (the single definition)
- `sensitive_action_matcher.py` — `get_sensitive_actions_by_categories()`, `check_sensitive_actions()`
- `policy_level_checks.py` — `check_policy_level_actions()`, `_check_all_of_pattern()`
- `formatting.py` — `format_list_with_backticks()`
