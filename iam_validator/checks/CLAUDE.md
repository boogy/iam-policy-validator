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
  `SERVICE_CONTROL_POLICY` and `RESOURCE_CONTROL_POLICY` — the six are `full_wildcard`,
  `service_wildcard`, `wildcard_action`, `wildcard_resource`, `sensitive_action` and
  `action_condition_enforcement`. `principal_validation`
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
`invalid_value_format`, `overly_permissive`, `missing_condition`, `privilege_escalation`,
`invalid_not_principal`, `public_access`, `policy_structure`, `resource_mismatch`,
`ineffective_deny_carve_out`, `literal_wildcard_deny_carve_out`, `not_action_allow_ineffective`, `unexpected_resource`,
`check_execution_error` (emitted by the registry when a check raises, never by a check
itself).

---

## Built-in checks

| File                              | Check ID                       | Severity | Notes                                                         |
| --------------------------------- | ------------------------------ | -------- | ------------------------------------------------------------- |
| `action_validation.py`            | `action_validation`            | error    | actions exist                                                 |
| `condition_key_validation.py`     | `condition_key_validation`     | error    | per-action condition keys; global-only on `NotAction`         |
| `condition_type_mismatch.py`      | `condition_type_mismatch`      | error    | operator–value type match                                     |
| `resource_validation.py`          | `resource_validation`          | error    | ARN format (uses `DEFAULT_ARN_VALIDATION_PATTERN`)            |
| `principal_validation.py`         | `principal_validation`         | high     | resource policies; ineffective `Deny` carve-outs              |
| `policy_structure.py`             | `policy_structure`             | error    | required fields                                               |
| `policy_size.py`                  | `policy_size`                  | error    | per-type byte limits; warns on inferred type                  |
| `policy_type_validation.py`       | `policy_type_validation`       | error    | type-specific rules + RCP shape hint + NotPrincipal rejection |
| `rcp_best_practices.py`           | `rcp_best_practices`           | medium   | RCP blanket denies + service carve-out shape                  |
| `sid_uniqueness.py`               | `sid_uniqueness`               | error    | policy-level; charset skipped for RESOURCE_POLICY             |
| `set_operator_validation.py`      | `set_operator_validation`      | warning  | ForAllValues/ForAnyValue                                      |
| `ifexists_condition_check.py`     | `ifexists_condition_usage`     | warning  | IfExists patterns                                             |
| `mfa_condition_check.py`          | `mfa_condition_antipattern`    | warning  | anti-patterns #2 and #4 are `Allow`-only                      |
| `trust_policy_validation.py`      | `trust_policy_validation`      | high     | + confused deputy                                             |
| `not_principal_validation.py`     | `not_principal_validation`     | warning  | NotPrincipal usage                                            |
| `action_resource_matching.py`     | `action_resource_matching`     | medium   | actions ↔ resource types                                      |
| `wildcard_action.py`              | `wildcard_action`              | high     | `Action: "*"`; never below `service_wildcard`                 |
| `wildcard_resource.py`            | `wildcard_resource`            | medium   | `Resource: "*"`                                               |
| `full_wildcard.py`                | `full_wildcard`                | critical | Action+Resource `*`                                           |
| `service_wildcard.py`             | `service_wildcard`             | high     | `s3:*`                                                        |
| `sensitive_action.py`             | `sensitive_action`             | category | 490+ privesc actions; dedups against ACE's enforced actions   |
| `not_action_not_resource.py`      | `not_action_not_resource`      | high     | Allow-grant findings dropped in SCP/RCP                       |
| `action_condition_enforcement.py` | `action_condition_enforcement` | high     | sensitive actions need conds                                  |

Custom-check examples: `examples/custom_checks/`.

---

## Ineffective denies (gotcha)

`principal_validation` reports `ineffective_deny_carve_out` for both spellings of a
`Deny` that exempts everyone: `NotPrincipal: "*"`, and `Principal: "*"` with
`ArnNotEquals` on `aws:PrincipalArn: "*"`. The condition form counts only for a
wildcard-capable operator; `StringNotEquals` on `"*"` exempts nobody and is reported as
`literal_wildcard_deny_carve_out`. A `Deny` carrying a `NotPrincipal` still falls
through to the blocked/allowed-principal rules, so both findings can appear on one
statement; a `Deny` without one is otherwise skipped (a deny grants nothing).

## RCP service carve-outs (gotcha)

`rcp_best_practices` emits `rcp_carveout_missing_ifexists` when a blanket-deny carve-out
tests `aws:PrincipalIsAWSService` with a bare `Bool`. AWS omits that key from anonymous
requests, so the bare operator cannot match, the whole `Condition` goes false, and
anonymous callers escape the deny. The canonical pair is
`StringNotEqualsIfExists aws:PrincipalOrgID` + `BoolIfExists aws:PrincipalIsAWSService`.

## Set-prefixed operators (gotcha)

`ForAllValues:`/`ForAnyValue:` prefixes hide an operator from a plain `==` comparison.
Use `strip_set_prefix(op)` — it lowercases and removes a recognized set prefix but
**keeps** `IfExists`, which `normalize_operator()` and `base_operator()` both strip.
Anywhere `Bool` and `BoolIfExists` must stay distinct, `strip_set_prefix` is the only
correct helper. `mfa_condition_check` and `rcp_best_practices` call it directly;
`action_condition_enforcement` and `principal_validation` reach it through
`has_condition_key()`, whose `operator=` argument matches a prefix-less requirement
against any set prefix but a prefixed one only against exactly that prefix.

## Cross-check dedup (gotcha)

A check that suppresses its own finding because another check covers the action must ask
that check what it will **actually** enforce, not read its config. `sensitive_action`
calls `ActionConditionEnforcementCheck.enforced_actions(root_config, policy_file=None)`,
which resolves the check's own config the way `ValidatorConfig.checks_config` does,
returns an empty set when the check is disabled, and runs the real
`_get_merged_requirements` — once per `root_config` object (`sensitive_action` caches it) — so a `merge_strategy`, an `ignore_patterns` match or a
user-supplied `action_condition_requirements` entry moves both checks together. Reading
`requirements` directly suppressed findings for requirements that were never in play.
Matching is `action_matches`, not `==`: a requirement may be a glob and IAM action names
are case-insensitive. Mapping-form `actions` count their `any_of` entries and a single-entry `all_of`, each group on its own as `_check_policy_wide` enforces them: a longer `all_of`
flags only statements granting every action, and `none_of` is a separate rule. `per_action_override` uses the same rule (`_owned_actions`): a user requirement replaces a default when one of its owned actions, as an IAM glob, covers the default's action (case-insensitive; `iam:Pass*` replaces `iam:PassRole`, not the reverse), and only when it enforces on every `Allow` exactly as `enforced_actions` counts it (`_owned_enforced_actions`, shared by both); a user rule whose `required_conditions` holds no evaluable entry (e.g. `none_of` only) owns no actions and keeps the default. Policy-level `invalid_condition_requirement` findings carry a `finding_key` digest (`rule_key`, never the message) of the problem text and `repr` of the raw entry, so entries differing only in presentation keys stay distinct; `_dedupe_issues` keys on it. Statement-level checks never receive `policy_file`, so a
requirement carrying `ignore_patterns` counts as unenforced there and the finding is
kept rather than wrongly suppressed.

## `if:` branches in `action_condition_enforcement` (gotcha)

A requirement carrying the `if` key (even `if: []`) dispatches to `_check_branches`;
one without it runs the single-requirement path, whose semantics changed only where
the CHANGELOG `Fixed` entries say. Parsing and matching live in
`utils/requirement_branches.py`. Each valid branch becomes an ordinary requirement run
through `_check_per_statement` / `_check_policy_wide` with keyword-only `effects` and
`statement_filter`. An omitted branch `effect` means `Allow` in both forms; findings
for the same rule (`finding_key = rule_key(*rule)` set by `_with_rule_identity`, so also part of the finding id; key-order independent, ignoring `severity`/`description`/`example`/`message` and null-valued keys) differing only in severity, suggestion or message wording are reported once (in every requirement, not only `if` ones) (most severe kept; a list entry and an `all_of` entry share an identity; a `forbidden_action` keys on its unordered `none_of` action set); `none_of` flags only `Allow` statements (`branch_problem` rejects a `Deny`-only branch whose only non-empty group is `none_of`; `requirement_branches` rejects any `Deny`-only branch of a requirement whose only non-empty `actions` group is `none_of`). Malformed branches yield one `invalid_condition_requirement` (only when a statement matches the requirement's actions)
(`error`, `statement_index=-1`) per policy. `branch_problem` does not check `severity`:
an invalid branch severity is reported and dropped by `_prepare_requirement` and the
branch still enforced (and counted by `enforced_actions`). `enforced_actions` skips a requirement
whose branches (including a top-level `required_conditions`, treated as an unscoped
branch) never enforce `Allow` without `resource` / `not_resource`, and any requirement
or branch whose `required_conditions` holds no evaluable `all_of` / `any_of` / list entry
(`_requires_evaluable_condition`, e.g. `none_of` alone).

## `sensitive_action` severity (gotcha)

Precedence: the user's `category_severities` entry → the check's `severity` →
`SensitiveActionCheck.DEFAULT_CATEGORY_SEVERITIES` → `default_severity`. The built-in
category map lives on the class, **not** in `defaults.py`, and `defaults.py` sets no
`severity` for this check: a merged config cannot tell a shipped value from a user's, so
either one there would silently beat (or be beaten by) what the user wrote. The built-in
category severity (only) is lowered to `scoped_resource_severities`
(`DEFAULT_SCOPED_RESOURCE_SEVERITIES`: `data_access`/`credential_exposure` → medium)
when every `Resource` is a specific ARN; a severity the user set is never lowered.

## Partly type-specific findings (gotcha)

`applies_to_policy_types` is all-or-nothing. When only some of a check's findings are
wrong for a type, override `filter_for_policy_type(issues, policy_type)` — the registry
calls it in `_process_issues` (statement-level `execute()` never sees the type).
`not_action_not_resource` uses it to drop its `GRANT_ISSUE_TYPES` in SCPs/RCPs while
keeping its `Deny` findings.

## `NotAction` statements (gotcha)

`get_actions()` is empty for a `NotAction` statement. `action_condition_enforcement`
treats an `Allow` + `NotAction` statement as granting every requirement action no
`NotAction` glob covers (`_granted_actions`); regex `action_patterns` cannot be
enumerated and are not matched there. `sensitive_action` skips it, as it skips
`Action: "*"`: `not_action_not_resource` owns that finding.

## Hardcoded severities (gotcha)

A check whose `default_severity` is `error` ("AWS will reject the policy") feeds
`fail_on_severities` and fails CI, so advisory findings from those checks set severity
literally instead of calling `get_severity(config)`:

- `policy_size_type_ambiguous` — `warning` (see above).
- `condition_key_validation` on a `NotAction` statement — `warning`. There is no action
  to resolve per-action keys against, so only global keys are decidable and an unknown
  key is a hint, not a rejection.
- `action_condition_enforcement` emits `invalid_condition_requirement` at `error` for any
  **malformed** config (bad `actions` or `required_conditions` shape, unknown or non-list group,
  non-string `condition_key`/`operator`, invalid requirement, branch or entry
  `severity`, malformed `if` branch), where the config itself is at fault. All of these
  except malformed `if` branches (`requirement_branches`, reported by `execute_policy`) come
  from one pre-pass, `_prepare_requirement`, once per policy at `statement_index=-1`; it
  returns a copy (never mutate the shared config) with null and invalid severities
  stripped, so the entry/branch/requirement is still enforced at the fallback severity.
  The per-statement path skips malformed pieces silently. A requirement's config
  problems (both kinds) are emitted only for a policy with a statement of either effect
  matching its actions (`_matches_any_statement`, which also reads strings from a malformed
  `actions` group and matches every policy when `actions` names none, and a statement granting `Action: "*"` when the requirement has `action_patterns`), and both kinds bypass the
  requirement's own `ignore_patterns`. `enforced_actions` counts a requirement (or `if`
  branch) only when its prepared `required_conditions` holds an evaluable `all_of` /
  `any_of` / list entry (`_requires_evaluable_condition`); detection-only (empty) still
  counts. Both checks judge an entry with `is_evaluable_entry` (`utils/requirement_branches.py`);
  an entry with both a non-null `condition_key` and `all_of` (`has_key_and_group`) is not evaluable; a null one of either counts as unset (`without_null_all_of` strips a null `all_of` before evaluation). `execute_policy` runs every finding, config problems included, through `_dedupe_issues`. Null, `[]`, `{}` and a
  mapping whose groups are all empty or null (`has_no_conditions`) count as an empty,
  detection-only `required_conditions`; a falsy scalar (`false`, `0`, `""`) is malformed. A
  non-string element of `actions` (list or group) is reported (one issue each) and dropped. Top-level shape
  messages come from `conditions_problem`, as for `if` branches. An unknown group key (e.g. a
  typo) inside an `if` branch's `required_conditions` drops the whole branch, unlike the
  top-level form, which still enforces its valid groups. A non-list `requirements` /
  `policy_level_requirements` / `action_condition_requirements`, or a non-mapping entry in one,
  is dropped in `_merge_requirements` (`_requirement_entries`, which also makes a string `actions` a list before any merge strategy runs, so `enforced_actions` and
  `sensitive_action` never see it) and reported by `execute_policy` once per policy for every
  policy (`_requirement_list_problems`).
  `principal_validation` keeps only the string entries of `blocked_principals`,
  `allowed_principals`, `allowed_service_principals` and a requirement's `principals`
  (`_string_entries`, never `str()`: YAML mangles leading-zero account ids) and reports each
  non-string entry once per policy from `execute_policy` (the three lists when a statement
  reaches the blocked/allowed rules, `_reaches_principal_rules`; `principals` with the
  requirement checks, only when the requirement's string patterns match an evaluated statement; a scalar non-string value counts as one bad entry). An `allowed_principals` that is
  configured (anything but null or `[]`) stays an allow-list even with no string entry, so it
  then allows nothing; likewise an all-invalid `allowed_service_principals` allows no service (a null one keeps the default `aws:*`).
  Non-string values in a policy's `Principal`/`NotPrincipal` are dropped by
  `_flatten_principal_field`. A non-list `principal_condition_requirements` or a non-mapping entry in
  it is skipped by `execute` (`_requirement_entries`) and reported once per policy there too.
  Every finding of this check that can repeat in one statement or policy carries a `finding_key`: the principal
  for `blocked_principal`/`unauthorized_principal`; for a requirement finding `rule_key` over its group
  (`required` for a list or `all_of` leaf, `any_of`, `none_of`) and canonical entry (an `any_of` set in any order, duplicates ignored, via `finding_identity.unordered`, as in `action_condition_enforcement`), never the principal patterns;
  for a config problem `rule_key` over the problem, the group label (`_create_invalid_entry_issue(where=)`, also named in the message) and `repr` of the offending entry (an invalid `severity` includes
  the entry in canonical form without its presentation keys, `severity_problem_key`, so key order does not matter); never the message or the matching principals.
  `_validate_principal_condition_requirements` merges a statement's requirement findings sharing type, condition key and
  `finding_key`: matched principals unioned in statement order, severity the max, text from the most severe requirement (first in config order on a tie); `rule_key(finding_key, "public")`
  when `"*"` is among the matched principals, so a public escalation gets a new id; a requirement at severity `none` is skipped before merging.
  Otherwise ids ignore matched principals and severity, so an ignore also covers a later escalation of the same statement and entry
  (e.g. a higher-severity requirement matching a newly added principal). `_dedupe` (`finding_identity.keep_most_severe`, shared with `action_condition_enforcement`) keys on `finding_key` on
  every multi-finding return path (the `Deny` carve-out path yields at most one), keeping the most severe.
  A non-mapping or keyless entry, a non-string `operator`, an invalid entry `severity`, an
  unknown or non-list group or a scalar `required_conditions` (`_prepare_conditions`) is skipped
  by `execute` (never satisfied); it and an invalid requirement-level `severity` are reported
  once per policy by `execute_policy` (`statement_index=-1`), only when the requirement's principals match a
  statement that `execute` would evaluate (`_condition_requirement_principals`, shared by both, so
  blocked principals and `Service: "*"` statements never count); a `principals` that is neither a
  string (one pattern) nor a list is reported there too and matches nothing; a nested `all_of` entry needs every child, and its leaves inherit the
  parent's `severity`/`description`/`example`/`message` unless they set their own (a null or
  invalid one counts as unset). A null, empty
  or invalid `severity` (entry, then requirement) falls back to the next level, then
  the check default.

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
  excluding a UTF-8 BOM. No `.json` file that parses to the validated policy (a dict
  from the SDK, a YAML source, an unrelated file of the same name) or
  `organizations_measurement: compact` falls back to compact.

SCP is 10,240 bytes since 2026-05-15, RCP still 5,120 — they are no longer equal.
Inline limits are AWS aggregates per entity; this check only sees one policy.

`--log-level debug` emits `policy_size=… measured=… limit_key=… limit=… limit_source=…`
per policy — start there when a size finding is missing.

Setting `policy_size.policy_type` (directly under the check id — options nested
under a `config:` key are never read; `apply_config_to_registry` warns once per config)
pins every policy in the run to one limit and makes the runtime type irrelevant to this check, so nothing in
`defaults.py` or the example configs may set it (see CHANGELOG 1.19.0 and 1.28.0). A value that is not a
`size_limits` key, or an `organizations_measurement` other than `as_written`/`compact`, is ignored with a
warning logged once per check instance and value — never silently.

---

`policy_size` additionally reads the `policy_type_source` kwarg
(`cli-flag` | `config-glob` | `auto-detect` | `default`, forwarded by
`_validate_policy_with_registry`; default `"cli-flag"` = treat as declared). When the
type was _not_ declared it compares against the one Organizations type the document is
indistinguishable from — `IDENTITY_POLICY` → `scp`, `RESOURCE_POLICY` that
`policy_type_validation.looks_like_rcp` accepts → `rcp` — measured the way that type is
measured, and emits `policy_size_type_ambiguous` at `warning` when that limit is exceeded. When the
policy instead exceeds its own limit but fits the candidate's, the `policy_size_exceeded`
suggestion leads with how to declare the type. The as-written candidate read is skipped when
the file's byte size cannot exceed the candidate limit.
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
- `finding_identity.py` — `PRESENTATION_KEYS`, `canonical_rule()`, `unordered()`, `rule_key()`, `severity_problem_key()`, `keep_most_severe()`
- `requirement_branches.py` — `requirement_branches()`, `branch_problem()`, `conditions_problem()`, `severity_problem()`, `branch_effects()`,
  `branch_matches_resources()`, `branch_enforces_allow_everywhere()`, `is_evaluable_entry()`,
  `has_key_and_group()`, `without_null_all_of()`
