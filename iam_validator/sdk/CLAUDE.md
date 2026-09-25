# SDK Module

Public Python API. Extends [../../CLAUDE.md](../../CLAUDE.md).

The authoritative export list is `iam_validator/sdk/__init__.py` — read it before
adding anything new.

---

## Usage

```python
from iam_validator.sdk import validate_file, validator, validator_from_config

# One-shot
result = await validate_file("policy.json")

# Shared fetcher, config and registry across multiple files
async with validator() as v:
    r1 = await v.validate_file("a.json")
    rs = await v.validate_directory("./policies/", recursive=True)
    v.generate_report([r1, *rs], format="markdown")

# With YAML config (a path or a loaded ValidatorConfig)
async with validator_from_config("iam-validator.yaml") as v:
    result = await v.validate_file("policy.json")
```

**CLI parity is a contract.** Every entry point must produce what `iam-validator
validate` produces for the same input:

- `policy_type=` mirrors `--policy-type`: when supplied it forces the type for every
  policy; when omitted, per-file resolution applies.
- `config` / `config_path`, `custom_checks_dir`, `aws_services_dir`,
  `allow_config_custom_checks` mirror the CLI flags; `validator()` builds its fetcher
  with `policy_checks.fetcher_kwargs()` so cache settings match too.
- Always pass the raw dict (`(name, policy, raw)` tuples) — `policy_structure`'s
  document-level checks only run with it.
- A file that fails to parse is returned as `PolicyValidationResult.from_parsing_error`
  (via `PolicyLoader.parsing_error_results()`), never dropped.
- `ValidationContext.generate_report` renders `json` via `generate_json_report` and
  `markdown` via `generate_github_comment`, like the CLI.

---

## File map

| File              | Purpose                                                                                                                                           |
| ----------------- | ------------------------------------------------------------------------------------------------------------------------------------------------- |
| `__init__.py`     | public API surface (`__all__`)                                                                                                                    |
| `shortcuts.py`    | `validate_file`, `validate_directory`, `validate_json`, `quick_validate`                                                                          |
| `context.py`      | `validator()`, `validator_from_config()`, `ValidationContext`                                                                                     |
| `policy_utils.py` | `parse_policy`, `extract_actions/resources/condition_keys`, `merge_policies`, `is_resource_policy`, `has_public_access`, …                        |
| `query_utils.py`  | service / action / condition-key queries against the fetcher                                                                                      |
| `arn_matching.py` | `arn_matches`, `arn_strictly_valid`, `is_glob_match`, `convert_aws_pattern_to_wildcard`, `normalize_template_variables`, `has_template_variables` |
| `helpers.py`      | check-development helpers                                                                                                                         |
| `exceptions.py`   | `IAMValidatorError` and subclasses                                                                                                                |

Re-exported from `core/`: `PolicyCheck`, `CheckRegistry`, `AWSServiceFetcher`,
`PolicyLoader`, `ReportGenerator`, `validate_policies`, `build_registry`, models, formatters.

`build_registry(config, *, custom_checks_dir=None, allow_config_custom_checks=False)` builds
a configured `CheckRegistry` without validating anything. Pass the result to
`validate_policies(..., registry=...)` to reuse one registry across many calls instead of
rebuilding it (and re-loading custom checks) every time.

---

## Conventions

- Add new exports to `__init__.py:__all__` AND document them in `docs/developer-guide/sdk/`.
- ARN-matching helpers are reused by checks (`action_resource_matching`, `resource_validation`)
  — keep the public signatures stable and parameterize new behaviour with kwargs.
- `arn_matches`'s "S3 bucket disallows `/`" rule is now derived from the _pattern_
  (no `/` in the pattern's resource id), not from the resource-type _name_. See
  `tests/sdk/test_arn_matching.py` for the regression cases (S3 vs s3vectors).
