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

# Shared fetcher across multiple files
async with validator() as v:
    r1 = await v.validate_file("a.json")
    r2 = await v.validate_directory("./policies/", recursive=True)
    v.generate_report([r1, r2], format="markdown")

# With YAML config
async with validator_from_config(load_validator_config("iam-validator.yaml")) as v:
    result = await v.validate_file("policy.json")
```

`policy_type=` kwarg on `validate_file` / `validate_directory` / `validate_json` /
`quick_validate` mirrors the CLI: when supplied it forces the type for every policy
in the run; when omitted, per-file resolution applies.

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
`PolicyLoader`, `ReportGenerator`, `validate_policies`, models, formatters.

---

## Conventions

- Add new exports to `__init__.py:__all__` AND document them in `docs/developer-guide/sdk/`.
- ARN-matching helpers are reused by checks (`action_resource_matching`, `resource_validation`)
  — keep the public signatures stable and parameterize new behaviour with kwargs.
- `arn_matches`'s "S3 bucket disallows `/`" rule is now derived from the _pattern_
  (no `/` in the pattern's resource id), not from the resource-type _name_. See
  `tests/sdk/test_arn_matching.py` for the regression cases (S3 vs s3vectors).
