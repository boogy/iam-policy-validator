---
title: Validation Functions
description: SDK validation functions reference
---

# Validation Functions

All available validation functions in the SDK.

## validate_file

Validate a single IAM policy file.

```python
from iam_validator.sdk import validate_file

result = await validate_file(
    "policy.json",
    config_path=None,  # Optional config file
    config=None        # Optional Config object
)
```

**Returns:** `PolicyValidationResult`

## validate_directory

Validate all policies in a directory.

```python
from iam_validator.sdk import validate_directory

results = await validate_directory(
    "./policies/",
    config_path=None,
    config=None
)
```

**Returns:** `list[PolicyValidationResult]`

## validate_json

Validate a policy from a Python dict.

```python
from iam_validator.sdk import validate_json

policy = {
    "Version": "2012-10-17",
    "Statement": [...]
}

result = await validate_json(
    policy,
    policy_name="inline",
    config_path=None,
    config=None
)
```

**Returns:** `PolicyValidationResult`

## quick_validate

Quick True/False validation.

```python
from iam_validator.sdk import quick_validate

# Auto-detects file, directory, or dict
is_valid = await quick_validate("policy.json")
```

**Returns:** `bool`

## get_issues

Get issues filtered by severity.

```python
from iam_validator.sdk import get_issues

# Get high and critical issues
issues = await get_issues(
    "policy.json",
    min_severity="high"
)

for issue in issues:
    print(f"{issue.severity}: {issue.message}")
```

**Returns:** `list[ValidationIssue]`

## count_issues_by_severity

Count issues grouped by severity.

```python
from iam_validator.sdk import count_issues_by_severity

counts = await count_issues_by_severity("policy.json")

print(f"Critical: {counts['critical']}")
print(f"High: {counts['high']}")
```

**Returns:** `dict[str, int]`

## PolicyValidationResult

The result object contains:

```python
result.is_valid      # bool - Overall validity
result.file_path     # str - Source file path
result.issues        # list[ValidationIssue] - All issues found
result.policy        # IAMPolicy - Parsed policy object
```

## ValidationIssue

Each issue contains:

```python
issue.severity        # str - error, warning, critical, high, etc.
issue.message         # str - Human-readable description
issue.check_id        # str - Check that found this issue
issue.statement_index # int - Statement number (0-based)
issue.statement_sid   # str | None - Statement ID
issue.line_number     # int | None - Line in source file
issue.suggestion      # str | None - How to fix
issue.example         # str | None - Code example
```
