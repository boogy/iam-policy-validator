---
title: Models API
description: Data model reference
---

# Models API Reference

## IAMPolicy

Represents a complete IAM policy document.

```python
class IAMPolicy(BaseModel):
    version: str
    id: str | None = None
    statement: list[Statement]
```

## Statement

Represents a single policy statement.

```python
class Statement(BaseModel):
    sid: str | None = None
    effect: str  # "Allow" or "Deny"
    action: str | list[str] | None = None
    not_action: str | list[str] | None = None
    resource: str | list[str] | None = None
    not_resource: str | list[str] | None = None
    principal: dict | str | None = None
    not_principal: dict | str | None = None
    condition: dict | None = None
    line_number: int | None = None

    def get_actions(self) -> list[str]: ...
    def get_resources(self) -> list[str]: ...
```

## ValidationIssue

Represents a validation issue found in a policy.

```python
class ValidationIssue(BaseModel):
    severity: str              # error, warning, critical, high, medium, low
    statement_index: int       # Statement number (0-based)
    issue_type: str            # Issue category
    message: str               # Human-readable description
    check_id: str | None       # Check that found this
    statement_sid: str | None  # Statement ID
    action: str | None         # Action involved
    resource: str | None       # Resource involved
    condition_key: str | None  # Condition key involved
    suggestion: str | None     # How to fix
    example: str | None        # Code example
    line_number: int | None    # Line in source file
    field_name: str | None     # Field name (action, resource, etc.)
```

## PolicyValidationResult

Result of validating a single policy.

```python
class PolicyValidationResult(BaseModel):
    file_path: str
    is_valid: bool
    issues: list[ValidationIssue]
    policy: IAMPolicy | None
```

## Config

Validation configuration.

```python
from iam_validator.sdk import Config

config = Config({
    "fail_on_severity": ["error", "critical", "high"],
    "wildcard_action": {"enabled": True, "severity": "critical"},
})
```
