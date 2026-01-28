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
    # Core fields
    severity: str              # error, warning, critical, high, medium, low
    statement_index: int       # Statement number (0-based)
    issue_type: str            # Issue category (e.g., "invalid_action", "overly_permissive")
    message: str               # Human-readable description
    check_id: str | None       # Check that found this (e.g., "wildcard_action")
    statement_sid: str | None  # Statement ID if present

    # Context fields
    action: str | None         # Action involved in the issue
    resource: str | None       # Resource involved in the issue
    condition_key: str | None  # Condition key involved in the issue
    field_name: str | None     # Field name: "action", "resource", "condition", "principal", "effect", "sid"
    line_number: int | None    # Line number in source file

    # Guidance fields
    suggestion: str | None     # How to fix the issue
    example: str | None        # Code example (JSON/YAML)

    # Enhanced finding quality fields
    risk_explanation: str | None      # Why this is a security risk
    documentation_url: str | None     # Link to AWS docs or runbook
    remediation_steps: list[str] | None  # Step-by-step fix guidance
    risk_category: str | None         # Category: "privilege_escalation", "data_exfiltration", etc.
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
