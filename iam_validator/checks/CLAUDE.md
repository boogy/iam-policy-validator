# Checks Module - Check Development Guide

**Purpose**: 21 built-in IAM policy validation checks
**Parent Context**: Extends [../../CLAUDE.md](../../CLAUDE.md)

---

## Quick Start: Creating a New Check

**Use `/add-check my_check_name` to scaffold automatically.**

### 1. Copy the Template

```python
"""My custom check - brief description."""

from typing import ClassVar

from iam_validator.core.aws_service import AWSServiceFetcher
from iam_validator.core.check_registry import CheckConfig, PolicyCheck
from iam_validator.core.models import Statement, ValidationIssue


class MyCheck(PolicyCheck):
    """Detailed description of what this check validates."""

    check_id: ClassVar[str] = "my_check"  # Unique snake_case ID
    description: ClassVar[str] = "Brief description for --help"
    default_severity: ClassVar[str] = "medium"  # low|medium|high|critical|error|warning

    async def execute(
        self,
        statement: Statement,
        statement_idx: int,
        fetcher: AWSServiceFetcher,
        config: CheckConfig,
    ) -> list[ValidationIssue]:
        """Execute check on a single statement."""
        issues = []

        # Only check Allow statements (most checks do this)
        if statement.effect != "Allow":
            return issues

        # Get actions/resources from statement
        actions = statement.get_actions()  # Returns list[str]
        resources = statement.get_resources()  # Returns list[str]

        # Your validation logic here
        if "*" in actions:
            issues.append(
                ValidationIssue(
                    severity=self.get_severity(config),  # Respects config override
                    statement_sid=statement.sid,
                    statement_index=statement_idx,
                    issue_type="overly_permissive",  # Category for grouping
                    message="Found wildcard action",
                    action="*",
                    suggestion="Replace with specific actions",
                    line_number=statement.line_number,
                    field_name="action",  # Optional: which field has the issue
                )
            )

        return issues
```

### 2. Register the Check

Add to `iam_validator/checks/__init__.py`:

```python
from iam_validator.checks.my_check import MyCheck

__all__ = [
    # ... existing checks
    "MyCheck",
]
```

Add to `iam_validator/core/check_registry.py` in `create_default_registry()`:

```python
registry.register(checks.MyCheck())
```

### 3. Add Tests

Create `tests/checks/test_my_check.py`:

```python
import pytest
from iam_validator.checks.my_check import MyCheck
from iam_validator.core.check_registry import CheckConfig
from iam_validator.core.models import Statement

@pytest.fixture
def check():
    return MyCheck()

@pytest.fixture
def config():
    return CheckConfig(check_id="my_check", enabled=True)

@pytest.mark.asyncio
async def test_detects_wildcard_action(check, config, mock_fetcher):
    statement = Statement(
        effect="Allow",
        action=["*"],
        resource=["*"],
    )
    issues = await check.execute(statement, 0, mock_fetcher, config)
    assert len(issues) == 1
    assert issues[0].issue_type == "overly_permissive"
```

---

## Check Types

### Statement-Level Checks (Most Common)

Override `execute()` - called once per statement:

```python
async def execute(
    self,
    statement: Statement,
    statement_idx: int,
    fetcher: AWSServiceFetcher,
    config: CheckConfig,
) -> list[ValidationIssue]:
```

**Examples**: [wildcard_action.py](wildcard_action.py), [wildcard_resource.py](wildcard_resource.py), [action_validation.py](action_validation.py)

### Policy-Level Checks

Override `execute_policy()` - called once per policy, sees all statements:

```python
async def execute_policy(
    self,
    policy: IAMPolicy,
    policy_file: str,
    fetcher: AWSServiceFetcher,
    config: CheckConfig,
    **kwargs,
) -> list[ValidationIssue]:
```

Use for:

- Cross-statement validation (duplicate SIDs)
- Aggregate analysis (total privilege escalation)
- Policy-wide constraints (size limits)

**Examples**: [sid_uniqueness.py](sid_uniqueness.py), [policy_size.py](policy_size.py), [sensitive_action.py](sensitive_action.py)

### Combined Checks

Can implement BOTH methods for hybrid validation:

```python
class ActionConditionEnforcementCheck(PolicyCheck):
    # Statement-level: Check individual conditions
    async def execute(self, statement, ...):
        ...

    # Policy-level: Check all_of requirements across statements
    async def execute_policy(self, policy, ...):
        ...
```

---

## Working with Statement Data

### Get Actions/Resources

```python
actions = statement.get_actions()      # Returns list[str]
resources = statement.get_resources()  # Returns list[str]
principals = statement.get_principals() # Returns list[str] (resource policies)
```

### Check Conditions

```python
if statement.condition:
    for operator, conditions in statement.condition.items():
        # operator: "StringEquals", "ArnLike", etc.
        for key, value in conditions.items():
            # key: "aws:SourceArn", "s3:prefix", etc.
            # value: string, list, or bool
            pass
```

### Access Config Options

```python
# Check-specific config from iam-validator.yaml
custom_option = config.config.get("my_option", "default_value")

# Override message/suggestion from config
message = config.config.get("message", "Default message")

# Get severity (respects config override)
severity = self.get_severity(config)
```

---

## Using AWS Service Data

The `fetcher` parameter provides AWS service definitions:

```python
# Validate an action exists
is_valid, error_msg, is_wildcard = await fetcher.validate_action("s3:GetObject")

# Expand wildcard actions
expanded = await fetcher.expand_wildcard_action("s3:Get*")
# Returns: ["s3:GetObject", "s3:GetObjectAcl", ...]

# Get service definition
s3_service = await fetcher.fetch_service_by_name("s3")
# Access: s3_service.actions, s3_service.resources, s3_service.condition_keys

# Check condition key validity
is_valid = await fetcher.validate_condition_key("s3", "s3:x-amz-acl")
```

---

## Severity Levels

| Level      | Use Case                                                       |
| ---------- | -------------------------------------------------------------- |
| `critical` | Immediate security risk (public access, admin privesc)         |
| `high`     | Significant security concern (sensitive actions, overly broad) |
| `medium`   | Best practice violation (wildcards, missing conditions)        |
| `low`      | Minor improvement suggestion                                   |
| `error`    | Invalid policy syntax (AWS will reject)                        |
| `warning`  | Valid but potentially problematic                              |

---

## Issue Types (for Grouping)

Common `issue_type` values:

- `invalid_action` - Action doesn't exist in AWS
- `invalid_resource` - Malformed ARN
- `invalid_condition_key` - Unknown condition key
- `overly_permissive` - Wildcards, broad access
- `missing_condition` - Sensitive action without constraint
- `privilege_escalation` - Can escalate own permissions
- `public_access` - Allows unauthenticated access
- `policy_structure` - Missing required fields

---

## File Reference

| File                              | Check ID                       | Description                          |
| --------------------------------- | ------------------------------ | ------------------------------------ |
| `action_validation.py`            | `action_validation`            | Actions exist in AWS                 |
| `condition_key_validation.py`     | `condition_key_validation`     | Valid condition keys                 |
| `condition_type_mismatch.py`      | `condition_type_mismatch`      | Operator-value type match            |
| `resource_validation.py`          | `resource_validation`          | ARN format validation                |
| `wildcard_action.py`              | `wildcard_action`              | `Action: "*"` detection              |
| `wildcard_resource.py`            | `wildcard_resource`            | `Resource: "*"` detection            |
| `full_wildcard.py`                | `full_wildcard`                | `Action + Resource: "*"` detection   |
| `ifexists_condition_check.py`     | `ifexists_condition_usage`     | IfExists condition validation        |
| `service_wildcard.py`             | `service_wildcard`             | `s3:*` style wildcards               |
| `sensitive_action.py`             | `sensitive_action`             | Privilege escalation (490+ actions)  |
| `action_condition_enforcement.py` | `action_condition_enforcement` | Conditions required                  |
| `sid_uniqueness.py`               | `sid_uniqueness`               | Duplicate SID detection              |
| `policy_size.py`                  | `policy_size`                  | Character limit validation           |
| `policy_structure.py`             | `policy_structure`             | Required fields                      |
| `policy_type_validation.py`       | `policy_type_validation`       | Policy type-specific validation      |
| `principal_validation.py`         | `principal_validation`         | Principal format                     |
| `trust_policy_validation.py`      | `trust_policy_validation`      | Trust policy rules + confused deputy |
| `not_principal_validation.py`     | `not_principal_validation`     | NotPrincipal usage patterns          |
| `not_action_not_resource.py`      | `not_action_not_resource`      | NotAction/NotResource detection      |
| `mfa_condition_check.py`          | `mfa_condition_antipattern`    | MFA anti-patterns                    |
| `set_operator_validation.py`      | `set_operator_validation`      | ForAllValues usage                   |
| `action_resource_matching.py`     | `action_resource_matching`     | Action-resource type match           |

---

## Custom Check Examples

See `examples/custom_checks/` for example custom checks:

| File                                 | Purpose                  |
| ------------------------------------ | ------------------------ |
| `domain_restriction_check.py`        | Restrict to domains      |
| `cross_account_external_id_check.py` | Cross-account validation |

---

## Testing Pattern

```python
import pytest
from unittest.mock import AsyncMock, MagicMock

@pytest.fixture
def mock_fetcher():
    fetcher = MagicMock()
    fetcher.validate_action = AsyncMock(return_value=(True, None, False))
    fetcher.expand_wildcard_action = AsyncMock(return_value=["s3:GetObject"])
    return fetcher

@pytest.fixture
def config():
    return CheckConfig(
        check_id="my_check",
        enabled=True,
        severity="high",  # Override default
        config={"custom_option": "value"},
    )

@pytest.mark.asyncio
async def test_check_allows_valid_policy(check, config, mock_fetcher):
    statement = Statement(effect="Allow", action=["s3:GetObject"], resource=["*"])
    issues = await check.execute(statement, 0, mock_fetcher, config)
    assert len(issues) == 0

@pytest.mark.asyncio
async def test_check_detects_issue(check, config, mock_fetcher):
    statement = Statement(effect="Allow", action=["*"], resource=["*"])
    issues = await check.execute(statement, 0, mock_fetcher, config)
    assert len(issues) == 1
    assert issues[0].severity == "high"  # Config override applied
```

---

## Quick Search

```bash
# Find check by ID
rg -n "check_id.*=.*\"wildcard" .

# Find where specific issue type is used
rg -n "issue_type.*=.*\"privilege" .

# Find checks using fetcher
rg -n "await fetcher\." .

# Find policy-level checks
rg -n "async def execute_policy" .
```

---

## Utility Modules (`utils/`)

Shared helpers used across multiple checks:

```
utils/
├── __init__.py                # Exports shared utilities
├── action_parser.py           # ParsedAction, parse_action(), is_wildcard_action(), extract_service()
├── sensitive_action_matcher.py # get_sensitive_actions_by_categories(), check_sensitive_actions()
├── wildcard_expansion.py      # compile_wildcard_pattern(), expand_wildcard_actions()
├── policy_level_checks.py     # check_policy_level_actions(), _check_all_of_pattern()
└── formatting.py              # format_list_with_backticks()
```

### Usage

```python
from iam_validator.checks.utils import parse_action, is_wildcard_action, check_sensitive_actions

# Parse an action string
parsed = parse_action("s3:GetObject")  # ParsedAction(service="s3", action="GetObject")

# Check for wildcards
is_wildcard_action("s3:*")  # True

# Check against sensitive action categories
matches = check_sensitive_actions(["iam:CreateUser"], config)
```
