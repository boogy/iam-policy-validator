---
title: Custom Checks Best Practices
description: Tips for writing effective custom checks
---

# Custom Checks Best Practices

Tips and guidelines for writing effective custom validation checks.

## Naming

### Use Descriptive Check IDs

```python
# Good
check_id: ClassVar[str] = "require_mfa_for_iam_actions"

# Bad
check_id: ClassVar[str] = "check1"
```

### Use Clear Descriptions

```python
# Good
description: ClassVar[str] = "Ensures IAM write actions require MFA authentication"

# Bad
description: ClassVar[str] = "MFA check"
```

## Error Messages

### Be Specific

```python
# Good
message=f"Action '{action}' requires MFA but no aws:MultiFactorAuthPresent condition found"

# Bad
message="MFA required"
```

### Provide Actionable Suggestions

```python
# Good
suggestion='Add condition: {"Bool": {"aws:MultiFactorAuthPresent": "true"}}'

# Bad
suggestion="Fix this"
```

## Handle Edge Cases

### Check for None Values

```python
async def execute(self, statement, statement_idx, fetcher, config):
    issues = []

    # Handle None action
    if statement.action is None and statement.not_action is None:
        return issues

    # Use helper method for safe list access
    actions = statement.get_actions()
```

### Handle Wildcards

```python
for action in actions:
    if action == "*":
        # Handle full wildcard separately
        continue

    if "*" in action:
        # Handle partial wildcard
        expanded = await fetcher.expand_wildcard_action(action)
```

## Severity Levels

Choose appropriate severity:

```python
# Critical: Full admin access, public exposure
default_severity: ClassVar[str] = "critical"

# High: Missing security controls, sensitive actions
default_severity: ClassVar[str] = "high"

# Medium: Best practice violations
default_severity: ClassVar[str] = "medium"

# Low: Style issues, minor improvements
default_severity: ClassVar[str] = "low"
```

## Configuration

### Support Config Overrides

```python
async def execute(self, statement, statement_idx, fetcher, config):
    # Get config with defaults
    required_tags = config.config.get("required_tags", ["Environment", "Owner"])
    max_wildcards = config.config.get("max_wildcards", 3)

    # Use configured severity
    severity = self.get_severity(config)
```

### Document Config Options

```yaml
# iam-validator.yaml
checks:
  my_check:
    enabled: true
    severity: high
    # Custom options
    required_tags:
      - Environment
      - Owner
      - CostCenter
```

## Testing

### Write Unit Tests

```python
import pytest
from iam_validator.core.aws_service import AWSServiceFetcher
from iam_validator.core.check_registry import CheckConfig
from iam_validator.core.models import Statement
from my_checks.mfa_check import MFARequiredCheck


@pytest.mark.asyncio
async def test_mfa_check_detects_missing_mfa():
    check = MFARequiredCheck()

    statement = Statement(
        effect="Allow",
        action=["iam:DeleteUser"],
        resource="*",
        condition=None,
    )

    config = CheckConfig(
        check_id="mfa_required",
        config={"require_mfa_for": ["iam:DeleteUser"]}
    )

    async with AWSServiceFetcher() as fetcher:
        issues = await check.execute(statement, 0, fetcher, config)

    assert len(issues) == 1
    assert "MFA" in issues[0].message


@pytest.mark.asyncio
async def test_mfa_check_passes_with_condition():
    check = MFARequiredCheck()

    statement = Statement(
        effect="Allow",
        action=["iam:DeleteUser"],
        resource="*",
        condition={"Bool": {"aws:MultiFactorAuthPresent": "true"}},
    )

    config = CheckConfig(
        check_id="mfa_required",
        config={"require_mfa_for": ["iam:DeleteUser"]}
    )

    async with AWSServiceFetcher() as fetcher:
        issues = await check.execute(statement, 0, fetcher, config)

    assert len(issues) == 0
```

### Test Edge Cases

- Empty statements
- Wildcard actions
- Multiple actions in one statement
- Deny statements (usually skip)
- Missing conditions

## Performance

### Avoid Unnecessary AWS Calls

```python
# Good - only call when needed
if needs_validation:
    is_valid, error, _ = await fetcher.validate_action(action)

# Bad - always calls API
for action in actions:
    await fetcher.validate_action(action)  # Even if not needed
```

### Cache Results

```python
class MyCheck(PolicyCheck):
    def __init__(self):
        self._cache = {}

    async def execute(self, statement, idx, fetcher, config):
        cache_key = statement.sid or idx
        if cache_key in self._cache:
            return self._cache[cache_key]

        # ... check logic ...

        self._cache[cache_key] = issues
        return issues
```

## Documentation

### Add Docstrings

```python
class MyCheck(PolicyCheck):
    """Ensures S3 buckets require encryption.

    This check verifies that all S3 PutObject actions include
    the s3:x-amz-server-side-encryption condition to enforce
    encryption at rest.

    Configuration:
        allowed_encryption: List of allowed encryption types
            Default: ["AES256", "aws:kms"]

    Example:
        checks:
          s3_encryption:
            enabled: true
            allowed_encryption:
              - AES256
    """
```
