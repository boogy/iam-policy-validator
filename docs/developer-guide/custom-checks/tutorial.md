---
title: Custom Checks Tutorial
description: Step-by-step guide to creating custom checks
---

# Custom Checks Tutorial

Learn how to create custom validation checks step by step.

## Prerequisites

- Python 3.10+
- IAM Policy Validator installed
- Basic understanding of IAM policies

## Step 1: Create Check File

Create a directory for your checks:

```bash
mkdir my-checks
```

Create `my-checks/mfa_check.py`:

```python
from typing import ClassVar

from iam_validator.core.check_registry import PolicyCheck, CheckConfig
from iam_validator.core.aws_service import AWSServiceFetcher
from iam_validator.core.models import Statement, ValidationIssue


class MFARequiredCheck(PolicyCheck):
    """Ensures sensitive actions require MFA authentication."""

    check_id: ClassVar[str] = "mfa_required"
    description: ClassVar[str] = "Ensures sensitive actions require MFA"
    default_severity: ClassVar[str] = "high"

    async def execute(
        self,
        statement: Statement,
        statement_idx: int,
        fetcher: AWSServiceFetcher,
        config: CheckConfig,
    ) -> list[ValidationIssue]:
        """Check that sensitive actions have MFA conditions."""
        issues = []

        # Only check Allow statements
        if statement.effect != "Allow":
            return issues

        # Get actions that require MFA from config
        require_mfa_for = set(config.config.get("require_mfa_for", []))

        # Get actions from statement
        actions = statement.get_actions()

        for action in actions:
            if action in require_mfa_for:
                if not self._has_mfa_condition(statement):
                    issues.append(
                        ValidationIssue(
                            severity=self.get_severity(config),
                            statement_sid=statement.sid,
                            statement_index=statement_idx,
                            issue_type="missing_mfa_condition",
                            message=f"Action '{action}' requires MFA",
                            action=action,
                            suggestion="Add aws:MultiFactorAuthPresent condition",
                            line_number=statement.line_number,
                        )
                    )

        return issues

    def _has_mfa_condition(self, statement: Statement) -> bool:
        """Check if statement has MFA condition."""
        if not statement.condition:
            return False

        for operator, conditions in statement.condition.items():
            if "aws:MultiFactorAuthPresent" in conditions:
                value = conditions["aws:MultiFactorAuthPresent"]
                if isinstance(value, bool) and value:
                    return True
                if isinstance(value, str) and value.lower() == "true":
                    return True

        return False
```

## Step 2: Create Configuration

Create `iam-validator.yaml`:

```yaml
settings:
  custom_checks_dir: "./my-checks"

checks:
  mfa_required:
    enabled: true
    severity: high
    require_mfa_for:
      - "iam:DeleteUser"
      - "iam:DeleteRole"
      - "s3:DeleteBucket"
```

## Step 3: Create Test Policy

Create `test-policy.json`:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DeleteUsers",
      "Effect": "Allow",
      "Action": "iam:DeleteUser",
      "Resource": "*"
    }
  ]
}
```

## Step 4: Run Validation

```bash
iam-validator validate --path test-policy.json --config iam-validator.yaml
```

**Expected Output:**

```
❌ [1/1] test-policy.json • INVALID

Issues (1)
└── 🔴 High
    └── [Statement: DeleteUsers] mfa_required
        └── Action 'iam:DeleteUser' requires MFA
            └── 💡 Add aws:MultiFactorAuthPresent condition
```

## Step 5: Fix the Policy

Update the policy with MFA condition:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DeleteUsers",
      "Effect": "Allow",
      "Action": "iam:DeleteUser",
      "Resource": "*",
      "Condition": {
        "Bool": {
          "aws:MultiFactorAuthPresent": "true"
        }
      }
    }
  ]
}
```

Re-run validation:

```bash
iam-validator validate --path test-policy.json --config iam-validator.yaml
```

**Output:**

```
✅ [1/1] test-policy.json • VALID
```

## Check Types

### Statement-Level Checks

Run on each statement:

```python
async def execute(
    self,
    statement: Statement,
    statement_idx: int,
    fetcher: AWSServiceFetcher,
    config: CheckConfig,
) -> list[ValidationIssue]:
    # Check individual statement
    pass
```

### Policy-Level Checks

Run once per policy:

```python
async def execute_policy(
    self,
    policy: IAMPolicy,
    policy_file: str,
    fetcher: AWSServiceFetcher,
    config: CheckConfig,
    **kwargs,
) -> list[ValidationIssue]:
    # Check entire policy
    pass
```

## Restricting to Policy Types

Set `applies_to_policy_types` when a check is only meaningful for some policy types
(e.g. a check about role assumption makes no sense on a service control policy):

```python
class MFARequiredCheck(PolicyCheck):
    check_id: ClassVar[str] = "mfa_required"
    description: ClassVar[str] = "Ensures sensitive actions require MFA"
    applies_to_policy_types: ClassVar[frozenset[str] | None] = frozenset(
        {"IDENTITY_POLICY", "RESOURCE_POLICY"}
    )
```

`None` (the default) means the check runs for every policy type. The valid members are
the `PolicyType` values defined in `iam_validator/core/models.py` — currently
`IDENTITY_POLICY`, `RESOURCE_POLICY`, `TRUST_POLICY`, `SERVICE_CONTROL_POLICY`, and
`RESOURCE_CONTROL_POLICY`; check that module for the current list. Declaring a member
that isn't one of these raises `ValueError` when the check is registered.

## Next Steps

- [Examples](examples.md) — More check examples
- [Best Practices](best-practices.md) — Writing effective checks
