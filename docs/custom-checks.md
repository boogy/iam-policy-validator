# Creating Custom Validation Checks

This guide explains how to create custom validation checks for the IAM Policy Validator.

## Overview

Custom checks allow you to enforce organization-specific policies and business rules beyond the built-in AWS validation. The validator supports two types of custom checks:

1. **Statement-Level Checks**: Run on each statement in a policy
2. **Policy-Level Checks**: Run once per complete policy document

## Quick Start

### 1. Create a Custom Check File

Create a Python file in a directory of your choice (e.g., `./my-checks/mfa_check.py`):

```python
from typing import List
from iam_validator.core.models import PolicyValidationIssue, PolicyStatement

def execute(statement: PolicyStatement, policy_document: dict) -> List[PolicyValidationIssue]:
    """
    Check that sensitive IAM actions require MFA.

    Args:
        statement: Single policy statement to validate
        policy_document: Full policy document for context

    Returns:
        List of validation issues found
    """
    issues = []

    # Define sensitive actions requiring MFA
    sensitive_actions = [
        "iam:CreateUser",
        "iam:DeleteUser",
        "iam:AttachUserPolicy",
        "iam:PutUserPolicy"
    ]

    # Get actions from statement (handle both string and list)
    actions = statement.action if isinstance(statement.action, list) else [statement.action]

    for action in actions:
        if action in sensitive_actions:
            # Check if MFA condition exists
            has_mfa = False
            if statement.condition:
                condition_str = str(statement.condition)
                has_mfa = "aws:MultiFactorAuthPresent" in condition_str

            if not has_mfa:
                issues.append(
                    PolicyValidationIssue(
                        check_name="mfa_required",
                        severity="high",
                        message=f"Action '{action}' requires MFA but condition is missing",
                        statement_index=statement.index,
                        action=action,
                        suggestion='Add: {"Bool": {"aws:MultiFactorAuthPresent": "true"}}'
                    )
                )

    return issues
```

### 2. Use the Custom Check

Run validation with your custom checks directory:

```bash
iam-validator validate \
  --path ./policies/ \
  --custom-checks-dir ./my-checks
```

The validator will automatically discover and load all checks in the directory.

## Statement-Level Checks

Statement-level checks are executed for each statement in a policy. They are ideal for:
- Validating individual actions
- Checking condition requirements
- Enforcing resource restrictions
- Verifying principal configurations

### Function Signature

```python
def execute(
    statement: PolicyStatement,
    policy_document: dict
) -> List[PolicyValidationIssue]:
    """Your check logic here."""
    pass
```

### Example: Require Encryption for S3 Operations

```python
from typing import List
from iam_validator.core.models import PolicyValidationIssue, PolicyStatement

def execute(statement: PolicyStatement, policy_document: dict) -> List[PolicyValidationIssue]:
    """Ensure S3 write operations require encryption."""
    issues = []

    # S3 write actions that should require encryption
    s3_write_actions = [
        "s3:PutObject",
        "s3:PutObjectAcl",
        "s3:ReplicateObject"
    ]

    actions = statement.action if isinstance(statement.action, list) else [statement.action]

    for action in actions:
        if action in s3_write_actions:
            # Check for encryption condition
            has_encryption = False
            if statement.condition:
                condition_str = str(statement.condition)
                has_encryption = "s3:x-amz-server-side-encryption" in condition_str

            if not has_encryption:
                issues.append(
                    PolicyValidationIssue(
                        check_name="s3_encryption_required",
                        severity="high",
                        message=f"S3 write action '{action}' should require encryption",
                        statement_index=statement.index,
                        action=action,
                        suggestion='Add condition: {"StringEquals": {"s3:x-amz-server-side-encryption": "AES256"}}'
                    )
                )

    return issues
```

### Example: Restrict Resource Wildcards

```python
from typing import List
from iam_validator.core.models import PolicyValidationIssue, PolicyStatement

def execute(statement: PolicyStatement, policy_document: dict) -> List[PolicyValidationIssue]:
    """Ensure production resources don't use wildcards."""
    issues = []

    # Get resources (handle both string and list)
    resources = statement.resource if isinstance(statement.resource, list) else [statement.resource]

    for resource in resources:
        # Check if resource contains 'production' and uses wildcard
        if "production" in resource.lower() and "*" in resource:
            issues.append(
                PolicyValidationIssue(
                    check_name="production_wildcard",
                    severity="critical",
                    message=f"Production resource '{resource}' should not use wildcards",
                    statement_index=statement.index,
                    resource=resource,
                    suggestion="Replace wildcard with specific resource identifiers"
                )
            )

    return issues
```

## Policy-Level Checks

Policy-level checks run once per complete policy document. They are ideal for:
- Cross-statement validation
- Policy-wide constraints
- Conflicting permission detection
- Overall policy structure validation

### Function Signature

```python
def execute_policy(
    policy_document: dict,
    statements: List[dict]
) -> List[PolicyValidationIssue]:
    """Your policy-level check logic here."""
    pass
```

### Example: Detect Conflicting Allow/Deny

```python
from typing import List
from iam_validator.core.models import PolicyValidationIssue

def execute_policy(policy_document: dict, statements: List[dict]) -> List[PolicyValidationIssue]:
    """Check for conflicting Allow/Deny statements on same resources."""
    issues = []

    resources_allowed = set()
    resources_denied = set()

    for idx, stmt in enumerate(statements):
        resources = stmt.get("Resource", [])
        if not isinstance(resources, list):
            resources = [resources]

        if stmt.get("Effect") == "Allow":
            resources_allowed.update(resources)
        elif stmt.get("Effect") == "Deny":
            resources_denied.update(resources)

    # Find conflicts
    conflicts = resources_allowed & resources_denied
    if conflicts:
        issues.append(
            PolicyValidationIssue(
                check_name="conflicting_statements",
                severity="warning",
                message=f"Policy has conflicting Allow/Deny for resources: {conflicts}",
                suggestion="Review policy logic - Deny statements always override Allow"
            )
        )

    return issues
```

### Example: Enforce Maximum Statements

```python
from typing import List
from iam_validator.core.models import PolicyValidationIssue

def execute_policy(policy_document: dict, statements: List[dict]) -> List[PolicyValidationIssue]:
    """Ensure policy doesn't exceed maximum number of statements."""
    issues = []

    max_statements = 10
    statement_count = len(statements)

    if statement_count > max_statements:
        issues.append(
            PolicyValidationIssue(
                check_name="max_statements_exceeded",
                severity="warning",
                message=f"Policy has {statement_count} statements, exceeding limit of {max_statements}",
                suggestion="Split policy into multiple policies or consolidate similar statements"
            )
        )

    return issues
```

## Check Discovery

The validator discovers custom checks in two ways:

### 1. Automatic Discovery (Recommended)

Place check files in a directory and use `--custom-checks-dir`:

```bash
iam-validator validate \
  --path ./policies/ \
  --custom-checks-dir ./my-checks
```

**Directory structure:**
```
my-checks/
├── mfa_check.py
├── encryption_check.py
└── production_check.py
```

The validator loads all `.py` files with `execute()` or `execute_policy()` functions.

### 2. Configuration File

Register checks in your `iam-validator.yaml`:

```yaml
custom_checks:
  - module: my_checks.mfa_check
    enabled: true
    severity: high
  - module: my_checks.encryption_check
    enabled: true
    severity: critical
```

## Validation Issue Model

The `PolicyValidationIssue` model supports these fields:

```python
PolicyValidationIssue(
    check_name: str,           # Unique check identifier (required)
    severity: str,             # error, warning, info, critical, high, medium, low (required)
    message: str,              # Human-readable issue description (required)
    statement_index: int = -1, # Statement number (0-based), -1 for policy-level
    action: str = None,        # Action that caused the issue
    resource: str = None,      # Resource that caused the issue
    suggestion: str = None,    # Remediation guidance
    line_number: int = None,   # Line number in file (auto-detected)
    column: int = None,        # Column number (auto-detected)
)
```

### Severity Levels

**IAM Validity Severities:**
- `error`: Policy violates AWS IAM rules (invalid actions, ARNs, etc.)
- `warning`: Policy may have IAM-related issues
- `info`: Informational messages

**Security Severities:**
- `critical`: Critical security risk (fails validation by default)
- `high`: High security risk
- `medium`: Medium security risk
- `low`: Low security risk

## Best Practices

### 1. Use Descriptive Check Names

```python
# Good
check_name="require_mfa_for_iam_actions"

# Bad
check_name="check1"
```

### 2. Provide Helpful Suggestions

```python
# Good
suggestion='Add MFA condition: {"Bool": {"aws:MultiFactorAuthPresent": "true"}}'

# Bad
suggestion="Fix this"
```

### 3. Handle Both String and List Values

IAM policies can have actions/resources as strings or lists:

```python
# Always handle both cases
actions = statement.action if isinstance(statement.action, list) else [statement.action]
```

### 4. Use Appropriate Severity Levels

```python
# Critical: Full admin access, public exposure
severity="critical"

# High: Missing security controls, sensitive actions
severity="high"

# Medium: Best practice violations
severity="medium"

# Low: Style issues
severity="low"
```

### 5. Test Your Checks

Create test policies to validate your checks:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "iam:CreateUser",
      "Resource": "*"
    }
  ]
}
```

Run validation:
```bash
iam-validator validate \
  --path test-policy.json \
  --custom-checks-dir ./my-checks \
  --verbose
```

## Advanced Examples

### Cross-Statement Validation

```python
def execute_policy(policy_document: dict, statements: List[dict]) -> List[PolicyValidationIssue]:
    """Ensure Delete actions are explicitly denied if corresponding Get is allowed."""
    issues = []

    allowed_actions = set()
    denied_actions = set()

    for stmt in statements:
        actions = stmt.get("Action", [])
        if not isinstance(actions, list):
            actions = [actions]

        if stmt.get("Effect") == "Allow":
            allowed_actions.update(actions)
        elif stmt.get("Effect") == "Deny":
            denied_actions.update(actions)

    # Check for Get without corresponding Delete denial
    for action in allowed_actions:
        if ":Get" in action:
            service = action.split(":")[0]
            delete_action = f"{service}:Delete*"

            # Check if delete is explicitly denied
            has_delete_deny = any(delete_action in d for d in denied_actions)

            if not has_delete_deny:
                issues.append(
                    PolicyValidationIssue(
                        check_name="missing_delete_deny",
                        severity="medium",
                        message=f"Policy allows {action} but doesn't explicitly deny delete operations",
                        suggestion=f'Add Deny statement for {delete_action}'
                    )
                )

    return issues
```

### Resource Tag Validation

```python
def execute(statement: PolicyStatement, policy_document: dict) -> List[PolicyValidationIssue]:
    """Ensure production resources have ABAC tag conditions."""
    issues = []

    resources = statement.resource if isinstance(statement.resource, list) else [statement.resource]

    for resource in resources:
        if "production" in resource.lower():
            # Check for tag-based conditions
            has_tag_condition = False
            if statement.condition:
                condition_str = str(statement.condition)
                has_tag_condition = "ResourceTag" in condition_str or "PrincipalTag" in condition_str

            if not has_tag_condition:
                issues.append(
                    PolicyValidationIssue(
                        check_name="production_abac_required",
                        severity="high",
                        message=f"Production resource '{resource}' should use ABAC tag conditions",
                        statement_index=statement.index,
                        suggestion='Add: {"StringEquals": {"aws:ResourceTag/environment": "production"}}'
                    )
                )

    return issues
```

## Integration with Configuration

You can make your checks configurable:

```python
# my_checks/configurable_check.py
from typing import List
from iam_validator.core.models import PolicyValidationIssue, PolicyStatement

def execute(statement: PolicyStatement, policy_document: dict, config: dict = None) -> List[PolicyValidationIssue]:
    """Check with configurable severity and message."""
    issues = []

    # Use config if provided, otherwise use defaults
    config = config or {}
    severity = config.get("severity", "medium")
    max_wildcards = config.get("max_wildcards", 3)

    # Your check logic here
    wildcard_count = str(statement.resource).count("*")

    if wildcard_count > max_wildcards:
        issues.append(
            PolicyValidationIssue(
                check_name="excessive_wildcards",
                severity=severity,
                message=f"Statement has {wildcard_count} wildcards (max: {max_wildcards})",
                statement_index=statement.index
            )
        )

    return issues
```

Configure in `iam-validator.yaml`:
```yaml
custom_checks:
  - module: my_checks.configurable_check
    enabled: true
    severity: high
    max_wildcards: 2
```

## Troubleshooting

### Check Not Running

1. Verify file has `execute()` or `execute_policy()` function
2. Check `--custom-checks-dir` path is correct
3. Run with `--verbose` to see loaded checks
4. Ensure check is enabled in config

### Import Errors

Make sure the custom checks directory is in Python path:

```python
# Add at top of check file if needed
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
```

### Type Errors

Use type hints and check types:

```python
from typing import List, Union

actions: Union[str, List[str]] = statement.action
if not isinstance(actions, list):
    actions = [actions]
```

## Examples Directory

See [examples/custom_checks/](../examples/custom_checks/) for more complete examples:
- `privilege_escalation_check.py` - Detect privilege escalation patterns
- `tag_enforcement_check.py` - Enforce resource tagging
- `ip_restriction_check.py` - Require IP restrictions
- `time_based_access_check.py` - Enforce time-based access controls

## See Also

- [Configuration Guide](configuration.md) - Learn about configuration system
- [DOCS.md](../DOCS.md#creating-custom-checks) - Main documentation
- [Contributing Guide](../CONTRIBUTING.md) - Development guidelines
