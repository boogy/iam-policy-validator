# Condition Requirements

Enforce IAM conditions on sensitive actions using modular, Python-based requirements.

## Why Modular?

- Easy to read and customize
- Type-safe with IDE support
- Pre-built requirements library

## Available Requirements

**Default (Enabled):**
- `iam_pass_role` - Requires `iam:PassedToService` condition
- `s3_org_id` - Requires AWS organization ID for S3 writes
- `source_ip_restrictions` - Restricts access by IP
- `s3_secure_transport` - Enforces HTTPS for S3
- `prevent_public_ip` - Blocks `0.0.0.0/0` IP ranges

## Quick Start

### Use Defaults (Recommended)

```yaml
action_condition_enforcement:
  enabled: true  # Uses all 5 requirements
```

### Python Customization

```python
from iam_validator.core.config import CONDITION_REQUIREMENTS
from iam_validator.core.config.condition_requirements import (
    IAM_PASS_ROLE_REQUIREMENT,
    S3_WRITE_ORG_ID,
    S3_SECURE_TRANSPORT,
)
import copy

# Use all requirements
requirements = copy.deepcopy(CONDITION_REQUIREMENTS)

# Or pick specific ones
my_reqs = [
    IAM_PASS_ROLE_REQUIREMENT,
    S3_WRITE_ORG_ID,
    S3_SECURE_TRANSPORT,
]
```

### Add Custom Requirement

```python
custom_requirement = {
    "actions": ["lambda:CreateFunction"],
    "severity": "high",
    "required_conditions": [{
        "condition_key": "lambda:VpcConfig",
        "description": "Lambda must be in VPC"
    }]
}

import copy
requirements = copy.deepcopy(CONDITION_REQUIREMENTS)
requirements.append(custom_requirement)
```

## API Reference

```python
from iam_validator.core.config import CONDITION_REQUIREMENTS
from iam_validator.core.config.condition_requirements import (
    IAM_PASS_ROLE_REQUIREMENT,
    S3_WRITE_ORG_ID,
    SOURCE_IP_RESTRICTIONS,
    S3_SECURE_TRANSPORT,
    PREVENT_PUBLIC_IP,
)
import copy

# Get all requirements
requirements = copy.deepcopy(CONDITION_REQUIREMENTS)

# Or pick specific ones
my_reqs = [IAM_PASS_ROLE_REQUIREMENT, S3_SECURE_TRANSPORT]

# Filter by severity
high_risk = [req for req in CONDITION_REQUIREMENTS if req.get('severity') in ['high', 'critical']]

# Access requirement metadata
severity = IAM_PASS_ROLE_REQUIREMENT.get('severity')
description = IAM_PASS_ROLE_REQUIREMENT['required_conditions'][0]['description']
```

## Requirement Structure

```python
{
    "actions": ["iam:PassRole"],
    "severity": "high",  # Optional: Override check-level severity
    "required_conditions": [{
        "condition_key": "iam:PassedToService",
        "description": "Restrict which services can assume the role",  # User-facing explanation
        "example": '{\n  "Condition": {\n    "StringEquals": {\n      "iam:PassedToService": "lambda.amazonaws.com"\n    }\n  }\n}',  # Optional: Shows in GitHub with ```json formatting
        "expected_value": "lambda.amazonaws.com",  # Optional: Specific value to check
        "operator": "StringEquals",  # Optional: Condition operator (default: StringEquals)
    }]
}
```

**Field Reference:**
- `condition_key` (required) - The IAM condition key to enforce
- `description` (optional) - Explanation shown to users (plain text suggestion)
- `example` (optional) - Code example (formatted as ` ```json ` block in GitHub PR comments)
- `expected_value` (optional) - Specific value the condition should have
- `operator` (optional) - Condition operator type (default: "StringEquals")

**Advanced Conditions:**
```python
{
    "actions": ["ec2:RunInstances"],
    "required_conditions": {
        "all_of": [...],   # ALL required
        "any_of": [...],   # At least ONE
        "none_of": [...],  # NONE allowed
    }
}
```

## YAML Alternative

```yaml
action_condition_enforcement:
  enabled: true
  action_condition_requirements:
    - actions: [iam:PassRole]
      severity: high
      required_conditions:
        - condition_key: iam:PassedToService
```

**Tip:** Python approach is more maintainable for complex setups

## Common Use Cases

```python
from iam_validator.core.config import CONDITION_REQUIREMENTS
from iam_validator.core.config.condition_requirements import (
    IAM_PASS_ROLE_REQUIREMENT,
    S3_WRITE_ORG_ID,
    S3_SECURE_TRANSPORT,
    SOURCE_IP_RESTRICTIONS,
)
import copy

# Strict security - all high/critical
strict = [req for req in CONDITION_REQUIREMENTS if req.get('severity') in ['high', 'critical']]

# Development - essentials only
dev = [
    IAM_PASS_ROLE_REQUIREMENT,
    S3_SECURE_TRANSPORT,
]

# Production - comprehensive (all requirements)
prod = copy.deepcopy(CONDITION_REQUIREMENTS)
```

## Performance

- **Load time:** <1ms (5ms first call)
- **Memory:** ~10KB per requirement
- **vs YAML:** 10x faster, 5x smaller

## See Also

- [Modular Configuration](modular-configuration.md) - Architecture details
- [Configuration Reference](configuration.md) - YAML configuration
- [Custom Checks](custom-checks.md) - Custom validation rules
