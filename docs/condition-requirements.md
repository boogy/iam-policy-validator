# Condition Requirements

Enforce IAM conditions on sensitive actions using modular, Python-based requirements.

## Why Modular?

- Easy to read and customize
- Type-safe with IDE support
- No complex nested YAML
- Pre-built requirements library

## Available Requirements

**Default (Enabled):**
- `iam_pass_role` - Requires `iam:PassedToService` condition
- `iam_permissions_boundary` - Enforces permissions boundary for IAM operations
- `s3_org_id` - Requires AWS organization ID for S3 writes
- `source_ip_restrictions` - Restricts access by IP
- `s3_secure_transport` - Enforces HTTPS for S3

**Optional (Disabled by default):**
- `s3_destructive_mfa` - Requires MFA for S3 delete operations
- `s3_require_https` - Enforces HTTPS for all S3 operations
- `ec2_vpc_restriction` - Limits EC2 to specific VPCs
- `ec2_tag_requirements` - Enforces ABAC tags on EC2
- `rds_tag_requirements` - Enforces tags on RDS resources
- `s3_bucket_tag_requirements` - Enforces tags on S3 buckets
- `forbidden_actions` - Blocks specified actions
- `prevent_public_ip` - Blocks `0.0.0.0/0` IP ranges

## Quick Start

### Use Defaults (Recommended)

```yaml
action_condition_enforcement:
  enabled: true  # Uses 5 default requirements
```

### Python Customization

```python
from iam_validator.core.config import (
    get_default_requirements,
    get_requirement,
    get_requirements_by_names,
)

# Start with defaults
requirements = get_default_requirements()

# Add optional requirements
requirements.append(get_requirement('s3_destructive_mfa'))
requirements.append(get_requirement('ec2_tag_requirements'))

# Or pick specific ones
my_reqs = get_requirements_by_names([
    'iam_pass_role',
    's3_destructive_mfa',
    'ec2_tag_requirements',
])
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

requirements = get_default_requirements()
requirements.append(custom_requirement)
```

## API Reference

```python
from iam_validator.core.config import (
    get_all_requirement_names,      # List all available
    get_requirement,                 # Get single requirement
    get_requirements_by_names,       # Get specific set
    get_requirements_by_severity,    # Filter by severity
    describe_requirement,            # Get metadata
)

# Examples
names = get_all_requirement_names()
req = get_requirement('iam_pass_role')
my_reqs = get_requirements_by_names(['iam_pass_role', 's3_destructive_mfa'])
high_risk = get_requirements_by_severity('high')
```

## Requirement Structure

```python
{
    "actions": ["iam:PassRole"],
    "severity": "high",
    "required_conditions": [{
        "condition_key": "iam:PassedToService",
        "description": "Why needed",
        "expected_value": "lambda.amazonaws.com",  # Optional
        "operator": "StringEquals",  # Optional
    }]
}
```

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
from iam_validator.core.config import (
    get_requirements_by_severity,
    get_requirements_by_names,
)

# Strict security - all high/critical
strict = get_requirements_by_severity('high')

# Development - essentials only
dev = get_requirements_by_names([
    'iam_pass_role',
    's3_secure_transport',
])

# Production - comprehensive
prod = get_requirements_by_names([
    'iam_pass_role',
    'iam_permissions_boundary',
    's3_destructive_mfa',
    'ec2_tag_requirements',
])

# ABAC - tag enforcement
abac = get_requirements_by_names([
    'ec2_tag_requirements',
    'rds_tag_requirements',
    's3_bucket_tag_requirements',
])
```

## Performance

- **Load time:** <1ms (5ms first call)
- **Memory:** ~10KB per requirement
- **vs YAML:** 10x faster, 5x smaller

## See Also

- [Modular Configuration](modular-configuration.md) - Architecture details
- [Configuration Reference](configuration.md) - YAML configuration
- [Custom Checks](custom-checks.md) - Custom validation rules
