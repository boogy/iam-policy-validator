# Examples Directory

This directory contains examples, configurations, and templates for using the IAM Policy Validator.

## Directory Structure

```
examples/
├── access-analyzer/       # AWS Access Analyzer integration examples
├── configs/               # Configuration file examples
├── custom_checks/         # Custom policy check examples
├── github-actions/        # GitHub Actions workflow examples
├── none-of-feature/       # none_of feature demonstration
└── policies/              # Sample IAM policies
    ├── samples/           # Valid sample policies
    └── test-cases/        # Test policies (invalid/problematic)
```

## Quick Start

### Basic Validation

Validate a single policy file:
```bash
iam-validator validate --path examples/policies/samples/sample_policy.json
```

Validate with custom configuration:
```bash
iam-validator validate \
  --path examples/policies/test-cases/ \
  --config examples/configs/unified-condition-enforcement.yaml
```

### GitHub Actions Integration

See [github-actions/README.md](github-actions/README.md) for CI/CD integration examples.

### Custom Checks

See [custom_checks/README.md](custom_checks/README.md) for creating custom validation rules.

## Examples by Category

### 1. Configuration Files (`configs/`)

- **`unified-condition-enforcement.yaml`** - Comprehensive condition enforcement configuration
  - MFA requirements
  - IP/VPC restrictions
  - Tag enforcement
  - Time-based access controls

- **`action-condition-enforcement-advanced.yaml`** - Advanced examples with `all_of`/`any_of` logic

- **`custom-business-rules.yaml`** - Organization-specific business rules

### 2. Sample Policies (`policies/`)

#### Valid Samples (`policies/samples/`)
- **`sample_policy.json`** - Basic valid IAM policy example

#### Test Cases (`policies/test-cases/`)
- **`invalid_policy.json`** - Policy with AWS validation errors
- **`insecure_policy.json`** - Policy with security issues (wildcards, missing MFA)
- **`policy_with_wildcard_resources.json`** - Overly permissive resource wildcards
- **`policy_missing_required_tags.json`** - Missing required tag conditions
- **`policy_tag_enforcement_example.json`** - Tag enforcement examples

### 3. Custom Checks (`custom_checks/`)

Reusable custom check implementations:
- **`mfa_required_check.py`** - Enforce MFA for sensitive actions
- **`region_restriction_check.py`** - Restrict actions to specific AWS regions
- **`encryption_required_check.py`** - Enforce encryption requirements
- **`time_based_access_check.py`** - Time-based access restrictions
- **`domain_restriction_check.py`** - Restrict access to specific domains
- **`cross_account_external_id_check.py`** - Validate cross-account access
- **`tag_enforcement_check.py`** - Custom tag enforcement logic
- **`advanced_multi_condition_validator.py`** - Complex multi-condition validation

See [custom_checks/README.md](custom_checks/README.md) for usage details.

### 4. GitHub Actions Workflows (`github-actions/`)

CI/CD integration examples:
- **`basic-validation.yaml`** - Simple PR validation workflow
- **`access-analyzer-only.yaml`** - AWS Access Analyzer only
- **`two-step-validation.yaml`** - Combined built-in + Access Analyzer
- **`multi-region-validation.yaml`** - Multi-region policy validation
- **`resource-policy-validation.yaml`** - S3/SQS resource policies
- **`sequential-validation.yaml`** - Sequential validation stages

See [github-actions/README.md](github-actions/README.md) for setup instructions.

### 5. AWS Access Analyzer (`access-analyzer/`)

Example resource policies for Access Analyzer validation:
- **`example1.json`** - S3 bucket policy
- **`example2.json`** - SQS queue policy

Usage:
```bash
iam-validator analyze \
  --path examples/access-analyzer/ \
  --resource-type AWS::S3::Bucket
```

### 6. none_of Feature (`none-of-feature/`)

Demonstrates the `none_of` logic for forbidding actions and conditions:
- **`README.md`** - Comprehensive guide to using `none_of`
- **`none_of_example.yaml`** - Configuration with forbidden rules
- **`test_none_of_violations.json`** - Policy that violates none_of rules
- **`test_none_of_valid.json`** - Policy that passes none_of rules

See [none-of-feature/README.md](none-of-feature/README.md) for details.

## Common Use Cases

### Security Hardening

Enforce MFA and IP restrictions:
```bash
iam-validator validate \
  --path ./policies/ \
  --config examples/configs/unified-condition-enforcement.yaml
```

### Tag Compliance

Ensure all resources have required tags:
```yaml
# In your config
checks:
  action_condition_enforcement:
    action_condition_requirements:
      - actions:
          - "ec2:RunInstances"
        required_conditions:
          all_of:
            - condition_key: "aws:RequestTag/Owner"
            - condition_key: "aws:RequestTag/CostCenter"
```

### Forbidden Actions

Block dangerous actions completely:
```yaml
checks:
  action_condition_enforcement:
    action_condition_requirements:
      - actions:
          none_of:
            - "iam:*"
            - "s3:DeleteBucket"
        description: "These actions are forbidden"
```

### Custom Business Rules

Create organization-specific checks:
```bash
iam-validator validate \
  --path ./policies/ \
  --config examples/configs/custom-business-rules.yaml \
  --custom-checks-dir examples/custom_checks/
```

## Testing

Run validation on test cases to see different error types:

```bash
# Invalid AWS actions
iam-validator validate --path examples/policies/test-cases/invalid_policy.json

# Security issues
iam-validator validate --path examples/policies/test-cases/insecure_policy.json

# Missing required tags
iam-validator validate \
  --path examples/policies/test-cases/policy_missing_required_tags.json \
  --config examples/configs/unified-condition-enforcement.yaml
```

## Contributing

When adding new examples:

1. **Policies** → `policies/samples/` (valid) or `policies/test-cases/` (invalid)
2. **Configurations** → `configs/`
3. **Custom checks** → `custom_checks/` with documentation
4. **Workflows** → `github-actions/`
5. **Features** → Create a dedicated folder with README

Include:
- Clear description of what the example demonstrates
- Expected output/behavior
- Usage instructions

## Additional Resources

- [Main Documentation](../README.md)
- [Configuration Reference](../docs/configuration.md)
- [Custom Checks Guide](custom_checks/README.md)
- [GitHub Actions Integration](github-actions/README.md)
