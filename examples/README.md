# Examples Directory

This directory contains examples, configurations, and templates for using the IAM Policy Validator.

## Directory Structure

```
examples/
├── access-analyzer/       # AWS Access Analyzer integration examples
├── configs/               # Configuration file examples (3 essential configs)
├── custom_checks/         # Custom policy check examples
├── github-actions/        # GitHub Actions workflow examples
├── iam-test-policies/     # Test IAM policies (invalid/problematic cases)
└── none-of-feature/       # none_of feature demonstration
```

## Quick Start

### Basic Validation

Validate a single policy file (JSON or YAML):
```bash
# JSON format
iam-validator validate --path examples/iam-test-policies/sample_policy.json

# YAML format
iam-validator validate --path examples/iam-test-policies/sample_policy.yaml
```

Validate entire directory (both JSON and YAML files):
```bash
iam-validator validate \
  --path examples/iam-test-policies/ \
  --config examples/configs/strict-security.yaml
```

### GitHub Actions Integration

See [github-actions/README.md](github-actions/README.md) for CI/CD integration examples.

### Custom Checks

See [custom_checks/README.md](custom_checks/README.md) for creating custom validation rules.

## Examples by Category

### 1. Configuration Files (`configs/`)

Three essential configurations covering common use cases:

- **`basic-config.yaml`** - Minimal configuration with defaults
  - Good starting point for most users
  - All checks enabled with standard settings
  - Fails on errors and critical issues

- **`offline-validation.yaml`** - For environments without internet access
  - Uses local AWS service definitions
  - No API calls required
  - Perfect for CI/CD pipelines and air-gapped environments

- **`strict-security.yaml`** - Enterprise-grade security enforcement
  - Fails on medium+ severity issues
  - Minimal wildcard allowlist
  - Strict condition requirements for sensitive actions
  - Elevated severity levels

### 2. Test IAM Policies (`iam-test-policies/`)

Collection of 36+ test policies in both **JSON and YAML formats** demonstrating various issues and edge cases:

**Common Test Cases (JSON & YAML):**
- `invalid_policy.*` - Policy with AWS validation errors
- `insecure_policy.*` - Security issues (wildcards, missing conditions)
- `sample_policy.*` - Basic valid IAM policy example
- `wildcard_examples.*` - Various wildcard patterns
- `lambda_developer.*` - Lambda function permissions
- `s3_bucket_access.*` - S3 bucket policies with conditions

**Service-Specific Examples:**
- `lambda_developer.json` - Lambda function permissions
- `s3_bucket_access.json` - S3 bucket policies
- `dynamodb_table_access.json` - DynamoDB operations
- `rds_database_admin.json` - RDS database administration
- `kms_encryption_keys.json` - KMS key management

**Security Test Cases:**
- `privilege_escalation_scattered.json` - Privilege escalation patterns
- `sensitive-action-wildcards.json` - Overly permissive wildcards
- `policy_missing_required_tags.json` - Missing required conditions

See [docs/privilege-escalation.md](../docs/privilege-escalation.md) for privilege escalation detection examples.

### 3. Custom Checks (`custom_checks/`)

Reusable custom check implementations:
- `mfa_required_check.py` - Enforce MFA for sensitive actions
- `region_restriction_check.py` - Restrict actions to specific AWS regions
- `encryption_required_check.py` - Enforce encryption requirements
- `time_based_access_check.py` - Time-based access restrictions
- `domain_restriction_check.py` - Restrict access to specific domains
- `cross_account_external_id_check.py` - Validate cross-account access
- `tag_enforcement_check.py` - Custom tag enforcement logic
- `advanced_multi_condition_validator.py` - Complex multi-condition validation

See [custom_checks/README.md](custom_checks/README.md) for usage details.

### 4. GitHub Actions Workflows (`github-actions/`)

CI/CD integration examples - 7 ready-to-use workflows:
- `basic-validation.yaml` - Simple PR validation workflow
- `sequential-validation.yaml` ⭐ **RECOMMENDED** - Access Analyzer → Custom checks
- `access-analyzer-only.yaml` - AWS Access Analyzer only
- `resource-policy-validation.yaml` - S3/SQS resource policies
- `multi-region-validation.yaml` - Multi-region policy validation
- `two-step-validation.yaml` - Separate validation & reporting
- `custom-policy-checks.yml` - Advanced security checks

See [github-actions/README.md](github-actions/README.md) for quick start and [docs/github-actions-workflows.md](../docs/github-actions-workflows.md) for detailed setup.

### 5. AWS Access Analyzer (`access-analyzer/`)

Example resource policies for Access Analyzer validation:
- `example1.json` - S3 bucket policy
- `example2.json` - SQS queue policy

Usage:
```bash
iam-validator analyze \
  --path examples/access-analyzer/ \
  --policy-type RESOURCE_POLICY
```

## Common Use Cases

### Offline Validation

Validate policies without internet access:
```bash
# First, download AWS service definitions
make download-aws-services

# Then validate using local files
iam-validator validate \
  --path ./policies/ \
  --config examples/configs/offline-validation.yaml
```

### Security Hardening

Enforce strict security policies:
```bash
iam-validator validate \
  --path ./policies/ \
  --config examples/configs/strict-security.yaml
```

### Basic Validation with Defaults

Use standard checks for most cases:
```bash
iam-validator validate \
  --path ./policies/ \
  --config examples/configs/basic-config.yaml
```

### Custom Business Rules

Create organization-specific checks:
```bash
iam-validator validate \
  --path ./policies/ \
  --config your-custom-config.yaml \
  --custom-checks-dir examples/custom_checks/
```

## Testing

Run validation on test cases to see different error types:

```bash
# Invalid AWS actions
iam-validator validate --path examples/iam-test-policies/invalid_policy.json

# Security issues
iam-validator validate --path examples/iam-test-policies/insecure_policy.json

# Validate entire test suite
iam-validator validate --path examples/iam-test-policies/
```

## Contributing

When adding new examples:

1. **Test Policies** → `iam-test-policies/`
2. **Configurations** → `configs/` (only if essential and well-documented)
3. **Custom checks** → `custom_checks/` with documentation
4. **Workflows** → `github-actions/`
5. **Features** → Create a dedicated folder with README

Include:
- Clear description of what the example demonstrates
- Expected output/behavior
- Usage instructions

## Additional Resources

- [Main Documentation](../README.md)
- [Complete Documentation](../DOCS.md)
- [Configuration Reference](../docs/configuration.md)
- [Custom Checks Guide](../docs/custom-checks.md)
- [AWS Services Backup Guide](../docs/aws-services-backup.md)
- [Privilege Escalation Detection](../docs/privilege-escalation.md)
- [GitHub Actions Examples](../docs/github-actions-examples.md)
