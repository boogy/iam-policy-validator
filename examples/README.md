# Examples

This directory contains example files for the IAM Policy Validator.

## Directory Structure

```
examples/
├── configs/              # Configuration file examples
├── custom_checks/        # Custom check examples
├── github-actions/       # GitHub Actions workflow examples
├── iam-test-policies/    # Test IAM policies by type
├── trust-policies/       # Trust policy examples
├── access-analyzer/      # AWS Access Analyzer examples
└── quick-start/          # Quick start policies
```

## Documentation

For detailed documentation, see:

- **Getting Started**: [docs/getting-started/](../docs/getting-started/)
- **Configuration**: [docs/user-guide/configuration.md](../docs/user-guide/configuration.md)
- **GitHub Actions**: [docs/integrations/github-actions.md](../docs/integrations/github-actions.md)
- **Custom Checks**: [docs/developer-guide/custom-checks/](../docs/developer-guide/custom-checks/)

## Quick Start

```bash
# Validate a policy
iam-validator validate examples/quick-start/s3-policy.json

# Use a configuration file
iam-validator validate examples/iam-test-policies/ \
  --config examples/configs/minimal-validation-config.yaml

# Validate trust policies
iam-validator validate examples/trust-policies/ \
  --policy-type TRUST_POLICY
```
