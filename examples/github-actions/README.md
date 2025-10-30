# GitHub Actions Workflow Examples

This directory contains example GitHub Actions workflows for validating IAM policies.

## Quick Start

Choose one of these workflows and copy it to `.github/workflows/` in your repository:

### 1. **basic-validation.yaml** - Simple validation
- Validates IAM policies on every pull request
- Posts results as PR comments
- Good starting point for most projects

### 2. **sequential-validation.yaml** ⭐ **RECOMMENDED**
- Runs AWS Access Analyzer first, then custom checks
- Two-stage validation with early exit
- Best of both worlds

### 3. **access-analyzer-only.yaml** - AWS official validation
- Uses only AWS IAM Access Analyzer
- Requires AWS credentials
- Fast validation

### 4. **resource-policy-validation.yaml** - Resource policies
- For S3 bucket policies, SNS topics, etc.
- Uses `--policy-type RESOURCE_POLICY`

### 5. **multi-region-validation.yaml** - Multi-region testing
- Validates across multiple AWS regions
- Matrix strategy for parallel execution

### 6. **two-step-validation.yaml** - Separate validation & reporting
- Generate report first
- Post to PR in separate job
- Useful for approval workflows

### 7. **custom-policy-checks.yml** - Advanced security checks
- CheckAccessNotGranted - prevent dangerous actions
- CheckNoNewAccess - compare against baseline
- CheckNoPublicAccess - prevent public exposure

### 8. **validate-changed-files.yaml** ⭐ **SMART FILTERING**
- Validates only files changed in PR
- Automatically detects and filters IAM policies
- Skips non-IAM JSON/YAML files (configs, data, schemas)
- Perfect for mixed repositories

## Usage

1. **Copy a workflow** to your repository: `.github/workflows/iam-validation.yml`
2. **Update paths** to match your policy directory
3. **Configure AWS credentials** (if using Access Analyzer) - see below
4. **Commit and test** on a pull request

## AWS Credentials Setup (for Access Analyzer)

**Recommended:** Use OpenID Connect (OIDC) for secure authentication.

See the [GitHub Actions Workflows Guide](../../docs/github-actions-workflows.md) for detailed setup instructions including:
- OIDC configuration
- IAM role creation
- Required permissions
- Troubleshooting

## Customization

### Change policy paths
```yaml
on:
  pull_request:
    paths:
      - 'iam/**/*.json'  # Your policy directory
```

### Adjust failure behavior
```yaml
# Fail on warnings
--fail-on-warnings

# Only fail on errors (remove the flag above)
```

### Control PR comments
```yaml
# Summary + line-specific comments
--github-comment --github-review

# Summary only
--github-comment

# No comments (validation only)
# Remove both flags
```

## Additional Resources

- **[Complete Workflow Documentation](../../docs/github-actions-workflows.md)** - Detailed setup guide
- **[GitHub Actions Examples](../../docs/github-actions-examples.md)** - Additional examples and patterns
- **[Main Documentation](../../DOCS.md)** - Full CLI reference
