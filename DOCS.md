# IAM Policy Auditor - Complete Documentation

> High-performance AWS IAM policy validation using AWS Access Analyzer and custom checks

**Quick Links:** [Installation](#installation) • [Quick Start](#quick-start) • [GitHub Actions](#github-actions) • [Custom Checks](#custom-policy-checks) • [CLI Reference](#cli-reference) • [Configuration](#configuration)

---

## Table of Contents

1. [Installation](#installation)
2. [Quick Start](#quick-start)
3. [GitHub Actions Integration](#github-actions)
4. [CLI Usage](#cli-reference)
5. [Custom Policy Checks](#custom-policy-checks)
6. [Configuration](#configuration)
7. [Built-in Checks](#built-in-validation-checks)
8. [Custom Validation Rules](#creating-custom-checks)
9. [Performance & Optimization](#performance-optimization)
10. [Development](#development)

---

## Installation

### As a GitHub Action

Add to your `.github/workflows/` directory (see [GitHub Actions](#github-actions) section).

### As a CLI Tool

```bash
# Clone and install
git clone https://github.com/boogy/iam-policy-auditor.git
cd iam-policy-auditor
uv sync

# Verify installation
uv run iam-validator --help
```

### As a Python Package

```bash
# From PyPI (once published)
pip install iam-policy-validator

# From source
pip install git+https://github.com/boogy/iam-policy-auditor.git
```

---

## Quick Start

### Basic Validation

```bash
# Validate a single policy
uv run iam-validator validate --path policy.json

# Validate all policies in a directory
uv run iam-validator validate --path ./policies/

# Validate multiple paths
uv run iam-validator validate --path policy1.json --path ./policies/ --path ./more-policies/
```

### AWS Access Analyzer Validation

```bash
# Basic analysis (requires AWS credentials)
uv run iam-validator analyze --path policy.json

# With specific region and profile
uv run iam-validator analyze --path policy.json --region us-west-2 --profile my-profile

# Resource policy validation
uv run iam-validator analyze --path bucket-policy.json --policy-type RESOURCE_POLICY
```

### Sequential Validation (Recommended)

Run AWS Access Analyzer first, then custom checks if it passes:

```bash
uv run iam-validator analyze \
  --path policy.json \
  --github-comment \
  --run-all-checks \
  --github-review
```

This posts two separate PR comments:
1. Access Analyzer results (immediate)
2. Custom validation results (only if Access Analyzer passes)

---

## GitHub Actions

### Option 1: Basic Validation (Custom Checks Only)

Create `.github/workflows/iam-policy-validator.yml`:

```yaml
name: IAM Policy Validation

on:
  pull_request:
    paths:
      - 'policies/**/*.json'

jobs:
  validate:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      pull-requests: write

    steps:
      - name: Checkout code
        uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.12'

      - name: Install uv
        uses: astral-sh/setup-uv@v3

      - name: Install dependencies
        run: uv sync

      - name: Validate IAM Policies
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
          GITHUB_REPOSITORY: ${{ github.repository }}
          GITHUB_PR_NUMBER: ${{ github.event.pull_request.number }}
        run: |
          uv run iam-validator validate \
            --path ./policies/ \
            --github-comment \
            --github-review \
            --fail-on-warnings
```

### Option 2: Sequential Validation (Recommended) ⭐

Run AWS Access Analyzer first, then custom checks:

```yaml
name: Sequential IAM Policy Validation

on:
  pull_request:
    paths:
      - 'policies/**/*.json'

jobs:
  validate:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      pull-requests: write
      id-token: write  # Required for AWS OIDC

    steps:
      - name: Checkout code
        uses: actions/checkout@v4

      - name: Configure AWS Credentials
        uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: arn:aws:iam::123456789012:role/GitHubActionsRole
          aws-region: us-east-1

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.12'

      - name: Install uv
        uses: astral-sh/setup-uv@v3

      - name: Install dependencies
        run: uv sync

      - name: Sequential Validation
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
          GITHUB_REPOSITORY: ${{ github.repository }}
          GITHUB_PR_NUMBER: ${{ github.event.pull_request.number }}
        run: |
          uv run iam-validator analyze \
            --path ./policies/ \
            --github-comment \
            --run-all-checks \
            --github-review \
            --fail-on-warnings
```

**Why Sequential?**
- ✅ Access Analyzer validates first (fast, official AWS validation)
- ✅ Stops immediately if errors found (saves time)
- ✅ Only runs custom checks if Access Analyzer passes
- ✅ Two separate PR comments for clear separation

### Option 3: Custom Security Checks

```yaml
name: IAM Policy Security Validation

on:
  pull_request:
    paths:
      - 'policies/**/*.json'

jobs:
  validate-security:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      pull-requests: write
      id-token: write

    steps:
      - name: Checkout code
        uses: actions/checkout@v4

      - name: Configure AWS Credentials
        uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: ${{ secrets.AWS_ROLE_ARN }}
          aws-region: us-east-1

      # Prevent dangerous actions
      - name: Check for Dangerous Actions
        run: |
          uv run iam-validator analyze \
            --path policies/ \
            --check-access-not-granted "s3:DeleteBucket iam:CreateAccessKey iam:AttachUserPolicy" \
            --github-comment \
            --fail-on-warnings

      # Check S3 bucket policies for public access
      - name: Check S3 Public Access
        run: |
          uv run iam-validator analyze \
            --path s3-policies/ \
            --policy-type RESOURCE_POLICY \
            --check-no-public-access \
            --public-access-resource-type "AWS::S3::Bucket" \
            --github-comment \
            --fail-on-warnings

      # Compare against baseline
      - name: Checkout baseline from main
        uses: actions/checkout@v4
        with:
          ref: main
          path: baseline

      - name: Check for New Access
        run: |
          uv run iam-validator analyze \
            --path policies/role-policy.json \
            --check-no-new-access baseline/policies/role-policy.json \
            --github-comment \
            --fail-on-warnings
```

See `examples/github-actions/` for more workflow examples.

---

## Custom Policy Checks

AWS IAM Access Analyzer provides specialized checks beyond basic validation:

### 1. CheckAccessNotGranted - Prevent Dangerous Actions

Verify policies do NOT grant specific actions (max 100 actions per check):

```bash
# Prevent dangerous S3 actions
uv run iam-validator analyze \
  --path ./policies/ \
  --check-access-not-granted s3:DeleteBucket s3:DeleteObject

# Scope to specific resources
uv run iam-validator analyze \
  --path ./policies/ \
  --check-access-not-granted s3:PutObject \
  --check-access-resources "arn:aws:s3:::production-bucket/*"

# Prevent privilege escalation
uv run iam-validator analyze \
  --path ./policies/ \
  --check-access-not-granted \
    iam:CreateAccessKey \
    iam:AttachUserPolicy \
    iam:PutUserPolicy
```

**Supported:** IDENTITY_POLICY, RESOURCE_POLICY

### 2. CheckNoNewAccess - Validate Policy Updates

Ensure policy changes don't grant new permissions:

```bash
# Compare updated policy against baseline
uv run iam-validator analyze \
  --path ./new-policy.json \
  --check-no-new-access ./old-policy.json

# In CI/CD - compare against main branch
git show main:policies/policy.json > baseline-policy.json
uv run iam-validator analyze \
  --path policies/policy.json \
  --check-no-new-access baseline-policy.json
```

**Supported:** IDENTITY_POLICY, RESOURCE_POLICY

### 3. CheckNoPublicAccess - Prevent Public Exposure

Validate resource policies don't allow public access (29+ resource types):

```bash
# Check S3 bucket policies
uv run iam-validator analyze \
  --path ./bucket-policy.json \
  --policy-type RESOURCE_POLICY \
  --check-no-public-access \
  --public-access-resource-type "AWS::S3::Bucket"

# Check multiple resource types
uv run iam-validator analyze \
  --path ./resource-policies/ \
  --policy-type RESOURCE_POLICY \
  --check-no-public-access \
  --public-access-resource-type "AWS::S3::Bucket" "AWS::Lambda::Function" "AWS::SNS::Topic"

# Check ALL 29 resource types
uv run iam-validator analyze \
  --path ./resource-policies/ \
  --policy-type RESOURCE_POLICY \
  --check-no-public-access \
  --public-access-resource-type all
```

**Supported Resource Types (29 total):**
- **Storage**: S3 Bucket, S3 Access Point, S3 Express, S3 Glacier, S3 Outposts, S3 Tables, EFS
- **Database**: DynamoDB Table/Stream, OpenSearch Domain
- **Messaging**: Kinesis Stream, SNS Topic, SQS Queue
- **Security**: KMS Key, Secrets Manager Secret, IAM Assume Role Policy
- **Compute**: Lambda Function
- **API**: API Gateway REST API
- **DevOps**: CodeArtifact Domain, Backup Vault, CloudTrail

---

## CLI Reference

### `validate` Command

Validate IAM policies against AWS service definitions:

```bash
iam-validator validate --path PATH [OPTIONS]

Options:
  --path PATH, -p PATH          Path to IAM policy file or directory (required, can be repeated)
  --format {console,json,markdown,sarif,csv,html}
                                Output format (default: console)
  --output OUTPUT, -o OUTPUT    Output file path
  --stream                      Enable streaming mode for large policy sets
  --no-recursive                Don't recursively search directories
  --fail-on-warnings            Fail validation if warnings are found
  --github-comment              Post validation results as GitHub PR comment
  --github-review               Create line-specific review comments
  --config CONFIG, -c CONFIG    Path to configuration file (default: iam-validator.yaml)
  --verbose, -v                 Enable verbose logging
```

**Examples:**

```bash
# Basic validation
iam-validator validate --path policy.json

# Multiple paths with JSON output
iam-validator validate --path ./iam/ --path ./s3-policies/ --format json --output report.json

# Streaming mode for large policy sets
iam-validator validate --path ./policies/ --stream

# GitHub PR integration
iam-validator validate --path ./policies/ --github-comment --github-review
```

### `analyze` Command

Validate using AWS IAM Access Analyzer (requires AWS credentials):

```bash
iam-validator analyze --path PATH [OPTIONS]

Options:
  --path PATH, -p PATH          Path to IAM policy file or directory (required, can be repeated)
  --format {console,json,markdown}
                                Output format (default: console)
  --output OUTPUT, -o OUTPUT    Output file path
  --region REGION, -r REGION    AWS region for Access Analyzer (default: us-east-1)
  --policy-type {IDENTITY_POLICY,RESOURCE_POLICY,SERVICE_CONTROL_POLICY}
                                Type of IAM policy (default: IDENTITY_POLICY)
  --profile PROFILE             AWS profile name
  --github-comment              Post results as GitHub PR comment
  --run-all-checks              Run full validation if Access Analyzer passes
  --github-review               Add line-specific review comments (requires --run-all-checks)
  --no-recursive                Don't recursively search directories
  --fail-on-warnings            Fail on any findings
  --verbose, -v                 Enable verbose logging

  # Custom Policy Checks
  --check-access-not-granted ACTION [ACTION ...]
                                Check that policies don't grant specific actions
  --check-access-resources ARN [ARN ...]
                                Resources to check for access-not-granted
  --check-no-new-access PATH    Compare against baseline policy
  --check-no-public-access      Check for public access
  --public-access-resource-type TYPE [TYPE ...]
                                Resource types to check (or 'all')
```

**Examples:**

```bash
# Basic Access Analyzer validation
iam-validator analyze --path policy.json

# Resource policy with public access check
iam-validator analyze \
  --path bucket-policy.json \
  --policy-type RESOURCE_POLICY \
  --check-no-public-access \
  --public-access-resource-type "AWS::S3::Bucket"

# Sequential validation workflow
iam-validator analyze \
  --path policy.json \
  --github-comment \
  --run-all-checks \
  --github-review
```

### `post-to-pr` Command

Post validation reports to GitHub PRs:

```bash
iam-validator post-to-pr --report REPORT [OPTIONS]

Options:
  --report REPORT, -r REPORT    Path to JSON report file (required)
  --create-review               Create line-specific review comments (default: true)
  --no-review                   Don't create review comments
  --add-summary                 Add summary comment (default: true)
  --no-summary                  Don't add summary comment
  --verbose, -v                 Enable verbose logging
```

---

## Configuration

### Configuration File

Create `iam-validator.yaml` in your project root:

```yaml
# Enable/disable checks
checks:
  action_validation:
    enabled: true
    severity: error

  condition_key_validation:
    enabled: true
    severity: warning

  resource_arn_validation:
    enabled: true
    severity: warning

  security_best_practices:
    enabled: true
    wildcard_action_check:
      enabled: true
      severity: warning
    wildcard_resource_check:
      enabled: true
      severity: warning

  sid_uniqueness:
    enabled: true
    severity: error

# GitHub integration
github:
  comment_on_pr: true
  create_review: true
  update_existing_comments: true

# Output settings
output:
  format: console
  verbose: false
```

### Severity Levels

- **error**: Fail validation
- **warning**: Report but don't fail (unless `--fail-on-warnings`)
- **info**: Informational only

### Example Configurations

See `examples/configs/` directory:
- `config-privilege-escalation.yaml` - Detect privilege escalation patterns
- `custom-wildcard-config.yaml` - Custom wildcard action validation

---

## Built-in Validation Checks

### 1. Action Validation

Verifies IAM actions exist in AWS services:

```json
{
  "Effect": "Allow",
  "Action": "s3:GetObject",  // ✅ Valid
  "Resource": "*"
}
```

```json
{
  "Effect": "Allow",
  "Action": "s3:InvalidAction",  // ❌ Invalid
  "Resource": "*"
}
```

### 2. Condition Key Validation

Checks condition keys are valid for specified actions:

```json
{
  "Effect": "Allow",
  "Action": "s3:GetObject",
  "Resource": "*",
  "Condition": {
    "StringEquals": {
      "aws:RequestedRegion": "us-east-1"  // ✅ Valid global condition
    }
  }
}
```

### 3. Resource ARN Validation

Ensures ARNs follow proper AWS format:

```json
{
  "Effect": "Allow",
  "Action": "s3:GetObject",
  "Resource": "arn:aws:s3:::my-bucket/*"  // ✅ Valid ARN
}
```

### 4. Security Best Practices

Identifies security risks:

- **Overly permissive wildcards**: `Action: "*"` with `Resource: "*"`
- **Sensitive actions without conditions**: Administrative permissions
- **Missing MFA requirements**: For privileged operations

### 5. SID Uniqueness

Ensures Statement IDs are unique within a policy:

```json
{
  "Statement": [
    { "Sid": "AllowRead", "Effect": "Allow", "Action": "s3:GetObject" },
    { "Sid": "AllowRead", "Effect": "Allow", "Action": "s3:ListBucket" }  // ❌ Duplicate SID
  ]
}
```

### 6. Wildcard Action Validation

Custom patterns for wildcard actions:

```yaml
# custom-wildcard-config.yaml
checks:
  wildcard_action_check:
    enabled: true
    allowed_actions:
      - s3:Get*
      - s3:List*
    blocked_actions:
      - s3:Delete*
      - iam:*
```

---

## Creating Custom Checks

### Statement-Level Check

Create a check that runs on each statement:

```python
# iam_validator/checks/my_custom_check.py
from typing import List
from iam_validator.models import PolicyValidationIssue, PolicyStatement

def execute(statement: PolicyStatement, policy_document: dict) -> List[PolicyValidationIssue]:
    """
    Check for specific security requirements.

    Args:
        statement: Single policy statement to validate
        policy_document: Full policy document for context

    Returns:
        List of validation issues found
    """
    issues = []

    # Example: Require MFA for sensitive actions
    sensitive_actions = ["iam:CreateUser", "iam:DeleteUser", "iam:AttachUserPolicy"]

    actions = statement.action if isinstance(statement.action, list) else [statement.action]

    for action in actions:
        if action in sensitive_actions:
            # Check if MFA condition exists
            if not statement.condition or "aws:MultiFactorAuthPresent" not in str(statement.condition):
                issues.append(
                    PolicyValidationIssue(
                        check_name="mfa_required",
                        severity="error",
                        message=f"Action '{action}' requires MFA but condition is missing",
                        statement_index=statement.index,
                        action=action,
                        suggestion="Add Condition: {\"Bool\": {\"aws:MultiFactorAuthPresent\": \"true\"}}"
                    )
                )

    return issues
```

### Policy-Level Check

Create a check that runs once per policy:

```python
# iam_validator/checks/policy_wide_check.py
from typing import List
from iam_validator.models import PolicyValidationIssue

def execute_policy(policy_document: dict, statements: List[dict]) -> List[PolicyValidationIssue]:
    """
    Check across all statements in a policy.

    Args:
        policy_document: Full policy document
        statements: All statements in the policy

    Returns:
        List of validation issues found
    """
    issues = []

    # Example: Check for conflicting Allow/Deny on same resource
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

    conflicts = resources_allowed & resources_denied
    if conflicts:
        issues.append(
            PolicyValidationIssue(
                check_name="conflicting_statements",
                severity="warning",
                message=f"Policy has conflicting Allow/Deny for resources: {conflicts}",
                suggestion="Review policy logic for these resources"
            )
        )

    return issues
```

### Register Custom Check

Add to `iam_validator/checks/__init__.py`:

```python
from . import my_custom_check
from . import policy_wide_check

STATEMENT_CHECKS = [
    # ... existing checks ...
    my_custom_check,
]

POLICY_CHECKS = [
    # ... existing checks ...
    policy_wide_check,
]
```

See `examples/custom_checks/` for complete examples.

---

## Performance Optimization

### Streaming Mode

For large policy sets, use streaming mode to reduce memory usage:

```bash
# Enable streaming (processes one policy at a time)
iam-validator validate --path ./policies/ --stream

# Auto-enabled in CI environments
# Streaming provides progressive feedback in GitHub PR comments
```

**Streaming Benefits:**
- ✅ Lower memory usage (one policy in memory at a time)
- ✅ Progressive feedback (see results as files are processed)
- ✅ Partial results (get results even if later files fail)
- ✅ Better CI/CD experience (PR comments appear progressively)

### Performance Features

**Built-in optimizations:**
- **Service Pre-fetching**: Common AWS services cached at startup
- **LRU Memory Cache**: Recently accessed services cached with TTL
- **Request Coalescing**: Duplicate API requests deduplicated
- **Parallel Execution**: Multiple checks run concurrently
- **HTTP/2 Support**: Multiplexed connections for API calls
- **Connection Pooling**: 20 keepalive, 50 max connections

**File Size Limits:**
- Default max: 100MB per policy file
- Files exceeding limit skipped with warning
- Prevents memory exhaustion

### Memory Management

```yaml
# iam-validator.yaml
performance:
  max_file_size_mb: 100
  stream_mode: auto  # auto, true, false
  cache_ttl: 3600
  max_concurrent_checks: 10
```

### GitHub Action Optimization

Streaming is auto-enabled in CI:

```yaml
- name: Validate Large Policy Set
  run: |
    # Streaming auto-enabled in CI
    uv run iam-validator validate \
      --path ./policies/ \
      --github-comment \
      --github-review
```

---

## Development

### Project Structure

```
iam-policy-auditor/
├── action.yaml                    # GitHub Action definition
├── pyproject.toml                 # Python project config
├── iam_validator/                 # Main package
│   ├── models.py                 # Pydantic models
│   ├── aws_fetcher.py            # AWS API client
│   ├── github_integration.py     # GitHub API client
│   ├── cli.py                    # CLI interface
│   ├── checks/                   # Validation checks
│   │   ├── action_validation.py
│   │   ├── condition_validation.py
│   │   ├── resource_validation.py
│   │   └── security_checks.py
│   └── core/
│       ├── policy_loader.py      # Policy loader
│       ├── policy_checks.py      # Validation logic
│       └── report.py             # Report generation
└── examples/
    ├── policies/                 # Example policies
    ├── configs/                  # Example configs
    ├── custom_checks/            # Custom check examples
    └── github-actions/           # GitHub workflow examples
```

### Running Tests

```bash
# Install dev dependencies
uv sync --extra dev

# Run tests
make test

# Run with coverage
make test-coverage

# Type checking
make type-check

# Linting
make lint

# All quality checks
make check
```

### Publishing

See `docs/development/PUBLISHING.md` for release process.

### Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Run quality checks: `make check`
5. Submit a pull request

See `CONTRIBUTING.md` for detailed guidelines.

---

## Environment Variables

### GitHub Integration

- `GITHUB_TOKEN`: GitHub API token (auto-provided in Actions)
- `GITHUB_REPOSITORY`: Repository in format `owner/repo`
- `GITHUB_PR_NUMBER`: Pull request number

### AWS Integration

Standard AWS credential chain:
- `AWS_ACCESS_KEY_ID`
- `AWS_SECRET_ACCESS_KEY`
- `AWS_SESSION_TOKEN`
- `AWS_PROFILE`
- `AWS_REGION`

---

## Troubleshooting

### Common Issues

**"No AWS credentials found"**
- Ensure AWS credentials are configured
- Check `aws configure` or environment variables
- Verify IAM role permissions in GitHub Actions

**"GitHub API rate limit exceeded"**
- Use `GITHUB_TOKEN` for higher rate limits
- Reduce comment frequency
- Use `--no-review` to skip line-specific comments

**"Policy file too large"**
- Enable streaming mode: `--stream`
- Increase file size limit in config
- Split large policies into smaller files

**"Check not found"**
- Verify check name in config file
- Ensure custom check is registered
- Check `--verbose` output for loaded checks

### Debug Mode

```bash
# Enable verbose logging
iam-validator validate --path policy.json --verbose

# Save detailed JSON report
iam-validator validate --path policy.json --format json --output debug.json
```

---

## License

MIT License - see [LICENSE](LICENSE) file for details.

## Support

- **Documentation**: This file and `examples/` directory
- **Issues**: [GitHub Issues](https://github.com/boogy/iam-policy-auditor/issues)
- **Discussions**: [GitHub Discussions](https://github.com/boogy/iam-policy-auditor/discussions)
