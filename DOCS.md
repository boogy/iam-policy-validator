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
10. [Cache Management](#cache-command)
11. [Development](#development)

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

The IAM Policy Validator can be used in GitHub Actions in **two ways**:

### **Option A: As a Standalone GitHub Action (Recommended)**

Use the published action directly - it handles all setup automatically (Python, uv, dependencies):

```yaml
- name: Validate IAM Policies
  uses: boogy/iam-policy-validator@v1
  with:
    path: policies/
    post-comment: true
    create-review: true
```

**Benefits:**
- ✅ Zero setup required - action handles everything
- ✅ Automatic caching of dependencies
- ✅ Consistent environment across runs
- ✅ Simple, declarative configuration

### **Option B: As a Python Module/CLI Tool**

Install and run the validator manually in your workflow:

```yaml
- name: Set up Python
  uses: actions/setup-python@v5
  with:
    python-version: '3.13'

- name: Install uv
  uses: astral-sh/setup-uv@v3

- name: Install dependencies
  run: uv sync

- name: Validate IAM Policies
  run: uv run iam-validator validate --path ./policies/ --github-comment
```

**Use when you need:**
- Full control over the Python environment
- Custom dependency versions
- Integration with existing setup steps
- Advanced CLI options not exposed in the action

---

## Workflow Examples

### Option 1: Basic Validation (Standalone Action)

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
        uses: actions/checkout@v5

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

Use AWS Access Analyzer first, then custom checks (standalone action):

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
        uses: actions/checkout@v5

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
        uses: astral-sh/setup-uv@v7

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

### Option 3: Using as Python Module (Manual Setup)

When you need more control or want to use the CLI directly:

```yaml
name: IAM Policy Validation (CLI)

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
        uses: actions/checkout@v5

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
            --fail-on-warnings \
            --log-level info
```

**Use this approach when:**
- You need access to CLI options not exposed in the action (e.g., `--log-level`, `--custom-checks-dir`, `--stream`)
- You want to run multiple validation commands in sequence
- You're already using `uv` in your workflow
- You need to customize the Python environment

### Option 4: Custom Security Checks (Standalone Action)

Use the standalone action for custom security checks:

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
        uses: actions/checkout@v5

      - name: Configure AWS Credentials
        uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: ${{ secrets.AWS_ROLE_ARN }}
          aws-region: us-east-1

      # Prevent dangerous actions
      - name: Check for Dangerous Actions
        uses: boogy/iam-policy-validator@v1
        with:
          path: policies/
          use-access-analyzer: true
          check-access-not-granted: "s3:DeleteBucket iam:CreateAccessKey iam:AttachUserPolicy"
          post-comment: true
          fail-on-warnings: true

      # Check S3 bucket policies for public access
      - name: Check S3 Public Access
        uses: boogy/iam-policy-validator@v1
        with:
          path: s3-policies/
          use-access-analyzer: true
          policy-type: RESOURCE_POLICY
          check-no-public-access: true
          public-access-resource-type: "AWS::S3::Bucket"
          post-comment: true
          fail-on-warnings: true

      # Compare against baseline
      - name: Checkout baseline from main
        uses: actions/checkout@v5
        with:
          ref: main
          path: baseline

      - name: Check for New Access
        uses: boogy/iam-policy-validator@v1
        with:
          path: policies/role-policy.json
          use-access-analyzer: true
          check-no-new-access: baseline/policies/role-policy.json
          post-comment: true
          fail-on-warnings: true
```

---

## When to Use Each Approach

### Use Standalone Action (`uses: boogy/iam-policy-validator@v1`) when:
- ✅ You want zero-setup validation (recommended for most users)
- ✅ You need simple, declarative configuration
- ✅ You're validating policies in CI/CD
- ✅ You want automatic dependency management

### Use Python Module/CLI (`uv run iam-validator`) when:
- ✅ You need advanced CLI options (e.g., `--log-level`, `--custom-checks-dir`, `--stream`, `--no-registry`)
- ✅ You want to run multiple validation commands in sequence
- ✅ You need full control over the Python environment
- ✅ You're integrating with existing Python-based workflows
- ✅ You're developing or testing the validator itself

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

### Global Options

These options are available for all commands:

```bash
--log-level {debug,info,warning,error,critical}
                              Set logging level (default: warning)
--version                     Show version information and exit
```

### `validate` Command

Validate IAM policies against AWS service definitions:

```bash
iam-validator validate --path PATH [OPTIONS]

Options:
  --path PATH, -p PATH          Path to IAM policy file or directory (required, can be repeated)
  --format, -f {console,enhanced,json,markdown,html,csv,sarif}
                                Output format (default: console)
                                - console: Clean terminal output
                                - enhanced: Modern visual output with Rich library
  --output OUTPUT, -o OUTPUT    Output file path (for json/markdown/html/csv/sarif formats)
  --stream                      Process files one-by-one (memory efficient, progressive feedback)
  --batch-size BATCH_SIZE       Number of policies to process per batch (default: 10, only with --stream)
  --no-recursive                Don't recursively search directories
  --fail-on-warnings            Fail validation if warnings are found (default: only fail on errors)
  --github-comment              Post validation results as GitHub PR comment
  --github-review               Create line-specific review comments on PR (requires --github-comment)
  --config CONFIG, -c CONFIG    Path to configuration file (default: auto-discover iam-validator.yaml)
  --custom-checks-dir DIR       Path to directory containing custom checks for auto-discovery
  --no-registry                 Use legacy validation (disable check registry system)
  --verbose, -v                 Enable verbose logging
```

**Examples:**

```bash
# Basic validation
iam-validator validate --path policy.json

# Multiple paths with JSON output
iam-validator validate --path ./iam/ --path ./s3-policies/ --format json --output report.json

# Enhanced visual output
iam-validator validate --path ./policies/ --format enhanced

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
  --policy-type, -t {IDENTITY_POLICY,RESOURCE_POLICY,SERVICE_CONTROL_POLICY}
                                Type of IAM policy to validate (default: IDENTITY_POLICY)
  --region REGION               AWS region for Access Analyzer (default: us-east-1)
  --profile PROFILE             AWS profile to use for Access Analyzer
  --format, -f {console,json,markdown}
                                Output format (default: console)
  --output OUTPUT, -o OUTPUT    Output file path (only for json/markdown formats)
  --no-recursive                Don't recursively search directories
  --fail-on-warnings            Fail validation if warnings are found (default: only fail on errors)
  --github-comment              Post validation results as GitHub PR comment
  --github-review               Create line-specific review comments on PR (requires --github-comment)
  --run-all-checks              Run full validation checks if Access Analyzer passes
  --verbose, -v                 Enable verbose logging

  # Custom Policy Checks
  --check-access-not-granted ACTION [ACTION ...]
                                Check that policy does NOT grant specific actions (e.g., s3:DeleteBucket)
  --check-access-resources RESOURCE [RESOURCE ...]
                                Resources to check with --check-access-not-granted (e.g., arn:aws:s3:::bucket/*)
  --check-no-new-access EXISTING_POLICY
                                Path to existing policy to compare against for new access checks
  --check-no-public-access      Check that resource policy does not allow public access (for RESOURCE_POLICY type only)
  --public-access-resource-type {all,AWS::S3::Bucket,...}
                                Resource type(s) for public access check. Use 'all' to check all 29 types.
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
  --report, -r REPORT           Path to JSON report file (required)
  --create-review               Create line-specific review comments (default: True)
  --no-review                   Don't create line-specific review comments
  --add-summary                 Add summary comment (default: True)
  --no-summary                  Don't add summary comment
```

**Examples:**

```bash
# Post report with line comments and summary
iam-validator post-to-pr --report report.json

# Post only summary comment
iam-validator post-to-pr --report report.json --no-review

# Post only line comments (no summary)
iam-validator post-to-pr --report report.json --no-summary
```

### `cache` Command

Manage AWS service definition cache for improved performance:

```bash
iam-validator cache {info,list,clear,refresh,prefetch,location}

Subcommands:
  info                Show cache information and statistics
  list                List all cached AWS services
  clear               Clear all cached AWS service definitions
  refresh             Clear cache and pre-fetch common AWS services
  prefetch            Pre-fetch common AWS services (without clearing)
  location            Show cache directory location
```

**Examples:**

```bash
# Show cache information and statistics
iam-validator cache info

# List all cached AWS services
iam-validator cache list

# Clear all cached service definitions
iam-validator cache clear

# Refresh cache (clear and pre-fetch common services)
iam-validator cache refresh

# Pre-fetch common AWS services without clearing existing cache
iam-validator cache prefetch

# Show cache directory location
iam-validator cache location
```

---

## Configuration

> **📢 Configuration Change (v1.1.0+):** The `allowed_wildcards` configuration has moved from `action_validation_check` to `security_best_practices_check` for cleaner separation of concerns. If you have a custom config file, update it accordingly. See [Migration Note](#configuration-migration) below.

### Configuration File

Create a configuration file (e.g., `my-config.yaml`) based on [default-config.yaml](default-config.yaml):

```yaml
# ============================================================================
# GLOBAL SETTINGS
# ============================================================================
settings:
  # Stop validation on first error
  fail_fast: false

  # Maximum number of concurrent policy validations
  max_concurrent: 10

  # Enable/disable ALL built-in checks (default: true)
  # Set to false when using AWS Access Analyzer to avoid redundant validation
  enable_builtin_checks: true

  # Enable parallel execution of checks (default: true)
  parallel_execution: true

  # Cache AWS service definitions locally
  cache_enabled: true
  cache_directory: ".cache/aws_services"
  cache_ttl_hours: 24

  # Severity levels that cause validation to fail
  fail_on_severity:
    - error     # IAM policy validity errors
    - critical  # Critical security issues
    # - high    # Uncomment to fail on high security issues
    # - warning # Uncomment to fail on IAM validity warnings

# ============================================================================
# BUILT-IN CHECKS - AWS Validation
# ============================================================================

# Validate Statement ID (Sid) uniqueness
sid_uniqueness_check:
  enabled: true
  severity: error

# Validate IAM actions against AWS service definitions
action_validation_check:
  enabled: true
  severity: error
  description: "Validates that actions exist in AWS services"
  # Note: Wildcard security checks are handled by security_best_practices_check

# Validate condition keys
condition_key_validation_check:
  enabled: true
  severity: error

# Validate resource ARN format
resource_validation_check:
  enabled: true
  severity: error

# Security best practices
security_best_practices_check:
  enabled: true
  # Define allowed wildcard patterns for safe read-only operations
  allowed_wildcards:
    - "s3:List*"
    - "s3:Describe*"
    - "ec2:Describe*"
    - "iam:Get*"
    - "iam:List*"
    - "cloudwatch:Describe*"
    - "logs:Describe*"

  wildcard_action_check:
    enabled: true
    severity: medium
  wildcard_resource_check:
    enabled: true
    severity: medium
    # Inherits allowed_wildcards from parent
  full_wildcard_check:
    enabled: true
    severity: critical  # Action:* + Resource:* is critical!
  service_wildcard_check:
    enabled: true
    severity: high
  sensitive_action_check:
    enabled: true
    severity: medium

# Action condition enforcement (MFA, IP restrictions, tags, etc.)
action_condition_enforcement_check:
  enabled: true
  severity: high
```

Use with: `iam-validator validate --path policy.json --config my-config.yaml`

See [default-config.yaml](default-config.yaml) for full documentation with all available options.

### Severity Levels

**IAM Validity Severities** (for AWS IAM policy correctness):
- **error**: Policy violates AWS IAM rules (invalid actions, ARNs, etc.) - fails validation
- **warning**: Policy may have IAM-related issues but is technically valid
- **info**: Informational messages about the policy structure

**Security Severities** (for security best practices):
- **critical**: Critical security risk (e.g., Action:* + Resource:*) - fails validation by default
- **high**: High security risk (e.g., missing required conditions)
- **medium**: Medium security risk (e.g., overly permissive wildcards)
- **low**: Low security risk (e.g., minor best practice violations)

By default, validation fails on `error` and `critical` severities. Use `--fail-on-warnings` to fail on all issues.

### Example Configurations

See [examples/configs/](examples/configs/) directory for essential configurations:
- `basic-config.yaml` - Minimal configuration with defaults
- `offline-validation.yaml` - For environments without internet access
- `strict-security.yaml` - Enterprise-grade security enforcement

See [examples/configs-old/](examples/configs-old/) for additional example configurations:
- `config-privilege-escalation.yaml` - Detect privilege escalation patterns
- `custom-wildcard-config.yaml` - Custom wildcard action validation

---

## Built-in Validation Checks

### 1. Action Validation

Verifies IAM actions exist in AWS service definitions. This check focuses **solely on validity** - security concerns like wildcards are handled by [Security Best Practices](#4-security-best-practices).

```json
{
  "Effect": "Allow",
  "Action": "s3:GetObject",  // ✅ Valid action
  "Resource": "*"
}
```

```json
{
  "Effect": "Allow",
  "Action": "s3:InvalidAction",  // ❌ Invalid - action doesn't exist
  "Resource": "*"
}
```

```json
{
  "Effect": "Allow",
  "Action": "s3:List*",  // ✅ Valid - wildcards skipped (checked by security_best_practices_check)
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

The `security_best_practices_check` handles all wildcard security validation with customizable allowlists:

```yaml
security_best_practices_check:
  enabled: true

  # Define allowed wildcard patterns (e.g., safe read-only operations)
  # These patterns are considered acceptable and won't trigger warnings
  allowed_wildcards:
    - "s3:List*"        # Safe: listing resources
    - "s3:Describe*"    # Safe: describing configurations
    - "ec2:Describe*"   # Safe: read-only operations
    - "iam:Get*"        # Safe: non-sensitive IAM reads
    - "iam:List*"       # Safe: listing IAM entities
    - "cloudwatch:Describe*"
    - "logs:Describe*"

  # Wildcard resource check uses allowed_wildcards
  # Resource: "*" is acceptable if ALL actions match allowed_wildcards
  wildcard_resource_check:
    enabled: true
    severity: medium
    # Optionally override parent allowed_wildcards for this check:
    # allowed_wildcards:
    #   - "s3:List*"

  # Flag service-level wildcards (e.g., "s3:*")
  service_wildcard_check:
    enabled: true
    severity: high
    # Allow specific services to use wildcards
    allowed_services:
      - "logs"
      - "cloudwatch"
```

**Note:** The `action_validation_check` now focuses solely on validating that actions exist in AWS service definitions. All wildcard security concerns are handled by `security_best_practices_check`.

### Configuration Migration

If you have a custom configuration file from before v1.1.0, update it as follows:

**Before (v1.0.x):**
```yaml
action_validation_check:
  enabled: true
  severity: error
  allowed_wildcards:
    - "s3:List*"
    - "ec2:Describe*"
  disable_wildcard_warnings: true
```

**After (v1.1.0+):**
```yaml
action_validation_check:
  enabled: true
  severity: error
  # allowed_wildcards removed - moved to security_best_practices_check
  # disable_wildcard_warnings removed - no longer needed

security_best_practices_check:
  enabled: true
  # Move allowed_wildcards here
  allowed_wildcards:
    - "s3:List*"
    - "ec2:Describe*"

  wildcard_resource_check:
    enabled: true
    # Automatically inherits allowed_wildcards from parent
```

**Why this change?**
- **Clearer separation**: Action validation checks **validity**, security checks handle **safety**
- **Less confusion**: No overlap between validation and security concerns
- **Better architecture**: Wildcard security logic is centralized in one place

---

## Creating Custom Checks

The validator supports custom validation checks to enforce organization-specific policies and business rules. For comprehensive documentation, see the [Custom Checks Guide](docs/custom-checks.md).

### Quick Start

1. **Create a Custom Check File**

```python
# my_checks/mfa_check.py
from typing import List
from iam_validator.core.models import PolicyValidationIssue, PolicyStatement

def execute(statement: PolicyStatement, policy_document: dict) -> List[PolicyValidationIssue]:
    """Ensure sensitive IAM actions require MFA."""
    issues = []

    sensitive_actions = ["iam:CreateUser", "iam:DeleteUser", "iam:AttachUserPolicy"]
    actions = statement.action if isinstance(statement.action, list) else [statement.action]

    for action in actions:
        if action in sensitive_actions:
            # Check if MFA condition exists
            has_mfa = statement.condition and "aws:MultiFactorAuthPresent" in str(statement.condition)

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

2. **Use the Custom Check**

```bash
# Use custom checks from a directory
iam-validator validate --path ./policies/ --custom-checks-dir ./my_checks

# With configuration file
iam-validator validate --path ./policies/ --config my-config.yaml
```

### Check Types

**Statement-Level Checks:**
- Run on each statement in a policy
- Use `execute(statement, policy_document)` function
- Ideal for action/resource/condition validation

**Policy-Level Checks:**
- Run once per complete policy document
- Use `execute_policy(policy_document, statements)` function
- Ideal for cross-statement validation

### Complete Documentation

See [docs/custom-checks.md](docs/custom-checks.md) for:
- Detailed API documentation
- Multiple complete examples
- Best practices and patterns
- Integration with configuration
- Troubleshooting guide

### Examples

The [examples/custom_checks/](examples/custom_checks/) directory contains ready-to-use examples:
- Privilege escalation detection
- Tag enforcement
- IP restriction requirements
- Time-based access controls

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

Configuration settings for performance:

```yaml
settings:
  # Maximum number of concurrent policy validations
  max_concurrent: 10

  # Enable parallel execution of checks
  parallel_execution: true

  # Cache AWS service definitions locally
  cache_enabled: true
  cache_directory: ".cache/aws_services"
  cache_ttl_hours: 24

# Note: Streaming mode is auto-enabled in CI environments
# File size limits are enforced automatically (100MB default)
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
├── docs/                         # Documentation
│   ├── aws-services-backup.md    # AWS services backup guide
│   ├── configuration.md          # Configuration reference
│   └── custom-checks.md          # Custom checks guide
└── examples/
    ├── iam-test-policies/        # Test IAM policies
    ├── configs/                  # Essential example configs (3 files)
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

The project uses **trusted publishing** to PyPI via GitHub Actions - no API tokens required. See [release.yml](.github/workflows/release.yml) for the automated release workflow.

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
