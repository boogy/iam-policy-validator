---
title: GitHub Actions
description: Integrate IAM Policy Validator with GitHub Actions
---

# GitHub Actions Integration

IAM Policy Validator provides a native GitHub Action for seamless CI/CD integration with PR comments, code scanning, and AWS Access Analyzer support.

## Quick Start

```yaml
name: Validate IAM Policies

on:
  pull_request:
    paths:
      - "**.json"
      - "**.yaml"

jobs:
  validate:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      pull-requests: write
    steps:
      - uses: actions/checkout@v4
      - uses: boogy/iam-policy-validator@v1
        with:
          path: ./policies/
```

## Action Inputs

### Core Inputs

| Input | Description | Default |
|-------|-------------|---------|
| `path` | Path(s) to IAM policy files or directories. Use newline-separated values for multiple paths | Required |
| `config-file` | Path to custom configuration file (iam-validator.yaml) | Auto-detect |
| `policy-type` | Policy type: `IDENTITY_POLICY`, `RESOURCE_POLICY`, `TRUST_POLICY`, `SERVICE_CONTROL_POLICY`, `RESOURCE_CONTROL_POLICY` | `IDENTITY_POLICY` |
| `recursive` | Recursively search directories for policy files | `true` |
| `fail-on-warnings` | Fail validation if warnings are found (default: only fail on errors) | `false` |

### GitHub Integration

| Input | Description | Default |
|-------|-------------|---------|
| `post-comment` | Post validation results as PR comment | `true` |
| `create-review` | Create line-specific review comments on PR files | `true` |
| `allow-owner-ignore` | Allow CODEOWNERS to ignore findings by replying 'ignore' | `true` |
| `github-summary` | Write summary to GitHub Actions job summary | `false` |
| `github-token` | GitHub token for posting comments and reviews | `${{ github.token }}` |

### Output Options

| Input | Description | Default |
|-------|-------------|---------|
| `format` | Output format: `console`, `enhanced`, `json`, `markdown`, `sarif`, `csv`, `html` | `console` |
| `output-file` | Path to save output file (for json, markdown, sarif, csv, html formats) | - |
| `upload-sarif` | Upload SARIF results to GitHub Code Scanning | `false` |
| `show-console-output` | Show enhanced validation results in job logs | `true` |
| `summary` | Show Executive Summary section in enhanced output | `false` |
| `severity-breakdown` | Show Issue Severity Breakdown section in enhanced output | `false` |

### Performance Options

| Input | Description | Default |
|-------|-------------|---------|
| `stream` | Process files one-by-one (memory efficient for large repos) | `false` |
| `batch-size` | Number of policies to process per batch when streaming | `10` |
| `aws-services-dir` | Path to pre-downloaded AWS service definitions (offline mode) | - |
| `custom-checks-dir` | Path to directory containing custom validation checks | - |
| `log-level` | Logging level: `debug`, `info`, `warning`, `error`, `critical` | `warning` |

### AWS Access Analyzer

| Input | Description | Default |
|-------|-------------|---------|
| `use-access-analyzer` | Use AWS IAM Access Analyzer for validation | `false` |
| `access-analyzer-region` | AWS region for Access Analyzer | `us-east-1` |
| `run-all-checks` | Run custom checks after Access Analyzer passes | `false` |
| `check-access-not-granted` | Actions that should NOT be granted (space-separated) | - |
| `check-access-resources` | Resources to check with check-access-not-granted | - |
| `check-no-new-access` | Path to baseline policy for new access comparison | - |
| `check-no-public-access` | Check that resource policies don't allow public access | `false` |
| `public-access-resource-type` | Resource type(s) for public access check | `AWS::S3::Bucket` |

## Action Outputs

| Output | Description |
|--------|-------------|
| `validation-result` | Validation result (`success` or `failure`) |
| `total-policies` | Total number of policies validated |
| `valid-policies` | Number of valid policies |
| `invalid-policies` | Number of invalid policies |
| `total-issues` | Total number of issues found |

---

## Examples

### Basic Validation with PR Comments

```yaml
name: IAM Policy Validation

on:
  pull_request:
    paths:
      - "policies/**"
      - "terraform/**/*.json"

permissions:
  contents: read
  pull-requests: write

jobs:
  validate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Validate IAM Policies
        uses: boogy/iam-policy-validator@v1
        with:
          path: ./policies/
          config-file: ./iam-validator.yaml
          post-comment: true
          create-review: true
          github-summary: true
```

### GitHub Code Scanning with SARIF

Upload results to GitHub's Security tab for centralized vulnerability tracking:

```yaml
name: IAM Policy Security Scan

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

permissions:
  contents: read
  security-events: write  # Required for SARIF upload

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Validate IAM Policies
        uses: boogy/iam-policy-validator@v1
        with:
          path: ./policies/
          format: sarif
          output-file: iam-results.sarif
          upload-sarif: true
```

Results appear in your repository's **Security > Code scanning alerts** tab.

### AWS Access Analyzer Integration

Use AWS IAM Access Analyzer for additional validation (requires AWS credentials):

```yaml
name: IAM Policy Analysis

on:
  pull_request:
    paths:
      - "policies/**"

permissions:
  contents: read
  pull-requests: write
  id-token: write  # For OIDC authentication

jobs:
  analyze:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Configure AWS Credentials
        uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: arn:aws:iam::123456789012:role/GitHubActionsRole
          aws-region: us-east-1

      - name: Analyze with Access Analyzer
        uses: boogy/iam-policy-validator@v1
        with:
          path: ./policies/
          use-access-analyzer: true
          access-analyzer-region: us-east-1
          run-all-checks: true  # Also run built-in checks
```

### Check for Prohibited Actions

Ensure specific dangerous actions are never granted:

```yaml
- uses: boogy/iam-policy-validator@v1
  with:
    path: ./policies/
    use-access-analyzer: true
    check-access-not-granted: >-
      iam:CreateAccessKey
      iam:CreateUser
      iam:AttachUserPolicy
      s3:DeleteBucket
      kms:ScheduleKeyDeletion
    check-access-resources: >-
      arn:aws:iam::*:user/*
      arn:aws:s3:::prod-*
      arn:aws:kms:*:*:key/*
```

### Check for Public Access (Resource Policies)

Validate S3 bucket policies don't allow public access:

```yaml
- uses: boogy/iam-policy-validator@v1
  with:
    path: ./bucket-policies/
    policy-type: RESOURCE_POLICY
    use-access-analyzer: true
    check-no-public-access: true
    public-access-resource-type: AWS::S3::Bucket AWS::Lambda::Function
```

### Multiple Policy Paths

Validate policies from different directories:

```yaml
- uses: boogy/iam-policy-validator@v1
  with:
    path: |
      ./iam-policies/
      ./terraform/modules/iam/
      ./cloudformation/policies/
```

### Different Policy Types (Matrix Strategy)

Validate different policy types in parallel:

```yaml
name: Validate All Policy Types

on: [pull_request]

jobs:
  validate:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      pull-requests: write
    strategy:
      matrix:
        include:
          - path: ./identity-policies/
            type: IDENTITY_POLICY
          - path: ./trust-policies/
            type: TRUST_POLICY
          - path: ./resource-policies/
            type: RESOURCE_POLICY
          - path: ./scps/
            type: SERVICE_CONTROL_POLICY
    steps:
      - uses: actions/checkout@v4
      - uses: boogy/iam-policy-validator@v1
        with:
          path: ${{ matrix.path }}
          policy-type: ${{ matrix.type }}
```

### Large Repositories (Streaming Mode)

For repositories with many policy files, use streaming mode to reduce memory usage:

```yaml
- uses: boogy/iam-policy-validator@v1
  with:
    path: ./policies/
    stream: true
    batch-size: 20  # Process 20 policies at a time
```

### Custom Checks

Use organization-specific validation rules:

```yaml
- uses: boogy/iam-policy-validator@v1
  with:
    path: ./policies/
    custom-checks-dir: ./custom-checks/
    config-file: ./iam-validator.yaml
```

### Offline Mode (Air-Gapped Environments)

Pre-download AWS service definitions for environments without internet access:

```yaml
# First, generate the service definitions (run once, commit to repo)
# iam-validator download-services --output-dir ./aws-services/

- uses: boogy/iam-policy-validator@v1
  with:
    path: ./policies/
    aws-services-dir: ./aws-services/
```

### Using Outputs in Workflow

Access validation results for conditional logic:

```yaml
jobs:
  validate:
    runs-on: ubuntu-latest
    outputs:
      result: ${{ steps.validate.outputs.validation-result }}
      issues: ${{ steps.validate.outputs.total-issues }}
    steps:
      - uses: actions/checkout@v4
      - id: validate
        uses: boogy/iam-policy-validator@v1
        with:
          path: ./policies/

  notify:
    needs: validate
    if: needs.validate.outputs.result == 'failure'
    runs-on: ubuntu-latest
    steps:
      - name: Send Slack notification
        run: |
          echo "Validation failed with ${{ needs.validate.outputs.issues }} issues"
          # Add your notification logic here
```

### Fail on Specific Severities

Configure which severity levels cause the workflow to fail:

```yaml
# Fail on errors and critical issues only (default)
- uses: boogy/iam-policy-validator@v1
  with:
    path: ./policies/

# Fail on warnings too
- uses: boogy/iam-policy-validator@v1
  with:
    path: ./policies/
    fail-on-warnings: true
```

### Multiple Output Formats

Generate reports in multiple formats:

```yaml
- uses: boogy/iam-policy-validator@v1
  with:
    path: ./policies/
    format: json
    output-file: validation-report.json
    github-summary: true

- name: Upload Report
  uses: actions/upload-artifact@v4
  with:
    name: iam-validation-report
    path: validation-report.json
```

---

## PR Comments and Reviews

### Inline Review Comments

When `create-review: true`, the action creates line-specific comments on the exact locations where issues are found in the PR diff.

### Summary Comment

A summary comment is posted showing:

- Total policies validated
- Issues grouped by severity
- Links to specific findings

### CODEOWNERS Ignore

When `allow-owner-ignore: true`, code owners can reply "ignore" to dismiss specific findings. This is useful for acknowledged exceptions.

---

## Job Summary

Enable `github-summary: true` to add a summary to the Actions UI:

```yaml
- uses: boogy/iam-policy-validator@v1
  with:
    path: ./policies/
    github-summary: true
    summary: true
    severity-breakdown: true
```

The summary shows:

- Validation status (pass/fail)
- Total policies validated
- Issue counts by severity
- Executive summary (with `summary: true`)
- Severity breakdown chart (with `severity-breakdown: true`)

---

## Complete Production Example

A comprehensive workflow for production use:

```yaml
name: IAM Policy Validation

on:
  pull_request:
    paths:
      - "policies/**"
      - "terraform/**/*.json"
      - "iam-validator.yaml"
  push:
    branches: [main]
    paths:
      - "policies/**"

permissions:
  contents: read
  pull-requests: write
  security-events: write  # Required for SARIF upload

jobs:
  validate:
    name: Validate IAM Policies
    runs-on: ubuntu-latest
    steps:
      - name: Checkout
        uses: actions/checkout@v4

      - name: Validate Policies
        uses: boogy/iam-policy-validator@v1
        with:
          path: |
            ./policies/
            ./terraform/iam/
          config-file: ./iam-validator.yaml
          policy-type: IDENTITY_POLICY
          post-comment: true
          create-review: true
          github-summary: true
          summary: true
          severity-breakdown: true
          format: sarif
          output-file: iam-results.sarif
          upload-sarif: true  # Uploads to GitHub Code Scanning
```

---

## Troubleshooting

### PR Comments Not Appearing

Ensure you have the correct permissions:

```yaml
permissions:
  contents: read
  pull-requests: write
```

### SARIF Upload Failing

Ensure you have security-events write permission:

```yaml
permissions:
  security-events: write
```

### Rate Limiting with Large Repos

Use streaming mode and increase batch size:

```yaml
- uses: boogy/iam-policy-validator@v1
  with:
    path: ./policies/
    stream: true
    batch-size: 50
```

### AWS Access Analyzer Permissions

Ensure your IAM role has:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "access-analyzer:ValidatePolicy",
        "access-analyzer:CheckAccessNotGranted",
        "access-analyzer:CheckNoNewAccess",
        "access-analyzer:CheckNoPublicAccess"
      ],
      "Resource": "*"
    }
  ]
}
```
