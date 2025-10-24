# GitHub Action Usage Examples

This document provides examples of how to use the IAM Policy Validator GitHub Action with various configurations.

## Table of Contents
- [Basic Usage](#basic-usage)
- [Advanced Features](#advanced-features)
- [AWS Access Analyzer Integration](#aws-access-analyzer-integration)
- [Output Formats and Artifacts](#output-formats-and-artifacts)
- [Custom Configuration](#custom-configuration)
- [Multi-Step Workflows](#multi-step-workflows)

## Basic Usage

### Simple Validation

```yaml
name: Validate IAM Policies

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
      - uses: actions/checkout@v4

      - name: Validate IAM Policies
        uses: ./  # or your-org/iam-policy-auditor@v1
        with:
          path: policies/
```

### Fail on Warnings

```yaml
- name: Strict Validation
  uses: ./
  with:
    path: policies/
    fail-on-warnings: true
```

### Non-Recursive Validation

```yaml
- name: Validate Root Directory Only
  uses: ./
  with:
    path: policies/
    recursive: false
```

## Advanced Features

### Disable GitHub Comments

```yaml
- name: Validate Without PR Comments
  uses: ./
  with:
    path: policies/
    post-comment: false
```

### Comment Without Line-Specific Reviews

```yaml
- name: Summary Comment Only
  uses: ./
  with:
    path: policies/
    post-comment: true
    create-review: false
```

## AWS Access Analyzer Integration

### Basic Access Analyzer Validation

```yaml
name: AWS Access Analyzer Validation

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
      - uses: actions/checkout@v4

      - name: Configure AWS Credentials
        uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: arn:aws:iam::123456789012:role/GitHubActionsRole
          aws-region: us-east-1

      - name: Validate with Access Analyzer
        uses: ./
        with:
          path: policies/
          use-access-analyzer: true
```

### Sequential Validation (Access Analyzer + Custom Checks)

```yaml
- name: Sequential Validation
  uses: ./
  with:
    path: policies/
    use-access-analyzer: true
    run-all-checks: true
    post-comment: true
    create-review: true
```

### Resource Policy Validation

```yaml
- name: Validate S3 Bucket Policies
  uses: ./
  with:
    path: bucket-policies/
    use-access-analyzer: true
    policy-type: RESOURCE_POLICY
    access-analyzer-region: us-west-2
```

### Service Control Policy Validation

```yaml
- name: Validate SCPs
  uses: ./
  with:
    path: organization/scps/
    use-access-analyzer: true
    policy-type: SERVICE_CONTROL_POLICY
```

## Output Formats and Artifacts

### Generate JSON Report

```yaml
- name: Validate and Generate JSON Report
  uses: ./
  with:
    path: policies/
    format: json
    output-file: reports/validation-report.json
```

### Generate SARIF for Code Scanning

```yaml
- name: Validate and Upload to Code Scanning
  uses: ./
  with:
    path: policies/
    format: sarif
    output-file: results.sarif

- name: Upload SARIF to GitHub
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

### Generate HTML Report

```yaml
- name: Generate HTML Report
  uses: ./
  with:
    path: policies/
    format: html
    output-file: reports/validation.html

# The report is automatically uploaded as an artifact
# Download it from the Actions tab
```

### Generate Multiple Formats

```yaml
jobs:
  validate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Validate (Console)
        uses: ./
        with:
          path: policies/
          post-comment: true

      - name: Generate JSON Report
        uses: ./
        with:
          path: policies/
          format: json
          output-file: report.json
          post-comment: false

      - name: Generate HTML Report
        uses: ./
        with:
          path: policies/
          format: html
          output-file: report.html
          post-comment: false
```

## Custom Configuration

### Using Configuration File

Create `iam-validator.yaml`:
```yaml
checks:
  action_validation:
    enabled: true
    severity: error

  condition_key_validation:
    enabled: true
    severity: warning

  action_condition_enforcement:
    enabled: true
    severity: error
    config:
      action_condition_requirements:
        - actions: ["s3:GetObject"]
          required_conditions:
            all_of:
              - condition_key: "aws:SecureTransport"
                expected_value: true
```

Then use it:
```yaml
- name: Validate with Custom Config
  uses: ./
  with:
    path: policies/
    config-file: iam-validator.yaml
```

## Multi-Step Workflows

### Using Outputs in Subsequent Steps

```yaml
jobs:
  validate:
    runs-on: ubuntu-latest
    outputs:
      validation-result: ${{ steps.validate.outputs.validation-result }}
      total-issues: ${{ steps.validate.outputs.total-issues }}

    steps:
      - uses: actions/checkout@v4

      - name: Validate Policies
        id: validate
        uses: ./
        with:
          path: policies/

      - name: Check Results
        if: steps.validate.outputs.total-issues > 0
        run: |
          echo "Found ${{ steps.validate.outputs.total-issues }} issues"
          echo "Valid: ${{ steps.validate.outputs.valid-policies }}"
          echo "Invalid: ${{ steps.validate.outputs.invalid-policies }}"

  deploy:
    needs: validate
    if: needs.validate.outputs.validation-result == 'success'
    runs-on: ubuntu-latest
    steps:
      - name: Deploy Policies
        run: echo "Deploying policies..."
```

### Download and Analyze Report

```yaml
jobs:
  validate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Validate
        uses: ./
        with:
          path: policies/
          format: json
          output-file: validation-report.json

  analyze:
    needs: validate
    runs-on: ubuntu-latest
    steps:
      - name: Download Report
        uses: actions/download-artifact@v4
        with:
          name: iam-policy-validation-report

      - name: Analyze Report
        run: |
          # Custom processing of JSON report
          cat validation-report.json | jq '.total_issues'
```

### Matrix Strategy for Multiple Environments

```yaml
jobs:
  validate:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        environment: [dev, staging, prod]
        include:
          - environment: dev
            fail-on-warnings: false
          - environment: staging
            fail-on-warnings: false
          - environment: prod
            fail-on-warnings: true

    steps:
      - uses: actions/checkout@v4

      - name: Validate ${{ matrix.environment }} Policies
        uses: ./
        with:
          path: policies/${{ matrix.environment }}/
          fail-on-warnings: ${{ matrix.fail-on-warnings }}
          output-file: report-${{ matrix.environment }}.json
```

## Complete Example: Production-Ready Workflow

```yaml
name: IAM Policy Validation (Production)

on:
  pull_request:
    paths:
      - 'policies/**/*.json'
      - 'policies/**/*.yaml'
  push:
    branches: [main]

jobs:
  validate-custom:
    name: Custom Validation
    runs-on: ubuntu-latest
    permissions:
      contents: read
      pull-requests: write

    steps:
      - name: Checkout
        uses: actions/checkout@v4

      - name: Validate with Custom Checks
        uses: ./
        with:
          path: policies/
          config-file: .github/iam-validator.yaml
          fail-on-warnings: false
          post-comment: true
          create-review: true
          format: json
          output-file: custom-validation.json

  validate-aws:
    name: AWS Access Analyzer
    runs-on: ubuntu-latest
    permissions:
      contents: read
      pull-requests: write
      id-token: write

    steps:
      - name: Checkout
        uses: actions/checkout@v4

      - name: Configure AWS Credentials
        uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: ${{ secrets.AWS_ROLE_ARN }}
          aws-region: us-east-1

      - name: Validate with Access Analyzer
        uses: ./
        with:
          path: policies/
          use-access-analyzer: true
          policy-type: IDENTITY_POLICY
          fail-on-warnings: true
          post-comment: true
          format: sarif
          output-file: analyzer-results.sarif

      - name: Upload to Code Scanning
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: analyzer-results.sarif
          category: iam-policy-analyzer

  security-check:
    name: Security Best Practices
    runs-on: ubuntu-latest
    permissions:
      contents: read
      pull-requests: write

    steps:
      - name: Checkout
        uses: actions/checkout@v4

      - name: Security Validation
        uses: ./
        with:
          path: policies/
          fail-on-warnings: true
          post-comment: true
          create-review: true
          format: html
          output-file: security-report.html
```

## Tips and Best Practices

1. **Use dependency caching**: The action automatically caches `uv` dependencies for faster runs

2. **Separate validation jobs**: Run Access Analyzer and custom checks as separate jobs for clarity

3. **Generate reports**: Always generate JSON/HTML reports for audit trails

4. **Use matrix strategies**: Validate different environments with different strictness levels

5. **Leverage outputs**: Use action outputs to control downstream jobs

6. **Configure permissions**: Only grant the minimum required permissions

7. **Use SARIF format**: For GitHub Code Scanning integration

8. **Customize configuration**: Use configuration files for complex validation rules
