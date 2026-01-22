---
title: GitHub Actions
description: Integrate IAM Policy Validator with GitHub Actions
---

# GitHub Actions Integration

IAM Policy Validator provides a native GitHub Action for seamless CI/CD integration.

## Quick Start

```yaml
name: Validate IAM Policies

on:
  pull_request:
    paths:
      - '**.json'
      - '**.yaml'

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
          fail-on-severity: error,critical,high
```

## Action Inputs

| Input              | Description           | Default               |
| ------------------ | --------------------- | --------------------- |
| `path`             | Path to validate      | `.`                   |
| `config`           | Config file path      | Auto-detect           |
| `policy-type`      | Policy type           | `IDENTITY_POLICY`     |
| `fail-on-severity` | Severities that fail  | `error,critical`      |
| `github-token`     | Token for PR comments | `${{ github.token }}` |
| `post-to-pr`       | Post comments to PR   | `true`                |
| `github-summary`   | Add job summary       | `true`                |

## Complete Example

```yaml
name: IAM Policy Validation

on:
  pull_request:
    paths:
      - 'policies/**'
      - 'terraform/**/*.json'

permissions:
  contents: read
  pull-requests: write

jobs:
  validate-policies:
    runs-on: ubuntu-latest
    steps:
      # actions/checkout v6.0.1
      - name: Checkout
        uses: actions/checkout@8e8c483db84b4bee98b60c0593521ed34d9990e8

      - name: Validate IAM Policies
        uses: boogy/iam-policy-validator@v1
        with:
          path: ./policies/
          config: ./iam-validator.yaml
          fail-on-severity: error,critical,high
          post-to-pr: true
          github-summary: true
```

## PR Comments

The action posts inline comments on policy issues:

- Comments appear on the specific lines with issues
- Summary comment shows all findings
- Comments update on subsequent pushes (no duplicates)

## Job Summary

Enable `github-summary: true` to add a summary to the Actions UI showing:

- Total policies validated
- Pass/fail status
- Issue breakdown by severity

## Trust Policy Validation

```yaml
- uses: boogy/iam-policy-validator@v1
  with:
    path: ./trust-policies/
    policy-type: TRUST_POLICY
```

## Resource Policy Validation

```yaml
- uses: boogy/iam-policy-validator@v1
  with:
    path: ./bucket-policies/
    policy-type: RESOURCE_POLICY
```

## Multiple Policy Types

```yaml
jobs:
  validate-identity:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: boogy/iam-policy-validator@v1
        with:
          path: ./identity-policies/
          policy-type: IDENTITY_POLICY

  validate-trust:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: boogy/iam-policy-validator@v1
        with:
          path: ./trust-policies/
          policy-type: TRUST_POLICY
```
