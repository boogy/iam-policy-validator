---
title: Pre-commit
description: Validate IAM policies before committing
---

# Pre-commit Integration

Use IAM Policy Validator as a pre-commit hook to catch issues before they're committed.

## Setup

### 1. Install pre-commit

```bash
pip install pre-commit
```

### 2. Create Configuration

Add to `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: local
    hooks:
      - id: iam-policy-validator
        name: Validate IAM Policies
        entry: iam-validator validate --path
        language: system
        files: \.(json|yaml)$
        pass_filenames: true
        types: [file]
```

### 3. Install Hook

```bash
pre-commit install
```

## Configuration Options

### Validate Specific Directories

```yaml
repos:
  - repo: local
    hooks:
      - id: iam-policy-validator
        name: Validate IAM Policies
        entry: iam-validator validate
        language: system
        args: ["--path", "policies/", "--config", "iam-validator.yaml"]
        files: ^policies/.*\.(json|yaml)$
        pass_filenames: false
```

### With Custom Severity

```yaml
repos:
  - repo: local
    hooks:
      - id: iam-policy-validator
        name: Validate IAM Policies
        entry: iam-validator validate --path
        language: system
        args: ["--fail-on-warnings"]
        files: \.(json|yaml)$
```

## Using Python Entry Point

For environments without `iam-validator` in PATH:

```yaml
repos:
  - repo: local
    hooks:
      - id: iam-policy-validator
        name: Validate IAM Policies
        entry: python -m iam_validator.core.cli validate --path
        language: python
        additional_dependencies: ["iam-policy-validator"]
        files: \.(json|yaml)$
```

## Run Manually

```bash
# Run on all files
pre-commit run iam-policy-validator --all-files

# Run on staged files
pre-commit run iam-policy-validator
```

## Skip Hook Temporarily

```bash
git commit --no-verify -m "WIP: skip validation"
```

!!! warning
Only skip validation for work-in-progress commits. Always validate before merging.
