---
title: Quick Start
description: Validate your first IAM policy in seconds
---

# Quick Start

Validate your first IAM policy in under a minute.

## Create a Test Policy

Create a file called `policy.json`:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::my-bucket/*"
    }
  ]
}
```

## Run Validation

```bash
iam-validator validate --path policy.json
```

**Output:**

```
✅ [1/1] policy.json • VALID
   0 issues found
```

## Test with a Problematic Policy

Create `bad-policy.json` with common issues:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "TooPermissive",
      "Effect": "Allow",
      "Action": "*",
      "Resource": "*"
    },
    {
      "Sid": "Typo",
      "Effect": "Allow",
      "Action": "s3:GetObjekt",
      "Resource": "arn:aws:s3:::bucket/*"
    }
  ]
}
```

Run validation:

```bash
iam-validator validate --path bad-policy.json --format enhanced
```

**Output:**

```
❌ [1/1] bad-policy.json • INVALID

Issues (2)
├── 🔴 Critical
│   └── [Statement: TooPermissive] full_wildcard
│       └── Statement allows all actions (*) on all resources (*)
│           └── 💡 Replace wildcards with specific actions and resources
│
└── ❌ Error
    └── [Statement: Typo] invalid_action
        └── Invalid action: `s3:GetObjekt`
            └── 💡 Did you mean: s3:GetObject?
```

## Validate a Directory

Validate all policies in a directory:

```bash
iam-validator validate --path ./policies/ --format enhanced
```

## Output Formats

Choose your preferred output format:

```bash
# Rich console output (default)
iam-validator validate --path policy.json

# Enhanced output with colors
iam-validator validate --path policy.json --format enhanced

# JSON for automation
iam-validator validate --path policy.json --format json

# SARIF for security tools
iam-validator validate --path policy.json --format sarif

# Markdown for documentation
iam-validator validate --path policy.json --format markdown
```

## Exit Codes

| Code | Meaning                      |
| ---- | ---------------------------- |
| 0    | All policies valid           |
| 1    | Validation errors found      |
| 2    | Configuration or input error |

Use exit codes in scripts:

```bash
if iam-validator validate --path policy.json; then
    echo "Policy is valid"
else
    echo "Policy has issues"
fi
```

## Next Steps

- [:octicons-arrow-right-24: First Validation Tutorial](first-validation.md) — Detailed walkthrough
- [:octicons-arrow-right-24: Configuration](../user-guide/configuration.md) — Customize validation rules
- [:octicons-arrow-right-24: GitHub Actions](../integrations/github-actions.md) — CI/CD integration
