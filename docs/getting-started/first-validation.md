---
title: First Validation Tutorial
description: Step-by-step guide to understanding IAM policy validation
---

# First Validation Tutorial

This tutorial walks you through validating IAM policies step by step, explaining what each check does and why it matters.

## What You'll Learn

- How validation checks work
- Understanding error messages
- Fixing common issues
- Creating a configuration file

## Setup

Ensure you have IAM Policy Validator installed:

```bash
pip install iam-policy-validator
iam-validator --version
```

## Step 1: Create Sample Policies

Create a directory for this tutorial:

```bash
mkdir iam-tutorial
cd iam-tutorial
```

### Policy 1: User Access Policy

Create `user-policy.json`:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "S3ReadAccess",
      "Effect": "Allow",
      "Action": ["s3:GetObject", "s3:ListBucket"],
      "Resource": ["arn:aws:s3:::my-bucket", "arn:aws:s3:::my-bucket/*"]
    },
    {
      "Sid": "PassRoleToLambda",
      "Effect": "Allow",
      "Action": "iam:PassRole",
      "Resource": "arn:aws:iam::123456789012:role/lambda-execution-role"
    }
  ]
}
```

### Policy 2: Admin Policy (Problematic)

Create `admin-policy.json`:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "FullAdmin",
      "Effect": "Allow",
      "Action": "*",
      "Resource": "*"
    }
  ]
}
```

## Step 2: Run Basic Validation

Validate the user policy:

```bash
iam-validator validate --path user-policy.json --format enhanced
```

**Expected Output:**

```
❌ [1/1] user-policy.json • INVALID

Issues (1)
└── 🔴 High
    └── [Statement: PassRoleToLambda @L14] missing_required_condition
        └── Action `iam:PassRole` requires condition `iam:PassedToService`
            └── 💡 Restrict which AWS services can assume the passed role
```

### Understanding the Issue

The `iam:PassRole` action is flagged because:

1. **What it does**: Allows passing an IAM role to AWS services
2. **Why it's risky**: Without conditions, any service could use this role
3. **The fix**: Add `iam:PassedToService` condition to restrict which services can use the role

## Step 3: Fix the Policy

Update `user-policy.json` to add the required condition:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "S3ReadAccess",
      "Effect": "Allow",
      "Action": ["s3:GetObject", "s3:ListBucket"],
      "Resource": ["arn:aws:s3:::my-bucket", "arn:aws:s3:::my-bucket/*"]
    },
    {
      "Sid": "PassRoleToLambda",
      "Effect": "Allow",
      "Action": "iam:PassRole",
      "Resource": "arn:aws:iam::123456789012:role/lambda-execution-role",
      "Condition": {
        "StringEquals": {
          "iam:PassedToService": "lambda.amazonaws.com"
        }
      }
    }
  ]
}
```

Re-run validation:

```bash
iam-validator validate --path user-policy.json --format enhanced
```

**Expected Output:**

```
✅ [1/1] user-policy.json • VALID
   0 issues found
```

## Step 4: Validate the Admin Policy

Now check the admin policy:

```bash
iam-validator validate --path admin-policy.json --format enhanced
```

**Expected Output:**

```
❌ [1/1] admin-policy.json • INVALID

Issues (1)
└── 🔴 Critical
    └── [Statement: FullAdmin @L4] full_wildcard
        └── Statement allows all actions (*) on all resources (*)
            └── 💡 Replace wildcards with specific actions and resources needed
```

### Why This is Critical

The `Action: "*"` with `Resource: "*"` combination:

- Grants **full administrator access** to the entire AWS account
- Equivalent to `AdministratorAccess` managed policy
- Should almost never be in custom policies
- Violates least-privilege principle

## Step 5: Validate Multiple Policies

Validate all policies at once:

```bash
iam-validator validate --path . --format enhanced
```

This validates all `.json` files in the current directory.

## Step 6: Create a Configuration File

Create `iam-validator.yaml` to customize validation:

```yaml
# Fail on critical and high severity issues
settings:
  fail_on_severity: [error, critical, high]

# Customize check behavior
full_wildcard:
  severity: critical

sensitive_action:
  severity: high

# Require conditions for specific actions
action_condition_enforcement:
  enabled: true
  action_condition_requirements:
    - actions: ["iam:PassRole"]
      required_conditions:
        - condition_key: "iam:PassedToService"
          description: "Restrict which services can assume the role"
```

Run with configuration:

```bash
iam-validator validate --path . --config iam-validator.yaml --format enhanced
```

## Step 7: Output as JSON

For CI/CD pipelines, output as JSON:

```bash
iam-validator validate --path user-policy.json --format json
```

**Output:**

```json
{
  "summary": {
    "total_policies": 1,
    "valid_policies": 1,
    "invalid_policies": 0,
    "total_issues": 0
  },
  "results": [
    {
      "file": "user-policy.json",
      "is_valid": true,
      "issues": []
    }
  ]
}
```

## Understanding Severity Levels

| Severity     | Meaning                 | Action           |
| ------------ | ----------------------- | ---------------- |
| **Critical** | Severe security risk    | Block deployment |
| **High**     | Security concern        | Fix before merge |
| **Medium**   | Best practice violation | Address soon     |
| **Low**      | Minor improvement       | Optional fix     |
| **Error**    | AWS will reject         | Must fix         |
| **Warning**  | Potential issue         | Review           |

## What's Next?

Now that you understand the basics:

- [:octicons-arrow-right-24: Configuration Guide](../user-guide/configuration.md) — Advanced configuration options
- [:octicons-arrow-right-24: Check Reference](../user-guide/checks/index.md) — All 19 built-in checks explained
- [:octicons-arrow-right-24: GitHub Actions](../integrations/github-actions.md) — Automate validation in CI/CD
- [:octicons-arrow-right-24: Custom Checks](../developer-guide/custom-checks/index.md) — Write organization-specific rules
