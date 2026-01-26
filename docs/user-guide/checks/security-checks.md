---
title: Security Checks
description: Detect security risks and best practice violations
---

# Security Checks

These checks identify security risks and violations of AWS IAM best practices.

## full_wildcard

Detects the most dangerous pattern: `Action: "*"` with `Resource: "*"`.

**Severity:** `critical`

### Why It's Critical

This grants **full administrator access** to the entire AWS account, equivalent to the `AdministratorAccess` managed policy.

### Fail Example

```json
{
  "Effect": "Allow",
  "Action": "*",
  "Resource": "*"
}
```

### How to Fix

Replace with specific actions and resources:

```json
{
  "Effect": "Allow",
  "Action": ["s3:GetObject", "s3:PutObject"],
  "Resource": "arn:aws:s3:::my-bucket/*"
}
```

---

## wildcard_action

Detects `Action: "*"` without specifying which service.

**Severity:** `medium`

### Fail Example

```json
{
  "Effect": "Allow",
  "Action": "*",
  "Resource": "arn:aws:s3:::bucket/*"
}
```

### How to Fix

Specify the actions needed:

```json
{
  "Effect": "Allow",
  "Action": ["s3:GetObject", "s3:ListBucket"],
  "Resource": "arn:aws:s3:::bucket/*"
}
```

---

## wildcard_resource

Detects `Resource: "*"` (access to all resources).

**Severity:** `medium` (may be lowered to `low` with resource-scoping conditions)

### When It's Acceptable

Some actions require `Resource: "*"`:

- `s3:ListAllMyBuckets`
- `iam:GetAccountSummary`
- Many `Describe*` and `List*` actions

### Condition-Aware Severity

This check intelligently adjusts severity based on conditions that restrict resource scope:

#### Global Resource-Scoping Conditions (Always Lower Severity)

These conditions are always valid for all services and directly constrain which resources can be accessed:

| Condition Key          | Effect                              | Severity |
| ---------------------- | ----------------------------------- | -------- |
| `aws:ResourceAccount`  | Limits to specific AWS account(s)   | `low`    |
| `aws:ResourceOrgID`    | Limits to specific AWS Organization | `low`    |
| `aws:ResourceOrgPaths` | Limits to specific OU paths         | `low`    |

**Example (severity = low):**

```json
{
  "Effect": "Allow",
  "Action": ["s3:GetObject", "s3:PutObject"],
  "Resource": "*",
  "Condition": {
    "StringEquals": {
      "aws:ResourceAccount": "${aws:PrincipalAccount}"
    }
  }
}
```

#### Resource Tag Conditions (Conditional)

`aws:ResourceTag/*` conditions lower severity **only if ALL actions** in the statement support the condition. Support is validated against AWS service definitions.

**Example - SSM with tag support (severity = low):**

```json
{
  "Effect": "Allow",
  "Action": ["ssm:StartSession", "ssm:GetConnectionStatus"],
  "Resource": "*",
  "Condition": {
    "StringEquals": {
      "aws:ResourceTag/Component": "bastion"
    }
  }
}
```

**Example - Mixed actions, partial support (severity = medium):**

```json
{
  "Effect": "Allow",
  "Action": ["s3:GetObject", "route53:ChangeResourceRecordSets"],
  "Resource": "*",
  "Condition": {
    "StringEquals": {
      "aws:ResourceTag/Env": "prod"
    }
  }
}
```

In this case, `s3:GetObject` supports `aws:ResourceTag` but `route53:ChangeResourceRecordSets` does not, so the severity remains `medium`.

### How to Fix

Restrict to specific resources:

```json
{
  "Effect": "Allow",
  "Action": "s3:GetObject",
  "Resource": "arn:aws:s3:::specific-bucket/*"
}
```

Or use resource-scoping conditions:

```json
{
  "Effect": "Allow",
  "Action": "s3:GetObject",
  "Resource": "*",
  "Condition": {
    "StringEquals": {
      "aws:ResourceAccount": "123456789012"
    }
  }
}
```

---

## service_wildcard

Detects service-level wildcards like `s3:*` or `iam:*`.

**Severity:** `high`

### Fail Example

```json
{
  "Effect": "Allow",
  "Action": "s3:*",
  "Resource": "*"
}
```

### How to Fix

Use specific actions or action patterns:

```json
{
  "Effect": "Allow",
  "Action": ["s3:Get*", "s3:List*"],
  "Resource": "*"
}
```

---

## sensitive_action

Detects 490+ privilege escalation actions that should have conditions.

**Severity:** `medium`

### Sensitive Action Categories

- **IAM Management:** `iam:CreateUser`, `iam:AttachRolePolicy`, `iam:PassRole`
- **Security Controls:** `iam:DeletePolicy`, `kms:DisableKey`
- **Data Access:** `s3:DeleteBucket`, `rds:DeleteDBInstance`

### Fail Example

```json
{
  "Effect": "Allow",
  "Action": "iam:PassRole",
  "Resource": "*"
}
```

### How to Fix

Add conditions to restrict usage:

```json
{
  "Effect": "Allow",
  "Action": "iam:PassRole",
  "Resource": "arn:aws:iam::*:role/lambda-*",
  "Condition": {
    "StringEquals": {
      "iam:PassedToService": "lambda.amazonaws.com"
    }
  }
}
```

---

## principal_validation

Validates Principal elements in resource policies and trust policies.

**Severity:** `high` (varies by issue type)

### What It Checks

- **Service Principal Wildcards** (`critical`): Detects dangerous `{"Service": "*"}` patterns
- **Wildcard Principals** (configurable): Detects `Principal: "*"` or `{"AWS": "*"}`
- **Blocked Principals**: Validates against configurable blocked list
- **Allowed Principals**: Enforces whitelist when configured
- **Principal Condition Requirements**: Requires specific conditions for certain principals
- **Service Principal Format**: Validates AWS service principal format

### Service Principal Wildcards (Critical)

The most dangerous pattern is `{"Service": "*"}` in trust policies, which allows **any AWS service** to assume a role.

```json
{
  "Effect": "Allow",
  "Principal": { "Service": "*" },
  "Action": "sts:AssumeRole"
}
```

This is flagged as **critical** because it creates an extremely permissive trust relationship. Any AWS service - including services you don't control - could potentially assume this role.

**Note:** `NotPrincipal: {"Service": "*"}` is NOT flagged because it means "everyone EXCEPT all services", which is an exclusion, not an overly permissive grant.

### Wildcard Principal Handling

The check supports two modes for handling `Principal: "*"`:

1. **Default mode** (`block_wildcard_principal: false`): Allows `*` if appropriate conditions are present (configured via `principal_condition_requirements`)
2. **Strict mode** (`block_wildcard_principal: true`): Blocks `*` entirely, regardless of conditions

#### When Wildcard with Conditions is Valid

Some use cases legitimately require `Principal: "*"` with conditions:

- **S3 bucket policies** with `aws:SourceArn` and `aws:SourceAccount`
- **SNS topic policies** for cross-account subscriptions
- **Trust policies** with `sts:ExternalId` for confused deputy protection

```json
{
  "Effect": "Allow",
  "Principal": "*",
  "Action": "s3:GetObject",
  "Resource": "arn:aws:s3:::bucket/*",
  "Condition": {
    "StringEquals": {
      "aws:SourceAccount": "123456789012"
    },
    "ArnLike": {
      "aws:SourceArn": "arn:aws:s3:::source-bucket"
    }
  }
}
```

### Configuration Options

```yaml
principal_validation:
  enabled: true

  # Strict mode: block * entirely (default: false)
  block_wildcard_principal: false

  # Block {"Service": "*"} patterns (default: true)
  block_service_principal_wildcard: true

  # Explicit block list
  blocked_principals:
    - "arn:aws:iam::*:root"

  # Whitelist mode (when set, only these are allowed)
  allowed_principals:
    - "arn:aws:iam::123456789012:*"

  # Condition requirements for specific principals
  principal_condition_requirements:
    - principals: ["*"]
      required_conditions:
        any_of:
          - condition_key: "aws:SourceArn"
          - condition_key: "aws:SourceAccount"
```

### Fail Examples

**Critical - Service Principal Wildcard:**

```json
{
  "Effect": "Allow",
  "Principal": { "Service": "*" },
  "Action": "sts:AssumeRole"
}
```

**High - Wildcard without conditions (strict mode):**

```json
{
  "Effect": "Allow",
  "Principal": "*",
  "Action": "s3:GetObject",
  "Resource": "arn:aws:s3:::bucket/*"
}
```

**Medium - Missing required conditions (default mode):**

```json
{
  "Effect": "Allow",
  "Principal": "*",
  "Action": "s3:GetObject",
  "Resource": "arn:aws:s3:::bucket/*"
}
```

### How to Fix

**For service principal wildcards - specify the service:**

```json
{
  "Effect": "Allow",
  "Principal": { "Service": "lambda.amazonaws.com" },
  "Action": "sts:AssumeRole"
}
```

**For wildcard principals - add conditions or specify principal:**

```json
{
  "Effect": "Allow",
  "Principal": {
    "AWS": "arn:aws:iam::123456789012:root"
  },
  "Action": "s3:GetObject",
  "Resource": "arn:aws:s3:::bucket/*",
  "Condition": {
    "StringEquals": {
      "aws:SourceAccount": "123456789012"
    }
  }
}
```

---

## mfa_condition_check

Detects MFA condition anti-patterns that may not work as expected.

**Severity:** `warning`

### Common Anti-Patterns

- `aws:MultiFactorAuthPresent` in Deny with `BoolIfExists`
- Missing MFA check with `StringEquals` instead of `Bool`

---

## not_action_not_resource

Detects dangerous NotAction/NotResource patterns that can grant overly broad permissions.

**Severity:** `high`

### Why It's Dangerous

NotAction and NotResource grant permissions by **exclusion** rather than explicit inclusion. This means:

- `NotAction` with `Allow` grants **ALL actions except** the listed ones
- `NotResource` with `Allow` grants access to **ALL resources except** the listed ones

This makes it easy to accidentally grant more access than intended, especially as AWS adds new services and actions.

### Patterns Detected

1. **NotAction with Allow (no conditions)** - Critical: Near-administrator access
2. **NotAction with Allow (with conditions)** - Medium: Still risky
3. **NotResource with broad Resource** - High: Access to all resources except listed

### Fail Example

```json
{
  "Effect": "Allow",
  "NotAction": ["iam:*", "sts:*"],
  "Resource": "*"
}
```

This grants ALL AWS actions **except** IAM and STS - equivalent to near-administrator access.

### How to Fix

Replace NotAction with explicit Action lists:

```json
{
  "Effect": "Allow",
  "Action": ["s3:GetObject", "s3:PutObject", "dynamodb:Query"],
  "Resource": [
    "arn:aws:s3:::my-bucket/*",
    "arn:aws:dynamodb:us-east-1:123456789012:table/my-table"
  ]
}
```

If NotAction is truly required, add strict conditions:

```json
{
  "Effect": "Allow",
  "NotAction": ["iam:*", "sts:*"],
  "Resource": "*",
  "Condition": {
    "Bool": { "aws:MultiFactorAuthPresent": "true" },
    "IpAddress": { "aws:SourceIp": "10.0.0.0/8" }
  }
}
```
