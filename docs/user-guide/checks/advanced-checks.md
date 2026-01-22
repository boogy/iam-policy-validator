---
title: Advanced Checks
description: Condition enforcement and trust policy validation
---

# Advanced Checks

These 3 checks provide advanced validation for condition enforcement and trust policies.

## action_condition_enforcement

Enforces required conditions for specific actions.

**Severity:** `error`

### Why It Matters

Some actions are dangerous without proper conditions. For example, `iam:PassRole` without `iam:PassedToService` allows passing roles to any AWS service.

### Configuration

```yaml
action_condition_enforcement:
  enabled: true
  action_condition_requirements:
    - actions: ["iam:PassRole"]
      required_conditions:
        - condition_key: "iam:PassedToService"
          description: "Restrict which services can assume the role"
    - actions: ["sts:AssumeRole"]
      required_conditions:
        - condition_key: "aws:SourceAccount"
          description: "Restrict which accounts can assume the role"
```

### Fail Example

```json
{
  "Effect": "Allow",
  "Action": "iam:PassRole",
  "Resource": "*"
}
```

**Error:** `Action iam:PassRole requires condition iam:PassedToService`

### Pass Example

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

## action_resource_matching

Validates actions are compatible with resource types.

**Severity:** `medium`

### What It Checks

- Object actions (`s3:GetObject`) used with object ARNs
- Bucket actions (`s3:ListBucket`) used with bucket ARNs
- Service-specific resource type requirements

### Fail Example

```json
{
  "Effect": "Allow",
  "Action": "s3:GetObject",
  "Resource": "arn:aws:s3:::my-bucket"
}
```

**Error:** `s3:GetObject requires object ARN, got bucket ARN`

### Pass Example

```json
{
  "Effect": "Allow",
  "Action": "s3:GetObject",
  "Resource": "arn:aws:s3:::my-bucket/*"
}
```

---

## trust_policy_validation

Validates IAM role trust policies.

**Severity:** `high`

### What It Checks

- Valid Principal format
- Service principal syntax
- OIDC provider configuration
- SAML provider configuration
- Cross-account trust patterns

### Trust Policy Types

#### AWS Service

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {
      "Service": "lambda.amazonaws.com"
    },
    "Action": "sts:AssumeRole"
  }]
}
```

#### Cross-Account

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {
      "AWS": "arn:aws:iam::123456789012:root"
    },
    "Action": "sts:AssumeRole",
    "Condition": {
      "StringEquals": {
        "sts:ExternalId": "unique-external-id"
      }
    }
  }]
}
```

#### OIDC (GitHub Actions)

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {
      "Federated": "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"
    },
    "Action": "sts:AssumeRoleWithWebIdentity",
    "Condition": {
      "StringEquals": {
        "token.actions.githubusercontent.com:aud": "sts.amazonaws.com"
      },
      "StringLike": {
        "token.actions.githubusercontent.com:sub": "repo:org/repo:*"
      }
    }
  }]
}
```

---

## Policy Type Validation

The validator supports different policy types and validates policies match their declared type.

### Policy Types

| Type                      | Principal   | Use Case           |
| ------------------------- | ----------- | ------------------ |
| `IDENTITY_POLICY`         | Not allowed | User/role policies |
| `RESOURCE_POLICY`         | Required    | S3, SQS, etc.      |
| `TRUST_POLICY`            | Required    | Role trust         |
| `SERVICE_CONTROL_POLICY`  | Not allowed | AWS Organizations  |
| `RESOURCE_CONTROL_POLICY` | Required    | AWS Organizations  |

### Configuration

```bash
# Validate as resource policy
iam-validator validate --path bucket-policy.json --policy-type RESOURCE_POLICY

# Validate as trust policy
iam-validator validate --path trust-policy.json --policy-type TRUST_POLICY
```
