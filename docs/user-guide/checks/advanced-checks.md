---
title: Advanced Checks
description: Condition enforcement, trust policy validation, and confused deputy detection
---

# Advanced Checks

These 3 checks provide advanced validation for condition enforcement, trust policies, and confused deputy protection.

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

Validates IAM role trust policies for security best practices.

**Severity:** `high` (trust issues) / `medium` (confused deputy)

!!! note "Opt-in Check"
Trust policy validation is enabled when using `--policy-type TRUST_POLICY`. The validator auto-detects trust policies (containing `sts:AssumeRole` actions with Principal elements) and suggests using this flag.

### What It Checks

- **Action-Principal type matching** - correct principal types for each assume action
- **Provider ARN validation** - SAML and OIDC provider ARN format
- **Required conditions** - SAML:aud, OIDC audience/subject conditions
- **Confused deputy prevention** - service principals without source restrictions

### Confused Deputy Detection

When a trust policy allows a service principal to assume a role without `aws:SourceArn` or `aws:SourceAccount` conditions, any resource using that service could assume the role - not just the intended one. This is the [confused deputy problem](https://docs.aws.amazon.com/IAM/latest/UserGuide/confused-deputy.html).

#### Vulnerable Example

```json
{
  "Effect": "Allow",
  "Principal": {
    "Service": "sns.amazonaws.com"
  },
  "Action": "sts:AssumeRole"
}
```

**Warning:** Trust policy allows service principal `sns.amazonaws.com` without `aws:SourceArn` or `aws:SourceAccount` condition. This may be vulnerable to confused deputy attacks.

#### Secure Example

```json
{
  "Effect": "Allow",
  "Principal": {
    "Service": "sns.amazonaws.com"
  },
  "Action": "sts:AssumeRole",
  "Condition": {
    "ArnLike": {
      "aws:SourceArn": "arn:aws:sns:us-east-1:123456789012:my-topic"
    },
    "StringEquals": {
      "aws:SourceAccount": "123456789012"
    }
  }
}
```

#### Safe Services (Not Flagged)

Only services where the role is directly bound to a compute resource owned by the account are exempt from confused deputy checks:

| Service                    | Reason                                           |
| -------------------------- | ------------------------------------------------ |
| `ec2.amazonaws.com`        | Instance profile bound to account-owned instance |
| `lambda.amazonaws.com`     | Execution role bound to account-owned function   |
| `edgelambda.amazonaws.com` | Lambda@Edge, same model as Lambda                |

!!! warning "All Other Services Require Conditions"
All other AWS service principals -- including services that typically use service-linked roles (e.g., `guardduty`, `elasticloadbalancing`, `organizations`) -- require `aws:SourceArn` or `aws:SourceAccount` conditions when used in custom trust policies. If a customer writes a custom trust policy for any of these services, the confused deputy risk applies to that custom role.

### Trust Policy Types

#### AWS Service

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Service": "lambda.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
```

#### Cross-Account

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
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
    }
  ]
}
```

#### OIDC (GitHub Actions)

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
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
    }
  ]
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
