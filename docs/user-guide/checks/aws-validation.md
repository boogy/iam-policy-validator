---
title: AWS Validation Checks
description: Checks for AWS IAM policy correctness
---

# AWS Validation Checks

These checks ensure your IAM policies comply with AWS IAM rules and will be accepted by AWS.

## action_validation

Validates that actions exist in AWS service definitions.

**Severity:** `error`

### What It Checks

- Action exists in the specified AWS service
- Correct action naming format (`service:ActionName`)
- Wildcard expansion for patterns like `s3:Get*`

### Pass Example

```json
{
  "Effect": "Allow",
  "Action": "s3:GetObject",
  "Resource": "arn:aws:s3:::bucket/*"
}
```

### Fail Example

```json
{
  "Effect": "Allow",
  "Action": "s3:GetObjekt",
  "Resource": "arn:aws:s3:::bucket/*"
}
```

**Error:** `Invalid action: s3:GetObjekt (Did you mean: s3:GetObject?)`

---

## condition_key_validation

Validates that condition keys exist and are valid for the actions used.

**Severity:** `error`

### What It Checks

- Condition key exists in AWS
- Key is valid for the specified service
- Global condition keys (aws:\*) are used correctly

### Pass Example

```json
{
  "Effect": "Allow",
  "Action": "s3:GetObject",
  "Resource": "arn:aws:s3:::bucket/*",
  "Condition": {
    "StringEquals": {
      "s3:prefix": "public/"
    }
  }
}
```

### Fail Example

```json
{
  "Effect": "Allow",
  "Action": "s3:GetObject",
  "Resource": "*",
  "Condition": {
    "StringEquals": {
      "s3:invalidKey": "value"
    }
  }
}
```

---

## resource_validation

Validates resource ARN formats are correct.

**Severity:** `error`

### What It Checks

- ARN format follows AWS standards
- Service prefix matches action service
- Required ARN components are present

### Pass Example

```json
{
  "Effect": "Allow",
  "Action": "s3:GetObject",
  "Resource": "arn:aws:s3:::my-bucket/*"
}
```

### Fail Example

```json
{
  "Effect": "Allow",
  "Action": "s3:GetObject",
  "Resource": "arn:aws:s3:my-bucket"
}
```

---

## policy_structure

Validates required policy elements are present and valid.

**Severity:** `error` / `warning`

### What It Checks

- `Version` field is present and valid (2012-10-17 or 2008-10-17)
- Outdated version `2008-10-17` warning (missing policy variables, advanced operators)
- `Statement` array is present
- Required statement fields (Effect, Action/NotAction)
- Mutual exclusivity (Action vs NotAction, Resource vs NotResource, Principal vs NotPrincipal)
- Unknown/unexpected fields in statements

### Pass Example

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "s3:GetObject",
      "Resource": "*"
    }
  ]
}
```

### Fail Example

```json
{
  "Statement": [
    {
      "Action": "s3:GetObject",
      "Resource": "*"
    }
  ]
}
```

**Errors:**

- Missing `Version` field
- Missing `Effect` field

### Outdated Version Warning

```json
{
  "Version": "2008-10-17",
  "Statement": [...]
}
```

**Warning:** Policy uses outdated `Version` `2008-10-17`. This version does not support policy variables (`${aws:username}`), advanced condition operators, or some newer IAM features. Update to `2012-10-17`.

---

## policy_size

Checks policy doesn't exceed AWS size limits.

**Severity:** `error`

### Size Limits

| Policy Type                  | Limit             |
| ---------------------------- | ----------------- |
| Managed policy               | 6,144 characters  |
| Inline user policy           | 2,048 characters  |
| Inline role policy           | 10,240 characters |
| Trust policy                 | 2,048 characters  |
| Service Control Policy (SCP) | 5,120 characters  |

!!! note "SCP Size Validation"
SCP size is validated separately when using `--policy-type SERVICE_CONTROL_POLICY`. The SCP limit (5,120 characters) is stricter than the managed policy limit (6,144 characters).

---

## sid_uniqueness

Validates Statement IDs (SIDs) are unique within a policy.

**Severity:** `warning`

### Pass Example

```json
{
  "Statement": [
    {"Sid": "ReadAccess", "Effect": "Allow", ...},
    {"Sid": "WriteAccess", "Effect": "Allow", ...}
  ]
}
```

### Fail Example

```json
{
  "Statement": [
    {"Sid": "S3Access", "Effect": "Allow", ...},
    {"Sid": "S3Access", "Effect": "Allow", ...}
  ]
}
```

---

## condition_type_mismatch

Validates condition operators match value types and formats.

**Severity:** `error`

### What It Checks

- String operators use string values
- Numeric operators use numeric values
- Date operators use valid date formats (ISO 8601 with semantic validation)
- Bool operators use boolean values (`"true"` or `"false"`)
- `IpAddress`/`NotIpAddress` values are valid CIDR notation
- `ArnEquals`/`ArnLike` values start with `arn:` or contain template variables
- `Null` operator doesn't use `IfExists` suffix (`NullIfExists` is invalid)

### Operator-Specific Format Validation

Even when the condition key type is unknown, the check validates values based on the operator:

| Operator                       | Expected Format                | Example Invalid Value |
| ------------------------------ | ------------------------------ | --------------------- |
| `IpAddress` / `NotIpAddress`   | CIDR notation (IPv4 or IPv6)   | `"not-an-ip"`         |
| `ArnEquals` / `ArnLike` / etc. | Must start with `arn:` or `${` | `"just-a-string"`     |
| `Bool`                         | `"true"` or `"false"`          | `"yes"`, `"1"`, `""`  |

---

## not_principal_validation

Detects dangerous `NotPrincipal` usage patterns.

**Severity:** `warning` / `error`

### What It Checks

- `NotPrincipal` with `Effect: Allow` is **not supported** by AWS (error)
- `NotPrincipal` in `Deny` statements is valid but deprecated (warning)
- Suggests using `Principal` with condition operators as a safer alternative

### Fail Example (Error)

```json
{
  "Effect": "Allow",
  "NotPrincipal": { "AWS": "arn:aws:iam::123456789012:root" },
  "Action": "s3:GetObject",
  "Resource": "arn:aws:s3:::bucket/*"
}
```

**Error:** `NotPrincipal` with `Effect: Allow` is not supported by AWS. The policy will be rejected or will not behave as expected.

### Warning Example

```json
{
  "Effect": "Deny",
  "NotPrincipal": { "AWS": "arn:aws:iam::123456789012:role/AdminRole" },
  "Action": "s3:*",
  "Resource": "arn:aws:s3:::bucket/*"
}
```

**Warning:** AWS recommends using `Principal` with condition operators instead of `NotPrincipal`.

### How to Fix

Replace `NotPrincipal` with `Principal: "*"` and a `Condition` using `ArnNotEquals`:

```json
{
  "Effect": "Deny",
  "Principal": "*",
  "Action": "s3:*",
  "Resource": "arn:aws:s3:::bucket/*",
  "Condition": {
    "ArnNotEquals": {
      "aws:PrincipalArn": [
        "arn:aws:iam::123456789012:role/AdminRole",
        "arn:aws:iam::123456789012:root"
      ]
    }
  }
}
```

---

## set_operator_validation

Validates ForAllValues and ForAnyValue operators are used correctly.

**Severity:** `error`

### What It Checks

- Set operators used with multi-valued condition keys
- Proper syntax for set operations
