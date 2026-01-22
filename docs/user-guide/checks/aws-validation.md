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
- Global condition keys (aws:*) are used correctly

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

**Severity:** `error`

### What It Checks

- `Version` field is present and valid (2012-10-17 or 2008-10-17)
- `Statement` array is present
- Required statement fields (Effect, Action/NotAction)

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

---

## policy_size

Checks policy doesn't exceed AWS size limits.

**Severity:** `error`

### Size Limits

| Policy Type        | Limit             |
| ------------------ | ----------------- |
| Managed policy     | 6,144 characters  |
| Inline user policy | 2,048 characters  |
| Inline role policy | 10,240 characters |
| Trust policy       | 2,048 characters  |

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

Validates condition operators match value types.

**Severity:** `error`

### What It Checks

- String operators use string values
- Numeric operators use numeric values
- Date operators use valid date formats
- Bool operators use boolean values

---

## set_operator_validation

Validates ForAllValues and ForAnyValue operators are used correctly.

**Severity:** `error`

### What It Checks

- Set operators used with multi-valued condition keys
- Proper syntax for set operations
