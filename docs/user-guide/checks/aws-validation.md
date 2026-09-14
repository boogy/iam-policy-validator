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

| Policy Type                   | Limit             | Whitespace counted? |
| ----------------------------- | ----------------- | ------------------- |
| Managed policy                | 6,144 characters  | no                  |
| Inline user policy            | 2,048 characters  | no                  |
| Inline group policy           | 5,120 characters  | no                  |
| Inline role policy            | 10,240 characters | no                  |
| Trust policy                  | 2,048 characters  | no                  |
| Service Control Policy (SCP)  | 10,240 characters | **yes**             |
| Resource Control Policy (RCP) | 5,120 characters  | **yes**             |

AWS raised the SCP limit from 5,120 to 10,240 characters on
[2026-05-15](https://aws.amazon.com/about-aws/whats-new/2026/05/aws-organizations-increased-scp-quotas/)
(the same change raised the per-node SCP attachment quota from 5 to 10). RCP was
not changed.

!!! danger "Whitespace counts for SCPs and RCPs"

    IAM "doesn't count white space when calculating the size of a policy", so
    identity policies are measured as **compact JSON** — how you format the file
    is irrelevant.

    AWS Organizations is different: it strips whitespace only on a console save.
    "If you save the policy using an SDK operation or the AWS CLI, then the
    policy is saved exactly as you provided and no automatic removal of
    characters occurs." Terraform, the CLI and every SDK submit the document
    verbatim, so **an SCP or RCP is measured as written** — a 2-space indented
    policy is roughly 1.7x its compact size.

    If your pipeline minifies the document before submitting it (Terraform's
    `jsonencode`, for example), the compact size is what counts; the finding
    reports both sizes so you can tell which case you are in, and
    `organizations_measurement: compact` makes compact the measurement. Policies
    validated from a dict or a YAML source fall back to the compact measurement,
    since there is no submitted document to measure. A UTF-8 byte-order mark is
    never counted.

    ```yaml
    policy_size:
      organizations_measurement: compact # default: as_written
    ```

Both measurements count UTF-8 **bytes**, matching AWS counting bytes rather than
Unicode codepoints.

!!! note "Inline policies are limited in aggregate"

    The inline limits apply to the *sum* of all inline policies on an entity
    ("the total aggregate policy size per entity"), not to each policy alone.
    This check measures one policy at a time, so an entity can still exceed its
    quota with several individually-valid inline policies.

### Which limit applies

The limit follows the resolved policy type
(`IDENTITY_POLICY` and `RESOURCE_POLICY` → managed, `TRUST_POLICY` → trust, `SERVICE_CONTROL_POLICY` → SCP,
`RESOURCE_CONTROL_POLICY` → RCP). Override it when the deployment target is more
specific than the runtime type:

```yaml
policy_size:
  policy_type: inline_user # 2,048 bytes
```

Valid keys: `managed`, `inline_user`, `inline_group`, `inline_role`,
`inline_role_trust`, `scp`, `rcp`.

!!! warning "The key goes directly under the check id"

    Options nested one level deeper under a `config:` key are **not read** —
    the override is silently ignored and the limit follows the policy type as
    if you had set nothing. The validator warns when a check's section has that
    shape. Entries under `custom_checks:` that load a module are different: their
    options do belong under `config:`.

    ```yaml
    # wrong — silently ignored
    policy_size:
      config:
        policy_type: inline_user
    ```

Setting `policy_type` pins **every** policy in the run to that one limit and
makes `--policy-type` irrelevant to this check, so prefer `policy_types:` globs
unless the whole run really targets one attachment type.

!!! warning "Declare the type for SCPs, RCPs and inline policies"

    SCPs and RCPs cannot be auto-detected: an SCP has the identity-policy shape
    and an RCP the `Principal: "*"` resource-policy shape. With no
    `--policy-type` and no `policy_types:` mapping, both are measured against
    the managed limit (6,144 bytes). A 5,500-byte RCP then passes validation
    and fails on `apply`.

    When the type was inferred and the look-alike Organizations limit would be
    exceeded — an RCP-shaped policy over 5,120 bytes, or an identity-shaped
    policy over 10,240 bytes as written — the check reports
    `policy_size_type_ambiguous` (severity `warning`, so it does not fail the run
    by default). Silence it by declaring the target:

    ```bash
    iam-validator validate --path rcp.json --policy-type RESOURCE_CONTROL_POLICY
    ```

    ```yaml
    policy_types:
      - pattern: "**/rcp/*.json"
        type: RESOURCE_CONTROL_POLICY
    ```

    Inline policies are never guessed at, since their limits apply per entity:
    declare them with `policy_size.policy_type`.

---

## sid_uniqueness

Validates Statement IDs (SIDs) are unique within a policy.

**Severity:** `error`

AWS states "In IAM, the Sid value must be unique within a JSON policy", so IAM
rejects a policy with duplicate Sids.

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

**Severity:** `warning`

AWS accepts a set operator on a single-valued key; its documentation only advises
against the pattern. Raise the severity in your config if you want it to fail CI.

### What It Checks

- Set operators used with multi-valued condition keys
- Proper syntax for set operations
