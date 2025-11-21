# Check Reference Guide

Complete reference for all **19 built-in validation checks** with configuration options and pass/fail examples.

## Check Overview

The validator includes **19 checks** organized into three categories:

- **12 AWS Validation Checks** - Ensure policies conform to AWS IAM requirements
- **6 Security Best Practice Checks** - Identify security risks and anti-patterns
- **1 Trust Policy Check** - Validates role assumption policies (opt-in, disabled by default)

**Note:** The `policy_structure` check runs automatically before all other checks to validate fundamental policy structure. It's not configurable but ensures basic AWS IAM policy grammar compliance.

## Quick Reference

| Check                                                         | Severity | Type           | Default | Configurable |
| ------------------------------------------------------------- | -------- | -------------- | ------- | ------------ |
| [policy_structure](#policy_structure)                         | error    | Structure      | ✅ On    | ❌            |
| [sid_uniqueness](#sid_uniqueness)                             | error    | AWS Validation | ✅ On    | ❌            |
| [policy_size](#policy_size)                                   | error    | AWS Validation | ✅ On    | ✅            |
| [action_validation](#action_validation)                       | error    | AWS Validation | ✅ On    | ❌            |
| [condition_key_validation](#condition_key_validation)         | error    | AWS Validation | ✅ On    | ✅            |
| [condition_type_mismatch](#condition_type_mismatch)           | error    | AWS Validation | ✅ On    | ❌            |
| [set_operator_validation](#set_operator_validation)           | error    | AWS Validation | ✅ On    | ❌            |
| [mfa_condition_antipattern](#mfa_condition_antipattern)       | warning  | AWS Validation | ✅ On    | ❌            |
| [resource_validation](#resource_validation)                   | error    | AWS Validation | ✅ On    | ✅            |
| [principal_validation](#principal_validation)                 | high     | AWS Validation | ✅ On    | ✅            |
| [policy_type_validation](#policy_type_validation)             | error    | AWS Validation | ✅ On    | ❌            |
| [action_resource_matching](#action_resource_matching)         | medium   | AWS Validation | ✅ On    | ❌            |
| [wildcard_action](#wildcard_action)                           | medium   | Security       | ✅ On    | ✅            |
| [wildcard_resource](#wildcard_resource)                       | medium   | Security       | ✅ On    | ✅            |
| [full_wildcard](#full_wildcard)                               | critical | Security       | ✅ On    | ❌            |
| [service_wildcard](#service_wildcard)                         | high     | Security       | ✅ On    | ✅            |
| [sensitive_action](#sensitive_action)                         | medium   | Security       | ✅ On    | ✅            |
| [action_condition_enforcement](#action_condition_enforcement) | high     | Security       | ✅ On    | ✅            |
| [trust_policy_validation](#trust_policy_validation)           | high     | Trust Policy   | ⚠️ Off   | ✅            |

---

## Policy Structure Check (1 check)

This check runs **first** before all other checks to validate fundamental IAM policy structure.

### policy_structure

**Purpose:** Validates that IAM policies meet AWS IAM structural requirements before detailed validation.

**Severity:** `error` (not configurable)

**Always Enabled:** This check cannot be disabled as it ensures basic policy validity.

**What it validates:**
- **Required fields**: Policy must have `Version` and `Statement` fields
- **Valid Version**: Must be `2012-10-17` or `2008-10-17`
- **Statement structure**: Each statement must have `Effect` and `Action`/`NotAction`
- **Field conflicts**: `Action` vs `NotAction`, `Resource` vs `NotResource`, `Principal` vs `NotPrincipal`
- **Valid values**: `Effect` must be `"Allow"` or `"Deny"`
- **Unknown fields**: Detects typos and unexpected fields
- **Policy type detection**: Auto-detects IDENTITY_POLICY vs RESOURCE_POLICY

#### Configuration

This check is not configurable and always runs first.

```yaml
# policy_structure check cannot be disabled or configured
# It automatically runs before all other checks
```

#### Examples

❌ **FAIL: Missing Version field**
```json
{
  "Statement": [{
    "Effect": "Allow",
    "Action": "s3:GetObject",
    "Resource": "*"
  }]
}
```
**Error:** `Policy document is missing the 'Version' field`

❌ **FAIL: Invalid Effect value**
```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "allow",  // Must be "Allow" or "Deny" (case-sensitive)
    "Action": "s3:GetObject",
    "Resource": "*"
  }]
}
```
**Error:** `Invalid Effect value: 'allow'. Must be 'Allow' or 'Deny'`

❌ **FAIL: Action and NotAction conflict**
```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": "s3:GetObject",
    "NotAction": "s3:DeleteObject",  // Cannot have both!
    "Resource": "*"
  }]
}
```
**Error:** `Statement contains both 'Action' and 'NotAction' fields`

❌ **FAIL: Unknown field (typo)**
```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Actions": "s3:GetObject",  // Typo: should be "Action"
    "Resource": "*"
  }]
}
```
**Error:** `Statement contains unknown field(s): 'Actions'`

✅ **PASS: Valid policy structure**
```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": "s3:GetObject",
    "Resource": "arn:aws:s3:::my-bucket/*"
  }]
}
```

**Why This Check is Important:**
- Catches structural errors before expensive AWS API validation
- Provides clear error messages for common typos
- Prevents submission of malformed policies to AWS
- Enables better error reporting in GitHub PRs

---

## AWS Validation Checks (11 checks)

These validate that policies conform to AWS IAM requirements and will work correctly in AWS.

### sid_uniqueness

**Purpose:** Ensures Statement IDs (Sids) are unique within a policy and follow AWS naming rules.

**Severity:** `error` (not configurable)

**AWS Requirements:**
- Sids must be unique within the policy
- Only alphanumeric characters, hyphens, and underscores allowed
- No spaces or special characters

#### Configuration

```yaml
sid_uniqueness:
  enabled: true
  severity: error  # Cannot be changed
  description: "Validates that Statement IDs (Sids) are unique and follow AWS naming requirements"
```

#### Examples

❌ **FAIL: Duplicate SID**
```json
{
  "Statement": [
    {
      "Sid": "AllowS3Access",
      "Effect": "Allow",
      "Action": "s3:GetObject",
      "Resource": "*"
    },
    {
      "Sid": "AllowS3Access",  // Duplicate!
      "Effect": "Allow",
      "Action": "s3:PutObject",
      "Resource": "*"
    }
  ]
}
```
**Error:** `Duplicate Statement ID 'AllowS3Access' found`

❌ **FAIL: Invalid SID format**
```json
{
  "Statement": [{
    "Sid": "Allow S3 Access",  // Space not allowed!
    "Effect": "Allow",
    "Action": "s3:*",
    "Resource": "*"
  }]
}
```
**Error:** `Statement ID 'Allow S3 Access' contains invalid characters`

✅ **PASS:**
```json
{
  "Statement": [
    {
      "Sid": "AllowS3Read",
      "Effect": "Allow",
      "Action": "s3:GetObject",
      "Resource": "*"
    },
    {
      "Sid": "AllowS3Write",
      "Effect": "Allow",
      "Action": "s3:PutObject",
      "Resource": "*"
    }
  ]
}
```

---

### policy_size

**Purpose:** Validates that IAM policies don't exceed AWS size limits.

**Severity:** `error` (configurable)

**AWS Limits (characters, excluding whitespace):**
- Managed policy: 6,144 characters
- Inline user policy: 2,048 characters
- Inline group policy: 5,120 characters
- Inline role policy: 10,240 characters

**How Policy Type is Determined:**

You must configure which size limit to check. There are **two common approaches**:

1. **Single Policy Type** (simplest) - All policies use same limit:
   ```yaml
   policy_size:
     policy_type: "managed"  # Check all policies against managed limit (6,144)
   ```

2. **Multiple Policy Types** - Validate different directories separately:
   ```bash
   # Strict limit for managed policies
   iam-validator validate managed-policies/ --config managed-config.yaml

   # Lenient limit for inline role policies
   iam-validator validate inline-roles/ --config inline-role-config.yaml
   ```

#### Configuration

```yaml
policy_size:
  enabled: true
  severity: error
  policy_type: "managed"  # Default type to check
  # Options: managed, inline_user, inline_group, inline_role

  # Optional: Override AWS default limits
  size_limits:
    managed: 6144
    inline_user: 2048
    inline_group: 5120
    inline_role: 10240
```

**Best Practices:**

- **Don't know the type?** Use `policy_type: "managed"` (strictest limit, safest default)
- **Managed policies only?** Use `policy_type: "managed"` (most common)
- **Inline role policies?** Use `policy_type: "inline_role"` (10,240 limit)
- **Mixed types?** Organize into directories and validate separately with different configs

#### Examples

❌ **FAIL: Exceeds managed policy limit**
```json
{
  "Statement": [
    // ... policy with 7000 characters ...
  ]
}
```

**Config used:**
```yaml
policy_size:
  policy_type: "managed"  # 6,144 limit
```

**Error:** `Policy size 7000 characters exceeds managed policy limit of 6144 characters`

**Solution 1: Reduce policy size**
```json
{
  "Statement": [
    // ... simplified to under 6,144 characters ...
  ]
}
```

**Solution 2: If this is actually an inline role policy**
```yaml
policy_size:
  policy_type: "inline_role"  # 10,240 character limit (more lenient)
```

✅ **PASS:**
Policy is under the configured limit for its type.

**Example: Repository with Mixed Policy Types**

```
project/
├── managed-policies/          # Customer-managed policies (6,144 limit)
│   └── config.yaml → policy_type: "managed"
├── inline-role-policies/      # Inline role policies (10,240 limit)
│   └── config.yaml → policy_type: "inline_role"
└── inline-user-policies/      # Inline user policies (2,048 limit)
    └── config.yaml → policy_type: "inline_user"
```

**Validate each directory separately:**
```bash
iam-validator validate managed-policies/
iam-validator validate inline-role-policies/
iam-validator validate inline-user-policies/
```

---

### action_validation

**Purpose:** Validates that all actions exist in AWS service definitions.

**Severity:** `error` (not configurable)

#### Configuration

```yaml
action_validation:
  enabled: true
  severity: error
```

#### Examples

❌ **FAIL: Invalid action**
```json
{
  "Statement": [{
    "Effect": "Allow",
    "Action": "s3:InvalidAction",  // Does not exist!
    "Resource": "*"
  }]
}
```
**Error:** `Action 's3:InvalidAction' does not exist in AWS service 's3'`

❌ **FAIL: Invalid service**
```json
{
  "Statement": [{
    "Effect": "Allow",
    "Action": "nonexistent:GetObject",
    "Resource": "*"
  }]
}
```
**Error:** `AWS service 'nonexistent' does not exist`

✅ **PASS:**
```json
{
  "Statement": [{
    "Effect": "Allow",
    "Action": "s3:GetObject",
    "Resource": "*"
  }]
}
```

---

### condition_key_validation

**Purpose:** Validates that condition keys are valid for the specified actions.

**Severity:** `error` (configurable validation behavior)

#### Configuration

```yaml
condition_key_validation:
  enabled: true
  severity: error
  validate_aws_global_keys: true  # Validate aws:* keys against known list
  warn_on_global_condition_keys: false  # Warn when global keys may not be available in request context
```

#### Examples

❌ **FAIL: Invalid condition key**
```json
{
  "Statement": [{
    "Effect": "Allow",
    "Action": "s3:GetObject",
    "Resource": "*",
    "Condition": {
      "StringEquals": {
        "s3:InvalidKey": "value"  // Does not exist!
      }
    }
  }]
}
```
**Error:** `Condition key 's3:InvalidKey' is not valid for action 's3:GetObject'`

❌ **FAIL: Invalid global condition key**
```json
{
  "Statement": [{
    "Effect": "Allow",
    "Action": "s3:GetObject",
    "Resource": "*",
    "Condition": {
      "StringEquals": {
        "aws:InvalidGlobalKey": "value"
      }
    }
  }]
}
```
**Error:** `Global condition key 'aws:InvalidGlobalKey' is not recognized`

⚠️ **WARNING: Global key may not be available in all contexts** (if `warn_on_global_condition_keys: true`)
```json
{
  "Statement": [{
    "Effect": "Allow",
    "Action": "s3:PutObject",
    "Resource": "arn:aws:s3:::bucket/*",
    "Condition": {
      "StringEquals": {
        "aws:PrincipalTag/Department": "Engineering"
      }
    }
  }]
}
```
**Warning:** `Global condition key 'aws:PrincipalTag/Department' is used with action 's3:PutObject'. While global condition keys can be used across all AWS services, the key may not be available in every request context. Verify that 'aws:PrincipalTag/Department' is available for this specific action's request context. Consider using '*IfExists' operators (e.g., StringEqualsIfExists) if the key might be missing.`

✅ **PASS:**
```json
{
  "Statement": [{
    "Effect": "Allow",
    "Action": "s3:GetObject",
    "Resource": "*",
    "Condition": {
      "StringEquals": {
        "s3:ExistingObjectTag/environment": "prod"
      }
    }
  }]
}
```

---

### condition_type_mismatch

**Purpose:** Validates that condition operators match the key types and value formats.

**Severity:** `error`

**Validates:**
- Operator matches key type (StringEquals for String keys, NumericEquals for Numeric keys)
- Value format is correct (dates, IPs, ARNs, booleans)

#### Examples

❌ **FAIL: Wrong operator for key type**
```json
{
  "Condition": {
    "NumericEquals": {
      "aws:username": "admin"  // aws:username is String type!
    }
  }
}
```
**Error:** `Operator 'NumericEquals' cannot be used with String-type condition key 'aws:username'`

❌ **FAIL: Invalid date format**
```json
{
  "Condition": {
    "DateGreaterThan": {
      "aws:CurrentTime": "2024-01-01"  // Missing time and timezone!
    }
  }
}
```
**Error:** `Invalid date format '2024-01-01'. Expected ISO 8601 format like '2024-01-01T00:00:00Z'`

❌ **FAIL: Invalid boolean value**
```json
{
  "Condition": {
    "Bool": {
      "aws:MultiFactorAuthPresent": "yes"  // Must be "true" or "false"!
    }
  }
}
```
**Error:** `Invalid boolean value 'yes'. Must be 'true' or 'false'`

❌ **FAIL: Invalid IP address**
```json
{
  "Condition": {
    "IpAddress": {
      "aws:SourceIp": "192.168.1.999"  // Invalid IP!
    }
  }
}
```
**Error:** `Invalid IP address '192.168.1.999'`

✅ **PASS:**
```json
{
  "Condition": {
    "StringEquals": {
      "aws:username": "admin"
    },
    "DateGreaterThan": {
      "aws:CurrentTime": "2024-01-01T00:00:00Z"
    },
    "Bool": {
      "aws:MultiFactorAuthPresent": "true"
    },
    "IpAddress": {
      "aws:SourceIp": "192.168.1.0/24"
    }
  }
}
```

---

### set_operator_validation

**Purpose:** Validates that ForAllValues/ForAnyValue operators are used with multi-value keys only.

**Severity:** `error`

**Set Operators:**
- `ForAllValues:` - All values in request must be in allowed values
- `ForAnyValue:` - At least one value in request must be in allowed values

#### Examples

❌ **FAIL: Set operator with single-value key**
```json
{
  "Condition": {
    "ForAllValues:StringEquals": {
      "aws:username": "admin"  // username is single-value!
    }
  }
}
```
**Error:** `Set operator 'ForAllValues' used with single-value condition key 'aws:username'`

✅ **PASS: Set operator with multi-value key**
```json
{
  "Condition": {
    "ForAllValues:StringEquals": {
      "aws:TagKeys": ["environment", "owner"]  // TagKeys is multi-value
    }
  }
}
```

✅ **PASS: Regular operator with single-value key**
```json
{
  "Condition": {
    "StringEquals": {
      "aws:username": "admin"
    }
  }
}
```

---

### mfa_condition_antipattern

**Purpose:** Detects MFA condition patterns that don't actually enforce MFA.

**Severity:** `warning`

**Common Mistakes:**
1. Using `"aws:MultiFactorAuthPresent": "false"` with Bool (key might not exist)
2. Using Null operator to check if key is false

#### Examples

⚠️ **WARNING: Bool with false doesn't enforce MFA**
```json
{
  "Effect": "Allow",
  "Action": "s3:*",
  "Resource": "*",
  "Condition": {
    "Bool": {
      "aws:MultiFactorAuthPresent": "false"  // Allows when key doesn't exist!
    }
  }
}
```
**Warning:** `Condition allows access when MFA key is missing. This does not enforce MFA.`

**Explanation:** If the user never authenticated with MFA, the key doesn't exist and evaluates to false, allowing access.

⚠️ **WARNING: Null operator checks existence, not value**
```json
{
  "Effect": "Deny",
  "Action": "s3:*",
  "Resource": "*",
  "Condition": {
    "Null": {
      "aws:MultiFactorAuthPresent": "false"
    }
  }
}
```
**Warning:** `Null operator only checks if key exists, not its value`

✅ **CORRECT: Require MFA**
```json
{
  "Effect": "Allow",
  "Action": "s3:*",
  "Resource": "*",
  "Condition": {
    "Bool": {
      "aws:MultiFactorAuthPresent": "true"  // Requires MFA!
    }
  }
}
```

✅ **CORRECT: Deny without MFA**
```json
{
  "Effect": "Deny",
  "Action": "s3:*",
  "Resource": "*",
  "Condition": {
    "BoolIfExists": {
      "aws:MultiFactorAuthPresent": "false"
    }
  }
}
```

---

### resource_validation

**Purpose:** Validates ARN format for resources.

**Severity:** `error`

#### Configuration

```yaml
resource_validation:
  enabled: true
  severity: error
  # Regex pattern for ARN validation (allows wildcards in region/account)
  # Default pattern supports all AWS partitions:
  # aws, aws-cn, aws-us-gov, aws-eusc, aws-iso, aws-iso-b, aws-iso-e, aws-iso-f
  arn_pattern: "^arn:(aws|aws-cn|aws-us-gov|aws-eusc|aws-iso|aws-iso-b|aws-iso-e|aws-iso-f):[a-z0-9\\-]+:[a-z0-9\\-*]*:[0-9*]*:.+$"
```

#### Examples

❌ **FAIL: Invalid ARN format**
```json
{
  "Resource": "not-an-arn"
}
```
**Error:** `Invalid ARN format: not-an-arn`

❌ **FAIL: Invalid partition**
```json
{
  "Resource": "arn:invalid:s3:::my-bucket/*"
}
```
**Error:** `Invalid ARN format: arn:invalid:s3:::my-bucket/*`

❌ **FAIL: Missing resource identifier**
```json
{
  "Resource": "arn:aws:s3:::"  // Missing bucket name!
}
```
**Error:** `Invalid ARN format: arn:aws:s3:::`

✅ **PASS: Valid ARNs**
```json
{
  "Resource": [
    "arn:aws:s3:::my-bucket/*",
    "arn:aws:s3:::my-bucket",
    "arn:aws:iam::123456789012:role/MyRole",
    "arn:aws:ec2:us-east-1:*:instance/*",  // Wildcard account OK
    "arn:aws:s3:*:*:*",  // Wildcard region/account OK
    "*"  // Special case: full wildcard
  ]
}
```

---

### principal_validation

**Purpose:** Validates Principal elements in resource-based policies for security.

**Severity:** `high` (configurable)

**Only runs with:** `--policy-type RESOURCE_POLICY`

#### Configuration

```yaml
principal_validation:
  enabled: true
  severity: high

  # Block these principals (public access, cross-account root)
  blocked_principals:
    - "*"
    - "arn:aws:iam::*:root"

  # Allow only these (whitelist mode - optional)
  allowed_principals: []

  # Service principals that are always allowed
  # Default: "*" allows ALL AWS service principals (*.amazonaws.com)
  # This is recommended as AWS services are generally trusted
  allowed_service_principals:
    - "*"  # Allow all AWS service principals (default)

  # Or restrict to specific services:
  # allowed_service_principals:
  #   - "cloudfront.amazonaws.com"
  #   - "s3.amazonaws.com"
  #   - "lambda.amazonaws.com"

  # Simple format: Require conditions for specific principals
  require_conditions_for:
    "*":
      - "aws:SourceArn"
      - "aws:SourceAccount"
    "arn:aws:iam::*:root":
      - "aws:PrincipalOrgID"

  # Advanced format: Rich condition requirements
  principal_condition_requirements:
    - principals:
        - "*"
      severity: critical
      required_conditions:
        all_of:
          - condition_key: "aws:SourceArn"
            description: "Limit by source ARN"
          - condition_key: "aws:SourceAccount"
            description: "Limit by account ID"
```

#### Examples

❌ **FAIL: Public access (blocked principal)**
```json
{
  "Statement": [{
    "Effect": "Allow",
    "Principal": "*",  // Public access - blocked!
    "Action": "s3:GetObject",
    "Resource": "arn:aws:s3:::my-bucket/*"
  }]
}
```
**Error:** `Blocked principal detected: *. This principal is explicitly blocked by your security policy.`

❌ **FAIL: Public access without required conditions**
```json
{
  "Statement": [{
    "Effect": "Allow",
    "Principal": "*",
    "Action": "s3:GetObject",
    "Resource": "arn:aws:s3:::my-bucket/*"
    // Missing required conditions!
  }]
}
```
**Error:** `Principal '*' requires conditions: aws:SourceArn, aws:SourceAccount. This principal must have these condition keys to restrict access.`

❌ **FAIL: Cross-account root without conditions**
```json
{
  "Statement": [{
    "Effect": "Allow",
    "Principal": {
      "AWS": "arn:aws:iam::123456789012:root"
    },
    "Action": "s3:GetObject",
    "Resource": "arn:aws:s3:::my-bucket/*"
  }]
}
```
**Config requires:**
```yaml
require_conditions_for:
  "arn:aws:iam::*:root":
    - "aws:PrincipalOrgID"
```
**Error:** `Principal 'arn:aws:iam::123456789012:root' requires conditions: aws:PrincipalOrgID`

✅ **PASS: Public access with conditions (CloudFront)**
```json
{
  "Statement": [{
    "Effect": "Allow",
    "Principal": "*",
    "Action": "s3:GetObject",
    "Resource": "arn:aws:s3:::my-bucket/*",
    "Condition": {
      "StringEquals": {
        "aws:SourceArn": "arn:aws:cloudfront::123456789012:distribution/EXAMPLE"
      }
    }
  }]
}
```

✅ **PASS: Service principal (always allowed)**
```json
{
  "Statement": [{
    "Effect": "Allow",
    "Principal": {
      "Service": "lambda.amazonaws.com"
    },
    "Action": "logs:CreateLogGroup",
    "Resource": "*"
  }]
}
```

✅ **PASS: Cross-account with organization restriction**
```json
{
  "Statement": [{
    "Effect": "Allow",
    "Principal": {
      "AWS": "arn:aws:iam::123456789012:root"
    },
    "Action": "s3:GetObject",
    "Resource": "arn:aws:s3:::my-bucket/*",
    "Condition": {
      "StringEquals": {
        "aws:PrincipalOrgID": "o-xxxxx"
      }
    }
  }]
}
```

**Whitelist Mode Example:**
```yaml
principal_validation:
  allowed_principals:
    - "arn:aws:iam::123456789012:*"  # Only this account
    - "arn:aws:iam::999888777666:role/TrustedRole"  # Specific role
```

---

### policy_type_validation

**Purpose:** Ensures policies match declared type and enforces RCP requirements.

**Severity:** `error`

**Validates:**
- IDENTITY policies don't have Principal element
- RESOURCE_POLICY policies have Principal element
- RCP (Resource Control Policy) requirements

#### Examples

❌ **FAIL: Identity policy with Principal**
```bash
iam-validator validate policy.json --policy-type IDENTITY
```
```json
{
  "Statement": [{
    "Effect": "Allow",
    "Principal": {"AWS": "arn:aws:iam::123456789012:root"},  // Not allowed!
    "Action": "s3:GetObject",
    "Resource": "*"
  }]
}
```
**Error:** `Identity policy cannot have Principal element`

❌ **FAIL: Resource policy without Principal**
```bash
iam-validator validate policy.json --policy-type RESOURCE_POLICY
```
```json
{
  "Statement": [{
    "Effect": "Allow",
    "Action": "s3:GetObject",  // Missing Principal!
    "Resource": "*"
  }]
}
```
**Error:** `Resource policy must have Principal element`

✅ **PASS: Correct types**
```json
// Identity policy (no Principal)
{
  "Statement": [{
    "Effect": "Allow",
    "Action": "s3:GetObject",
    "Resource": "*"
  }]
}

// Resource policy (has Principal)
{
  "Statement": [{
    "Effect": "Allow",
    "Principal": {"AWS": "arn:aws:iam::123456789012:root"},
    "Action": "s3:GetObject",
    "Resource": "*"
  }]
}
```

---

### action_resource_matching

**Purpose:** Validates that resources match required types for actions, including ensuring account-level actions use `Resource: "*"`.

**Severity:** `medium`

**Common Mistakes:**
- Account-level actions (e.g., `iam:ListUsers`, `s3:ListAllMyBuckets`) with specific resource ARNs
- `s3:GetObject` with bucket ARN (needs object ARN with `/*`)
- `s3:ListBucket` with object ARN (needs bucket ARN without `/`)

#### Examples

❌ **FAIL: Account-level action with specific resource**
```json
{
  "Statement": [{
    "Effect": "Allow",
    "Action": "iam:ListUsers",
    "Resource": "arn:aws:iam::123456789012:user/*"  // Not allowed!
  }]
}
```
**Error:** `Action 'iam:ListUsers' can only use Resource: "*"`

**Fix:**
```json
{
  "Statement": [{
    "Effect": "Allow",
    "Action": "iam:ListUsers",
    "Resource": "*"  // Correct!
  }]
}
```

❌ **FAIL: s3:GetObject with bucket ARN**
```json
{
  "Statement": [{
    "Effect": "Allow",
    "Action": "s3:GetObject",
    "Resource": "arn:aws:s3:::my-bucket"  // Missing /*
  }]
}
```
**Error:** `Action 's3:GetObject' requires object ARN. Add '/*' to bucket ARN`

**Fix:**
```json
{
  "Resource": "arn:aws:s3:::my-bucket/*"
}
```

❌ **FAIL: s3:ListBucket with object ARN**
```json
{
  "Statement": [{
    "Effect": "Allow",
    "Action": "s3:ListBucket",
    "Resource": "arn:aws:s3:::my-bucket/*"  // Should not have /*
  }]
}
```
**Error:** `Action 's3:ListBucket' requires bucket ARN, not object ARN. Remove '/*'`

**Fix:**
```json
{
  "Resource": "arn:aws:s3:::my-bucket"
}
```

✅ **PASS: Correct resource types**
```json
{
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "s3:ListBucket",
      "Resource": "arn:aws:s3:::my-bucket"
    },
    {
      "Effect": "Allow",
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::my-bucket/*"
    }
  ]
}
```

---

## Security Best Practice Checks (6 checks)

These checks flag security anti-patterns and enforce least-privilege principles.

### wildcard_action

**Purpose:** Flags statements that allow all actions (`Action: "*"`).

**Severity:** `medium` (configurable)

#### Configuration

```yaml
wildcard_action:
  enabled: true
  severity: medium  # Can be: low, medium, high, critical
  message: "Statement allows all actions (*)"
  suggestion: "Replace wildcard with specific actions"
```

#### Examples

❌ **FAIL: Wildcard action**
```json
{
  "Statement": [{
    "Effect": "Allow",
    "Action": "*",  // Too permissive!
    "Resource": "arn:aws:s3:::my-bucket/*"
  }]
}
```
**Issue:** `Statement allows all actions (*)`
**Severity:** `medium`

**Fix:**
```json
{
  "Statement": [{
    "Effect": "Allow",
    "Action": ["s3:GetObject", "s3:PutObject"],  // Specific actions
    "Resource": "arn:aws:s3:::my-bucket/*"
  }]
}
```

✅ **PASS: Specific actions**
```json
{
  "Statement": [{
    "Effect": "Allow",
    "Action": "s3:GetObject",
    "Resource": "*"
  }]
}
```

---

### wildcard_resource

**Purpose:** Flags statements that apply to all resources (`Resource: "*"`).

**Severity:** `medium` (configurable)

**Exception:** Allowed if ALL actions are in the allowed_wildcards list (read-only operations).

#### Dual Matching Strategy

The check uses **two complementary matching strategies** for maximum flexibility:

**1. Literal Match (Fast Path - no AWS API calls)**
- Policy actions match config patterns exactly as strings
- Example: Policy `"iam:Get*"` matches config `"iam:Get*"` → ✅ PASS
- Performance benefit: No AWS API expansion needed

**2. Expanded Match (Comprehensive Path - uses AWS API)**
- Both policy actions and config patterns expand to actual AWS actions
- Example: Policy `"iam:GetUser"` matches config `"iam:Get*"` (expanded) → ✅ PASS
- Ensures semantic correctness

**Supported Scenarios:**

| Policy Action           | Config Pattern        | Match Type | Result |
| ----------------------- | --------------------- | ---------- | ------ |
| `iam:Get*`              | `iam:Get*`            | Literal    | ✅ Pass |
| `iam:GetUser`           | `iam:Get*`            | Expanded   | ✅ Pass |
| `iam:Get*, iam:List*`   | `iam:Get*, iam:List*` | Literal    | ✅ Pass |
| `iam:Get*, iam:GetUser` | `iam:Get*`            | Literal    | ✅ Pass |
| `iam:Delete*`           | `iam:Get*`            | None       | ❌ Fail |

#### Configuration

```yaml
wildcard_resource:
  enabled: true
  severity: medium
  # Actions allowed with Resource: "*" (default from Python module)
  # Supports BOTH literal matching and pattern expansion
  allowed_wildcards:
    # Wildcard patterns - match both literally and expanded
    - "ec2:Describe*"    # Matches: ec2:Describe* OR ec2:DescribeInstances
    - "s3:List*"         # Matches: s3:List* OR s3:ListBucket
    - "iam:Get*"         # Matches: iam:Get* OR iam:GetUser

    # Specific actions - match only via expansion
    - "iam:GetUser"      # Matches: iam:GetUser only
    - "s3:ListBucket"    # Matches: s3:ListBucket only

    # ... 25 patterns by default
```

#### Examples

❌ **FAIL: Wildcard resource with write action**
```json
{
  "Statement": [{
    "Effect": "Allow",
    "Action": "s3:PutObject",  // Write action
    "Resource": "*"  // All buckets!
  }]
}
```
**Issue:** `Statement applies to all resources (*)`
**Severity:** `medium`

✅ **PASS: Wildcard actions with literal match (fast path)**
```json
{
  "Statement": [{
    "Effect": "Allow",
    "Action": ["iam:Get*", "iam:List*"],  // Wildcard actions
    "Resource": "*"  // OK - matches config literally
  }]
}
```
**Config:** `allowed_wildcards: ["iam:Get*", "iam:List*"]`
**Match:** Literal string match (no AWS API call needed)

✅ **PASS: Specific actions with expanded match**
```json
{
  "Statement": [{
    "Effect": "Allow",
    "Action": ["ec2:DescribeInstances", "ec2:DescribeVolumes"],  // Specific actions
    "Resource": "*"  // OK - all match when config expands
  }]
}
```
**Config:** `allowed_wildcards: ["ec2:Describe*"]`
**Match:** Config expands to include these specific actions

✅ **PASS: Specific resource**
```json
{
  "Statement": [{
    "Effect": "Allow",
    "Action": "s3:PutObject",
    "Resource": "arn:aws:s3:::my-bucket/*"  // Specific bucket
  }]
}
```

**Performance Tip:** Use exact patterns in both policy and config for fastest validation (literal match path).

---

### full_wildcard

**Purpose:** Flags BOTH `Action: "*"` AND `Resource: "*"` (full admin access).

**Severity:** `critical` (not configurable)

#### Examples

🚨 **CRITICAL: Full administrative access**
```json
{
  "Statement": [{
    "Effect": "Allow",
    "Action": "*",  // All actions
    "Resource": "*"  // On all resources
  }]
}
```
**Issue:** `Statement allows all actions on all resources - CRITICAL SECURITY RISK`
**Severity:** `critical`

**This is equivalent to:** AWS AdministratorAccess managed policy

**Fix:**
```json
{
  "Statement": [{
    "Effect": "Allow",
    "Action": ["s3:GetObject", "s3:PutObject"],  // Specific actions
    "Resource": "arn:aws:s3:::my-bucket/*"  // Specific resource
  }]
}
```

---

### service_wildcard

**Purpose:** Flags service-level wildcards (`iam:*`, `s3:*`, `ec2:*`).

**Severity:** `high` (configurable)

**Exception:** Some services are safe (logs, cloudwatch, xray).

#### Configuration

```yaml
service_wildcard:
  enabled: true
  severity: high
  # Services allowed to use wildcards
  allowed_services:
    - logs
    - cloudwatch
    - xray
```

#### Examples

❌ **FAIL: IAM service wildcard**
```json
{
  "Statement": [{
    "Effect": "Allow",
    "Action": "iam:*",  // All IAM actions!
    "Resource": "*"
  }]
}
```
**Issue:** `Service wildcard 'iam:*' grants all permissions for IAM service`
**Severity:** `high`

**Why dangerous:** Includes privilege escalation actions like `iam:CreateUser`, `iam:AttachUserPolicy`

❌ **FAIL: S3 service wildcard**
```json
{
  "Statement": [{
    "Effect": "Allow",
    "Action": "s3:*",  // All S3 actions!
    "Resource": "*"
  }]
}
```
**Issue:** `Service wildcard 's3:*' grants all permissions for S3 service`
**Severity:** `high`

✅ **PASS: Allowed service wildcards**
```json
{
  "Statement": [{
    "Effect": "Allow",
    "Action": "logs:*",  // Logs service is safe
    "Resource": "*"
  }]
}
```

✅ **PASS: Specific actions**
```json
{
  "Statement": [{
    "Effect": "Allow",
    "Action": ["s3:GetObject", "s3:PutObject"],  // Specific actions
    "Resource": "*"
  }]
}
```

---

### sensitive_action

**Purpose:** Flags sensitive actions without IAM conditions.

**Severity:** `medium` (configurable per category)

**490 sensitive actions across 4 categories:**
- CredentialExposure (46): Exposes credentials/secrets
- DataAccess (109): Retrieves sensitive data
- PrivEsc (27): Enables privilege escalation
- ResourceExposure (321): Modifies resource policies

#### Configuration

```yaml
sensitive_action:
  enabled: true
  severity: medium

  # Filter by categories (optional)
  categories:
    - credential_exposure
    - priv_esc

  # Category-specific severities
  category_severities:
    credential_exposure: high
    data_access: medium
    priv_esc: critical
    resource_exposure: high
```

#### Examples

⚠️ **WARNING: Sensitive action without conditions**
```json
{
  "Statement": [{
    "Effect": "Allow",
    "Action": "iam:CreateAccessKey",  // Privilege escalation risk!
    "Resource": "*"
    // Missing conditions!
  }]
}
```
**Issue:** `Sensitive action 'iam:CreateAccessKey' should have conditions to limit when it can be used`
**Category:** `priv_esc`
**Severity:** `medium` (or `critical` if using category_severities)

✅ **PASS: Sensitive action with conditions**
```json
{
  "Statement": [{
    "Effect": "Allow",
    "Action": "iam:CreateAccessKey",
    "Resource": "*",
    "Condition": {
      "StringEquals": {
        "aws:PrincipalTag/role": "admin"
      },
      "Bool": {
        "aws:MultiFactorAuthPresent": "true"
      }
    }
  }]
}
```

**Configuration Examples:**

**Focus on privilege escalation only:**
```yaml
sensitive_action:
  categories:
    - priv_esc  # Only check 27 privilege escalation actions
  category_severities:
    priv_esc: critical
```

**Different severities per category:**
```yaml
sensitive_action:
  category_severities:
    credential_exposure: high      # 46 actions
    data_access: medium            # 109 actions
    priv_esc: critical             # 27 actions
    resource_exposure: high        # 321 actions
```

**Disable check (check all 490 actions):**
```yaml
sensitive_action:
  # categories not specified = check all
```

---

### action_condition_enforcement

**Purpose:** Enforces specific IAM condition requirements for actions.

**Severity:** `high` (configurable)

**Default:** 5 pre-defined requirements (from Python module)
1. `iam:PassRole` must have `iam:PassedToService`
2. S3 writes must have organization ID
3. Source IP restrictions for sensitive actions
4. S3 must use secure transport
5. Prevent 0.0.0.0/0 IP ranges

#### Configuration

```yaml
action_condition_enforcement:
  enabled: true
  severity: high

  # Uses defaults from Python module by default
  # Or specify custom requirements:
  action_condition_requirements:
    - actions:
        - "iam:PassRole"
      severity: high
      required_conditions:
        - condition_key: "iam:PassedToService"
          description: "Restrict which services can assume the role"
```

See [Condition Requirements Guide](condition-requirements.md) for comprehensive examples.

---

## Ignore Patterns

All checks support ignore patterns for filtering specific findings:

```yaml
wildcard_action:
  ignore_patterns:
    # Ignore in test files
    - filepath: "^test/.*"

    # Ignore specific SID
    - sid: "AllowTerraformBackend"

    # Complex: file + action + resource
    - filepath: "terraform/.*"
      action: "s3:.*"
      resource: ".*-tfstate.*"

    # List of actions (any match = ignore)
    - action:
        - "^iam:PassRole$"
        - "^iam:CreateUser$"
        - "^iam:AttachUserPolicy$"

    # List with regex patterns
    - action:
        - "^s3:.*"        # All S3 actions
        - "^iam:Get.*"    # All IAM Get actions
        - "^ec2:Describe.*"  # All EC2 Describe actions
```

**Pattern Fields (ALL support single strings OR lists):**
- `filepath`: Match file path (regex) - aliases: `filepath_regex`
- `action`: Match action name (regex) - aliases: `action_matches`
- `resource`: Match resource ARN (regex) - aliases: `resource_matches`
- `sid`: Match statement SID (exact or regex) - aliases: `statement_sid`
- `condition_key`: Match condition key (regex) - aliases: `condition_key_matches`

**List Support (Works for ALL fields):**
Every field now supports lists of patterns for more concise configuration:
- Single string: `action: "^s3:.*"` (matches any S3 action)
- List: `action: ["^s3:GetObject$", "^s3:PutObject$"]` (matches either action)
- Any match in the list will trigger the ignore (OR logic)

**Additional Examples:**
```yaml
ignore_patterns:
  # filepath with list
  - filepath: ["^test/.*", "^examples/.*", "^sandbox/.*"]

  # sid with list (exact match or regex)
  - sid: ["AllowTestAccess", "AllowDevAccess", "Allow.*ReadOnly"]

  # resource with list
  - resource: ["arn:aws:s3:::.*-test-.*", "arn:aws:s3:::.*-dev-.*"]

  # condition_key with list
  - condition_key: ["aws:SourceIp", "aws:PrincipalOrgID"]
```

**Logic:**
- Multiple fields in ONE pattern = AND (all must match)
- Multiple items in ONE field list = OR (any match = ignore)
- Multiple patterns = OR (any pattern match = ignore)

---

## Check Configuration Strategies

### Development Environment
```yaml
# Relaxed for fast iteration
settings:
  fail_on_severity: [error, critical]

wildcard_action:
  severity: low  # Just warn

sensitive_action:
  enabled: false  # Too noisy in dev
```

### CI/CD Pipeline
```yaml
# Catch critical issues before merge
settings:
  fail_fast: true
  fail_on_severity: [error, critical, high]

wildcard_action:
  severity: high
  ignore_patterns:
    - filepath_regex: "^test/.*"
```

### Production
```yaml
# Maximum strictness
settings:
  fail_on_severity: [error, critical, high, medium]

wildcard_action:
  severity: critical  # Upgrade

sensitive_action:
  category_severities:
    priv_esc: critical
    credential_exposure: high
```

### Security Audit
```yaml
# Report everything
settings:
  fail_on_severity: [error, warning, critical, high, medium, low]

# All checks enabled with maximum severity
```

---

## Trust Policy Validation Check (1 check - Opt-in)

This check is **disabled by default** and must be explicitly enabled in your configuration.

### trust_policy_validation

**Purpose:** Validates trust policies (role assumption policies) for security best practices and action-principal coupling.

**Severity:** `high` (configurable)

**Disabled by Default:** This check must be explicitly enabled as it's specialized for trust policies.

**What it validates:**
- **Action-Principal Type Matching**: Ensures correct principal types for assume actions
  - `sts:AssumeRole` → Requires `AWS` or `Service` principals
  - `sts:AssumeRoleWithSAML` → Requires `Federated` principals (SAML provider)
  - `sts:AssumeRoleWithWebIdentity` → Requires `Federated` principals (OIDC provider)
- **Provider ARN Format**: Validates SAML and OIDC provider ARN formats
- **Required Conditions**: Enforces required conditions for federated access
  - SAML: Requires `SAML:aud` condition
  - OIDC: Requires provider-specific audience conditions (e.g., `*:aud`)

**Trust policies** are resource-based policies attached to IAM roles that control **who can assume the role** and under what conditions.

#### Configuration

```yaml
trust_policy_validation:
  enabled: true  # Must explicitly enable
  severity: high

  # Optional: Customize validation rules (uses defaults if not specified)
  validation_rules:
    sts:AssumeRole:
      allowed_principal_types: ["AWS", "Service"]
      description: "Standard role assumption"

    sts:AssumeRoleWithSAML:
      allowed_principal_types: ["Federated"]
      provider_pattern: "^arn:aws:iam::\\d{12}:saml-provider/[\\w+=,.@-]+$"
      required_conditions: ["SAML:aud"]
      description: "SAML-based federated role assumption"

    sts:AssumeRoleWithWebIdentity:
      allowed_principal_types: ["Federated"]
      provider_pattern: "^arn:aws:iam::\\d{12}:oidc-provider/[\\w./-]+$"
      required_conditions: ["*:aud"]  # Wildcard for provider-specific keys
      description: "OIDC-based federated role assumption"
```

#### Usage

**Always use with `--policy-type TRUST_POLICY` flag:**

```bash
# Enable trust policy validation
iam-validator validate trust-policy.json --policy-type TRUST_POLICY
```

The `--policy-type TRUST_POLICY` flag:
- ✅ Enables trust-specific validation (if check is enabled in config)
- ✅ Suppresses irrelevant warnings (missing Resource field)
- ✅ Provides clear, actionable error messages

#### Examples

❌ **FAIL: Wrong principal type for AssumeRoleWithSAML**

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {
      "AWS": "arn:aws:iam::123456789012:root"  // Should be Federated!
    },
    "Action": "sts:AssumeRoleWithSAML"
  }]
}
```

**Error:** `Action 'sts:AssumeRoleWithSAML' should not use Principal type 'AWS'. Expected principal types: 'Federated'`

**Fix:**

```json
{
  "Effect": "Allow",
  "Principal": {
    "Federated": "arn:aws:iam::123456789012:saml-provider/MyProvider"
  },
  "Action": "sts:AssumeRoleWithSAML",
  "Condition": {
    "StringEquals": {
      "SAML:aud": "https://signin.aws.amazon.com/saml"
    }
  }
}
```

❌ **FAIL: Missing required SAML:aud condition**

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {
      "Federated": "arn:aws:iam::123456789012:saml-provider/MyProvider"
    },
    "Action": "sts:AssumeRoleWithSAML"
    // Missing required condition!
  }]
}
```

**Error:** `Action 'sts:AssumeRoleWithSAML' is missing required conditions: 'SAML:aud'`

**Fix:** Add the required condition:

```json
{
  "Effect": "Allow",
  "Principal": {
    "Federated": "arn:aws:iam::123456789012:saml-provider/MyProvider"
  },
  "Action": "sts:AssumeRoleWithSAML",
  "Condition": {
    "StringEquals": {
      "SAML:aud": "https://signin.aws.amazon.com/saml"
    }
  }
}
```

❌ **FAIL: Invalid OIDC provider ARN format**

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {
      "Federated": "arn:aws:iam::123456789012:role/MyRole"  // Wrong! Should be oidc-provider
    },
    "Action": "sts:AssumeRoleWithWebIdentity"
  }]
}
```

**Error:** `Federated principal 'arn:aws:iam::123456789012:role/MyRole' does not match expected OIDC provider format`

**Fix:**

```json
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
      "token.actions.githubusercontent.com:sub": "repo:myorg/myrepo:*"
    }
  }
}
```

✅ **PASS: Valid AWS Service trust policy**

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

✅ **PASS: Valid cross-account trust with conditions**

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

✅ **PASS: Valid GitHub Actions OIDC trust**

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
        "token.actions.githubusercontent.com:sub": "repo:myorg/myrepo:*"
      }
    }
  }]
}
```

#### How It Complements Other Checks

Trust policy validation works alongside:

- **`principal_validation`** - Validates which principals are allowed/blocked (applies to all resource policies)
- **`trust_policy_validation`** - Validates action-principal coupling (specific to trust policies)
- **`action_condition_enforcement`** - Enforces required conditions for actions (applies to all policies)

All three checks work together without conflicts.

#### Common Trust Policy Patterns

**AWS Service Trust (Lambda, EC2, ECS):**

```json
{
  "Effect": "Allow",
  "Principal": {"Service": "lambda.amazonaws.com"},
  "Action": "sts:AssumeRole"
}
```

**Cross-Account Trust:**

```json
{
  "Effect": "Allow",
  "Principal": {"AWS": "arn:aws:iam::ACCOUNT-ID:root"},
  "Action": "sts:AssumeRole",
  "Condition": {
    "StringEquals": {"sts:ExternalId": "SECRET"}
  }
}
```

**SAML Federation:**

```json
{
  "Effect": "Allow",
  "Principal": {"Federated": "arn:aws:iam::ACCOUNT-ID:saml-provider/PROVIDER"},
  "Action": "sts:AssumeRoleWithSAML",
  "Condition": {
    "StringEquals": {"SAML:aud": "https://signin.aws.amazon.com/saml"}
  }
}
```

**OIDC Federation (GitHub Actions):**

```json
{
  "Effect": "Allow",
  "Principal": {"Federated": "arn:aws:iam::ACCOUNT-ID:oidc-provider/token.actions.githubusercontent.com"},
  "Action": "sts:AssumeRoleWithWebIdentity",
  "Condition": {
    "StringEquals": {"token.actions.githubusercontent.com:aud": "sts.amazonaws.com"},
    "StringLike": {"token.actions.githubusercontent.com:sub": "repo:org/repo:*"}
  }
}
```

#### See Also

- [Trust Policy Examples](../examples/trust-policies/README.md) - Complete trust policy examples
- [Principal Validation Check](#principal_validation) - Complementary principal validation
- [AWS Trust Policy Documentation](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_terms-and-concepts.html#iam-term-trust-policy)

---

## See Also

- [Configuration Guide](configuration.md) - Complete configuration reference
- [Condition Requirements](condition-requirements.md) - Action condition enforcement details
- [Privilege Escalation](privilege-escalation.md) - Detecting escalation paths
- [Example Configs](../examples/configs/README.md) - Ready-to-use configurations
- [Trust Policy Examples](../examples/trust-policies/README.md) - Trust policy validation examples
