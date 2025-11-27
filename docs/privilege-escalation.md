# Policy-Level Privilege Escalation Detection

This directory demonstrates the **policy-level privilege escalation detection** feature of the IAM Validator.

## What is Policy-Level Detection?

Traditional IAM policy validators check each statement individually. However, **privilege escalation often occurs when multiple actions are scattered across different statements** in the same policy.

### Example: The Problem

Consider this policy:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowCreateUser",
      "Effect": "Allow",
      "Action": "iam:CreateUser",
      "Resource": "*"
    },
    {
      "Sid": "AllowS3Read",
      "Effect": "Allow",
      "Action": ["s3:GetObject", "s3:ListBucket"],
      "Resource": "*"
    },
    {
      "Sid": "AllowAttachPolicy",
      "Effect": "Allow",
      "Action": "iam:AttachUserPolicy",
      "Resource": "*"
    }
  ]
}
```

**Individual statement checks would miss this!** Each statement looks innocent on its own:
- Statement 1: Just creates users
- Statement 2: Just reads S3 objects
- Statement 3: Just attaches policies

But **combined**, statements 1 and 3 allow privilege escalation:
1. Create a new IAM user
2. Attach AdministratorAccess policy to that user
3. Use the new admin user to take over the account

## How Policy-Level Detection Works

The IAM Validator now scans **the entire policy** to detect dangerous action combinations using `all_of` logic:

```yaml
checks:
  security_best_practices:
    enabled: true
    sensitive_action_check:
      enabled: true
      severity: error

      # Detect privilege escalation patterns ACROSS statements
      sensitive_actions:
        # Pattern 1: User privilege escalation
        - all_of:
            - "iam:CreateUser"
            - "iam:AttachUserPolicy"

        # Pattern 2: Role privilege escalation
        - all_of:
            - "iam:CreateRole"
            - "iam:AttachRolePolicy"

        # Pattern 3: Lambda backdoor
        - all_of:
            - "lambda:CreateFunction"
            - "iam:PassRole"
```

## Test Files

### `privilege_escalation_scattered.json`
Example policy with privilege escalation actions scattered across statements.

### `config-privilege-escalation.yaml`
Configuration file that enables policy-level privilege escalation detection.

## Running the Tests

```bash
# Test with the example policy
iam-validator validate \
  --path examples/iam-test-policies/privilege_escalation_scattered.json \
  --config examples/configs/strict-security.yaml
```

**Expected output:**
```
ERROR: Policy-level privilege escalation detected: grants all of
['iam:CreateUser', 'iam:AttachUserPolicy'] across multiple statements

Actions found in:
  - Statement 'AllowCreateUser': iam:CreateUser
  - Statement 'AllowAttachPolicy': iam:AttachUserPolicy
```

## Configuration Options

### Statement-Level vs Policy-Level Checks

- **`any_of`** logic: Checks **per-statement** (traditional behavior)
- **`all_of`** logic: Checks **across entire policy** (detects scattered actions)

### Example Configurations

#### Detect Multiple Escalation Patterns

```yaml
sensitive_actions:
  # User privilege escalation
  - all_of:
      - "iam:CreateUser"
      - "iam:AttachUserPolicy"

  # Role privilege escalation
  - all_of:
      - "iam:CreateRole"
      - "iam:AttachRolePolicy"

  # Lambda code injection
  - all_of:
      - "lambda:CreateFunction"
      - "iam:PassRole"
```

#### Using Regex Patterns

```yaml
sensitive_action_patterns:
  # Any IAM Create + Attach combination
  - all_of:
      - "^iam:Create.*"
      - "^iam:Attach.*"
```

#### Mixed Statement and Policy Level

```yaml
sensitive_actions:
  # Policy-level (all_of)
  - all_of:
      - "iam:CreateUser"
      - "iam:AttachUserPolicy"

  # Statement-level (simple string)
  - "s3:DeleteBucket"

  # Statement-level (any_of)
  - any_of:
      - "lambda:CreateFunction"
      - "lambda:UpdateFunctionCode"
```

## Common Privilege Escalation Patterns

### IAM User Escalation
```yaml
- all_of:
    - "iam:CreateUser"
    - "iam:AttachUserPolicy"
```

### IAM Role Escalation
```yaml
- all_of:
    - "iam:CreateRole"
    - "iam:AttachRolePolicy"
```

### Lambda Backdoor
```yaml
- all_of:
    - "lambda:CreateFunction"
    - "iam:PassRole"
```

### EC2 Instance Privilege Escalation
```yaml
- all_of:
    - "ec2:RunInstances"
    - "iam:PassRole"
```

### Policy Modification
```yaml
- all_of:
    - "iam:CreatePolicyVersion"
    - "iam:SetDefaultPolicyVersion"
```

## Filtering with ignore_patterns

You can selectively disable specific privilege escalation patterns using `ignore_patterns`. This is useful when you want to:

- Handle certain actions with custom condition requirements instead
- Exclude specific actions from escalation detection while keeping defaults for others

### Using ignore_patterns with Privilege Escalation

The `ignore_patterns` in `sensitive_action` check filter actions **before** privilege escalation detection runs. If any action in an `all_of` pattern is filtered out, the pattern won't trigger.

```yaml
sensitive_action:
  enabled: true
  # Keep default privilege escalation patterns enabled
  # But selectively disable specific actions
  ignore_patterns:
    - action:
        - "^iam:PassRole$"           # Handled by action_condition_enforcement
        - "^iam:CreateUser$"         # Handled by custom requirements
        - "^iam:AttachUserPolicy$"   # Handled by custom requirements
```

**How it works:**

| Default Pattern | ignore_patterns | Result |
|-----------------|-----------------|--------|
| `iam:CreateUser` + `iam:AttachUserPolicy` | `^iam:CreateUser$` | ✅ Pattern disabled (CreateUser filtered) |
| `iam:CreateRole` + `iam:AttachRolePolicy` | `^iam:CreateUser$` | ❌ Pattern still triggers |
| `ec2:RunInstances` + `iam:PassRole` | `^iam:PassRole$` | ✅ Pattern disabled (PassRole filtered) |

### Combining with action_condition_enforcement

A common pattern is to disable privilege escalation detection for specific actions and instead enforce custom conditions:

```yaml
# 1. Disable specific actions from privilege escalation detection
sensitive_action:
  enabled: true
  ignore_patterns:
    - action:
        - "^iam:PassRole$"
        - "^iam:Create(Role|User)$"
        - "^iam:Attach(Role|User)Policy$"

# 2. Enforce specific conditions on those actions instead
action_condition_enforcement:
  enabled: true
  merge_strategy: "user_only"  # Use only custom requirements
  action_condition_requirements:
    - actions:
        - "iam:PassRole"
      required_conditions:
        - condition_key: "iam:PassedToService"
          description: "Restrict which services can assume the role"

    - actions:
        - "iam:CreateRole"
        - "iam:AttachRolePolicy"
      required_conditions:
        - condition_key: "iam:PermissionsBoundary"
          description: "Require permission boundary"
```

This approach gives you:

- **Fine-grained control**: Custom condition requirements per action
- **No duplicate warnings**: Actions handled by one check, not both
- **Flexibility**: Keep defaults for some patterns, customize others

### Using merge_strategy

Alternatively, use `merge_strategy: "user_only"` to completely disable all default privilege escalation patterns:

```yaml
sensitive_action:
  enabled: true
  merge_strategy: "user_only"  # Disable ALL default privilege_escalation patterns
  # Define your own patterns if needed:
  sensitive_actions:
    - all_of:
        - "lambda:CreateFunction"
        - "lambda:InvokeFunction"
```

**merge_strategy options:**

| Strategy | Behavior |
|----------|----------|
| `append` (default) | Both defaults and user patterns apply |
| `user_only` | Disable ALL defaults, use only user patterns |
| `defaults_only` | Ignore user patterns, use only defaults |
| `replace_all` | User patterns replace defaults if provided |

## Best Practices

1. **Always use `all_of` for privilege escalation detection** - It scans the entire policy
2. **Combine multiple patterns** - Detect different escalation vectors
3. **Use patterns for flexibility** - Regex patterns catch variations
4. **Set severity to `error`** - Make CI/CD fail on privilege escalation risks
5. **Review suggestions carefully** - The tool shows exactly which statements contain the risky actions
6. **Use ignore_patterns for custom handling** - Filter actions you want to enforce with specific conditions
7. **Prefer ignore_patterns over merge_strategy** - More granular control than disabling all defaults

## References

- [AWS IAM Privilege Escalation Methods](https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/)
- [IAM Privilege Escalation Techniques](https://bishopfox.com/blog/privilege-escalation-in-aws)
