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

## Best Practices

1. **Always use `all_of` for privilege escalation detection** - It scans the entire policy
2. **Combine multiple patterns** - Detect different escalation vectors
3. **Use patterns for flexibility** - Regex patterns catch variations
4. **Set severity to `error`** - Make CI/CD fail on privilege escalation risks
5. **Review suggestions carefully** - The tool shows exactly which statements contain the risky actions

## References

- [AWS IAM Privilege Escalation Methods](https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/)
- [IAM Privilege Escalation Techniques](https://bishopfox.com/blog/privilege-escalation-in-aws)
