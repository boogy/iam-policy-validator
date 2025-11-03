# Configuration System

## Overview

The IAM Policy Validator uses a flexible configuration system that combines default configurations (defined in Python code) with user-provided YAML overrides. This ensures the tool works out-of-the-box while allowing full customization.

## How It Works

### Default Configuration

Default configurations are defined in Python code at [iam_validator/core/defaults.py](../iam_validator/core/defaults.py), which mirrors the example [default-config.yaml](../default-config.yaml) file. This ensures:
- The tool works out-of-the-box without requiring a config file
- Users only need to specify what they want to change
- Configuration is versioned with the code
- Defaults stay synchronized with the example YAML file

### User Configuration

Users can provide a YAML configuration file (e.g., `iam-validator.yaml`) to override defaults. The system uses **deep merge** logic:
- User settings take precedence over defaults
- Only specified values are overridden
- Unspecified settings retain their default values

## Examples

### Example 1: No Configuration File

```python
# No config file provided
config = ValidatorConfig()
# Result: All checks enabled with default settings
```

### Example 2: Disable One Check

```yaml
# iam-validator.yaml
policy_size_check:
  enabled: false
```

**Result:**
- `policy_size_check` is disabled
- All other checks remain enabled with default settings
- All settings retain default values

### Example 3: Override One Setting

```yaml
# iam-validator.yaml
settings:
  enable_builtin_checks: false
```

**Result:**
- All builtin checks are disabled
- All other settings retain defaults
- Individual check configs still exist in memory

### Example 4: Deep Nested Override

```yaml
# iam-validator.yaml
security_best_practices_check:
  wildcard_action_check:
    enabled: false
```

**Result:**
- `wildcard_action_check` sub-check is disabled
- `wildcard_resource_check` and other sub-checks remain enabled
- Parent `security_best_practices_check` remains enabled
- Default severity and other settings preserved

### Example 5: Multiple Overrides

```yaml
# iam-validator.yaml
settings:
  max_concurrent: 20  # Override default of 10

policy_size_check:
  severity: warning  # Override default of error

security_best_practices_check:
  severity: error  # Override default of warning
  wildcard_action_check:
    severity: critical  # Override sub-check severity
```

**Result:**
- `max_concurrent` changed to 20
- `policy_size_check` severity changed to warning
- `security_best_practices_check` severity changed to error
- `wildcard_action_check` severity changed to critical
- All other settings and checks retain defaults

## Configuration Loading

The configuration loader searches for config files in this order:

1. Explicit path (via `--config` flag)
2. Current directory (`iam-validator.yaml`, `.iam-validator.yaml`, etc.)
3. Parent directories (walking up to root)
4. User home directory

If no config file is found, the tool uses the built-in defaults.

## Disabling All Built-in Checks

To disable all built-in AWS validation checks (useful when using AWS Access Analyzer):

```yaml
settings:
  enable_builtin_checks: false
```

This is useful when you want to:
- Use only AWS Access Analyzer for IAM validation
- Run only custom business rule checks
- Reduce validation overhead

## Severity-Based Failure Control

The `fail_on_severity` setting controls which severity levels cause validation to fail and determines the GitHub review status:

### Configuration

```yaml
settings:
  # Severity levels that cause validation to fail
  # IAM Validity: error, warning, info
  # Security: critical, high, medium, low
  fail_on_severity:
    - error     # IAM policy validity errors
    - critical  # Critical security issues
    - high      # High security issues (optional)
    # - warning # IAM validity warnings (optional)
    # - medium  # Medium security issues (optional)
```

### Impact on Validation

**Exit Code:**
- If any issues match severities in `fail_on_severity` → Exit code 1 (failure)
- Otherwise → Exit code 0 (success)
- Note: `--fail-on-warnings` CLI flag overrides this to fail on all issues

**GitHub Review Status:**
- If any issues match severities in `fail_on_severity` → REQUEST_CHANGES
- Otherwise → COMMENT
- Only applies when using `--github-review` flag

### Common Configurations

**Strict (fail on everything):**
```yaml
fail_on_severity:
  - error
  - warning
  - info
  - critical
  - high
  - medium
  - low
```

**Moderate (default - fail on serious issues only):**
```yaml
fail_on_severity:
  - error      # IAM validity errors
  - critical   # Critical security issues
```

**Relaxed (only fail on IAM errors):**
```yaml
fail_on_severity:
  - error      # Only fail on IAM validity errors
```

**Security-focused (fail on all security issues):**
```yaml
fail_on_severity:
  - error
  - critical
  - high
  - medium
```

### Example: Customizing Review Behavior

```yaml
# Only REQUEST_CHANGES for critical issues
settings:
  fail_on_severity:
    - critical

# Result:
# - Critical issues → REQUEST_CHANGES (blocks PR)
# - High/Medium/Low issues → COMMENT (informational)
```

## Customizing Messages, Suggestions, and Examples

All security best practices sub-checks support customizable messages, suggestions, and code examples. This allows you to tailor the validation output to match your organization's terminology and guidelines.

### Available Message Fields

Each sub-check in `security_best_practices_check` supports:
- `message`: The issue description shown to users
- `suggestion`: **Text-only** remediation guidance explaining what to do
- `example`: **Code snippet** showing how to fix the issue

The `suggestion` and `example` fields are automatically combined in the output:
```
{suggestion}

Example:
{example}
```

Some sub-checks also support template placeholders:

#### Template Placeholders

**service_wildcard_check:**
- `{action}`: The wildcard action (e.g., "s3:*")
- `{service}`: The service name (e.g., "s3")

**sensitive_action_check:**
- `message_single`: Template for single action (supports `{action}`)
- `message_multiple`: Template for multiple actions (supports `{actions}`)

### Example: Custom Messages with Code Examples

```yaml
# iam-validator.yaml
security_best_practices_check:
  wildcard_action_check:
    message: "🚨 SECURITY ALERT: Wildcard actions detected!"
    suggestion: "Replace wildcard with specific actions needed for your use case"
    example: |
      Replace:
        "Action": ["*"]

      With specific actions:
        "Action": [
          "s3:GetObject",
          "s3:PutObject",
          "s3:ListBucket"
        ]

  sensitive_action_check:
    message_single: "⚡ Action '{action}' requires additional conditions"
    suggestion: "Add ABAC conditions to restrict access based on resource tags"
    example: |
      "Condition": {
        "StringEquals": {
          "aws:ResourceTag/owner": "${aws:PrincipalTag/owner}"
        }
      }
```

**Result:**
```
Issue: 🚨 SECURITY ALERT: Wildcard actions detected!
Suggestion: Replace wildcard with specific actions needed for your use case

Example:
Replace:
  "Action": ["*"]

With specific actions:
  "Action": [
    "s3:GetObject",
    "s3:PutObject",
    "s3:ListBucket"
  ]
```

### Default Messages and Examples

If you don't customize messages, the tool uses sensible defaults from [defaults.py](../iam_validator/core/defaults.py). Each check includes both a text suggestion and a code example:

| Sub-Check                 | Default Message                                                                                                                        | Default Suggestion                                                                                                        | Has Example                                     |
| ------------------------- | -------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------- |
| `wildcard_action_check`   | "Statement allows all actions (*)"                                                                                                     | "Replace wildcard with specific actions needed for your use case"                                                         | ✅ Shows before/after                            |
| `wildcard_resource_check` | "Statement applies to all resources (*)"                                                                                               | "Replace wildcard with specific resource ARNs"                                                                            | ✅ Shows before/after                            |
| `full_wildcard_check`     | "Statement allows all actions on all resources - CRITICAL SECURITY RISK"                                                               | "This grants full administrative access. Replace both wildcards..."                                                       | ✅ Shows before/after                            |
| `service_wildcard_check`  | "Service-level wildcard '{action}' grants all permissions for {service} service"                                                       | "Replace service-level wildcard with specific actions..."                                                                 | ✅ Shows before/after with {service} placeholder |
| `sensitive_action_check`  | Single: "Sensitive action '{action}' should have conditions..."<br>Multiple: "Sensitive actions '{actions}' should have conditions..." | "Add IAM conditions to limit when this action can be used. Consider: ABAC, IP restrictions, MFA, time-based restrictions" | ✅ Shows ABAC condition example                  |

## Principal Validation for Resource Policies

The `principal_validation_check` validates Principal elements in resource-based policies to enforce organizational security policies. This check only runs when `--policy-type RESOURCE_POLICY` is specified.

### Configuration

```yaml
principal_validation_check:
  enabled: true
  severity: high

  # Block dangerous principals
  blocked_principals:
    - "*"  # Public access
    - "arn:aws:iam::*:root"  # All AWS accounts

  # Whitelist mode (optional)
  allowed_principals:
    - "arn:aws:iam::123456789012:root"
    - "arn:aws:iam::123456789012:role/*"

  # Require conditions for specific principals
  require_conditions_for:
    "*":
      - "aws:SourceArn"
      - "aws:SourceAccount"
    "arn:aws:iam::*:root":
      - "aws:PrincipalOrgID"

  # Service principals whitelist
  allowed_service_principals:
    - "cloudfront.amazonaws.com"
    - "s3.amazonaws.com"
```

### Features

**1. Blocked Principals:**
Block dangerous principals that should never appear in your policies:
```yaml
blocked_principals:
  - "*"  # Block public access
  - "arn:aws:iam::*:root"  # Block all AWS accounts
```

**2. Allowed Principals (Whitelist Mode):**
When configured, ONLY these principals are allowed:
```yaml
allowed_principals:
  - "arn:aws:iam::123456789012:root"  # Specific account
  - "arn:aws:iam::123456789012:role/*"  # All roles in account
  - "arn:aws:iam::*:role/OrganizationAccountAccessRole"  # Specific role name
```

**3. Conditional Requirements:**
Require specific conditions for certain principals:
```yaml
require_conditions_for:
  "*":  # Public access must have these conditions
    - "aws:SourceArn"
    - "aws:SourceAccount"
  "arn:aws:iam::*:root":  # Cross-account access must have org ID
    - "aws:PrincipalOrgID"
```

**4. Service Principal Whitelist:**
AWS service principals that are always allowed:
```yaml
allowed_service_principals:
  - "cloudfront.amazonaws.com"
  - "s3.amazonaws.com"
  - "lambda.amazonaws.com"
```

### Use Cases

**Prevent Public Access:**
```yaml
blocked_principals:
  - "*"
```

**Organization-Only Access:**
```yaml
allowed_principals:
  - "arn:aws:iam::123456789012:*"  # Only my account
  - "arn:aws:iam::987654321098:*"  # Only partner account
```

**Conditional Public Access:**
```yaml
# Allow public access but require it to be limited
require_conditions_for:
  "*":
    - "aws:SourceArn"  # Must specify source resource
```

### Pattern Matching

All principal lists support fnmatch-style wildcards:
- `*` matches any characters
- `?` matches a single character
- `[abc]` matches any character in brackets

Examples:
- `arn:aws:iam::123456789012:*` - Any principal in account
- `arn:aws:iam::*:role/Admin*` - Any role starting with "Admin" in any account
- `*.amazonaws.com` - Any AWS service principal

## Best Practices

1. **Start Minimal**: Begin with a minimal config file that only overrides what you need
2. **Incremental Changes**: Add overrides incrementally as requirements evolve
3. **Document Overrides**: Add comments explaining why defaults are overridden
4. **Version Control**: Keep config files in version control
5. **Reference Defaults**: Check [defaults.py](../iam_validator/core/defaults.py) to see available options
6. **Customize Messages**: Tailor messages and suggestions to match your organization's security guidelines and terminology
7. **Principal Validation**: Use `principal_validation_check` to enforce organizational policies for resource-based policies
