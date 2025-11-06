# Configuration Guide

The IAM Policy Validator uses intelligent defaults while supporting full customization through YAML configuration files.

## Quick Start

**No configuration needed!** The validator works out-of-the-box with sensible defaults.

To customize, create `iam-validator.yaml` and override only what you need:

```yaml
settings:
  fail_on_severity: [error, critical, high]

wildcard_action:
  severity: critical
```

## How Configuration Works

### Default Behavior
- Built-in defaults defined in Python code ([full reference](../examples/configs/full-reference-config.yaml))
- 5-10x faster than YAML-only approach
- Zero configuration required to start

### YAML Overrides
- Create `iam-validator.yaml` in your project
- Override only specific settings you need
- Deep merge with defaults (unspecified settings unchanged)
- See [Modular Configuration](modular-configuration.md) for architecture details

## Configuration Examples

### Disable a Check

```yaml
policy_size:
  enabled: false
```

### Change Severity

```yaml
wildcard_action:
  severity: critical
```

### Configure Sub-Checks

```yaml
security_best_practices:
  wildcard_action_check:
    enabled: false
  wildcard_resource_check:
    severity: high
```

### Multiple Overrides

```yaml
settings:
  max_concurrent: 20
  fail_on_severity: [error, critical, high]

wildcard_action:
  severity: critical

wildcard_resource:
  severity: high
```

**Key Points:**
- Override only what you need
- Unspecified settings use defaults
- Deep merge preserves nested structures

## Configuration File Discovery

Auto-discovery search order:
1. `--config` flag (explicit path)
2. Current directory: `iam-validator.yaml`, `.iam-validator.yaml`
3. Parent directories (walks up to root)
4. Home directory

**Tip:** Place `iam-validator.yaml` in project root for automatic discovery.

## Disabling Built-in Checks

Disable all built-in checks to use only AWS Access Analyzer or custom checks:

```yaml
settings:
  enable_builtin_checks: false
```

## Severity Control

Configure which severities cause validation failures:

```yaml
settings:
  fail_on_severity: [error, critical, high]
```

**Severity Levels:**
- **IAM Validity:** `error`, `warning`, `info`
- **Security:** `critical`, `high`, `medium`, `low`

**Common Presets:**

```yaml
# Strict - Fail on everything
fail_on_severity: [error, warning, info, critical, high, medium, low]

# Default - Fail on serious issues
fail_on_severity: [error, critical]

# Relaxed - IAM errors only
fail_on_severity: [error]

# Security-focused
fail_on_severity: [error, critical, high, medium]
```

**Impact:**
- Exit code: 0 (success) or 1 (failure)
- GitHub review status: `COMMENT` or `REQUEST_CHANGES`
- Override with `--fail-on-warnings` flag

## Customizing Messages

Tailor validation messages to your organization's guidelines. Each check supports multiple message fields that control what users see when issues are detected.

### Message Field Reference

When configuring checks, you can customize these fields:

| Field         | Purpose                                      | When Shown                     | Audience                        |
| ------------- | -------------------------------------------- | ------------------------------ | ------------------------------- |
| `description` | Technical description of what the check does | Documentation, check listings  | Developers maintaining the tool |
| `message`     | Error/warning message when issue is detected | Validation reports, CLI output | End users fixing policies       |
| `suggestion`  | Guidance on how to fix or mitigate the issue | Validation reports             | Developers implementing fixes   |
| `example`     | Concrete code example showing before/after   | Validation reports             | Developers writing policy code  |

### Field Progression

The fields follow a natural progression from detection to resolution:

1. **`description`** - What the check does (internal/documentation)
2. **`message`** - What's wrong (alert the user)
3. **`suggestion`** - Why it's bad & how to approach fixing (advise)
4. **`example`** - Concrete fix with code (demonstrate)

### Example Configuration

```yaml
wildcard_action:
  enabled: true
  severity: critical
  description: "Checks for wildcard actions (*)"
  message: "Statement allows all actions (*) - violates least-privilege principle"
  suggestion: "Replace wildcard with specific actions needed for your use case. Review AWS documentation to identify minimal required permissions."
  example: |
    Replace:
      "Action": ["*"]

    With specific actions:
      "Action": ["s3:GetObject", "s3:PutObject", "s3:ListBucket"]

full_wildcard:
  enabled: true
  severity: critical
  description: "Checks for both action and resource wildcards together (critical risk)"
  message: "Statement allows all actions on all resources - CRITICAL SECURITY RISK"
  suggestion: |
    This grants full administrative access equivalent to AdministratorAccess policy.
    Replace both wildcards with specific actions and resources to follow least-privilege principle.
    Consider: What specific actions are needed? Which resources should be accessible?
  example: |
    Replace:
      "Action": "*",
      "Resource": "*"

    With specific values:
      "Action": [
        "s3:GetObject",
        "s3:PutObject"
      ],
      "Resource": [
        "arn:aws:s3:::my-bucket/*"
      ]
```

### Output Example

When a validation issue is found, the fields appear in reports like this:

```
❌ full_wildcard (CRITICAL)

Message:      Statement allows all actions on all resources - CRITICAL SECURITY RISK
Suggestion:   This grants full administrative access. Replace both wildcards with
              specific actions and resources to follow least-privilege principle

Example:
Replace:
  "Action": "*",
  "Resource": "*"

With specific values:
  "Action": [
    "s3:GetObject",
    "s3:PutObject"
  ],
  "Resource": [
    "arn:aws:s3:::my-bucket/*"
  ]
```

### Template Placeholders

Some checks support dynamic placeholders in messages that get replaced with actual values when issues are detected. This allows you to create flexible, context-aware validation messages.

#### Available Placeholders

**For `service_wildcard` check:**
- `{action}` - The specific wildcard action found (e.g., "s3:*")
- `{service}` - The service name extracted from the action (e.g., "s3")

Works in: `message`, `suggestion`, `example`

**For `sensitive_action` check:**
- `{action}` - Single sensitive action when only one is found (e.g., "iam:CreateRole")
- `{actions}` - Comma-separated list of sensitive actions when multiple are found (e.g., "iam:CreateRole', 'iam:PutUserPolicy")

Works in: `message_single`, `message_multiple`, `suggestion`, `example`

Note: `sensitive_action` uses special fields:
- `message_single` - Used when one sensitive action is detected
- `message_multiple` - Used when multiple sensitive actions are detected

#### Template Examples

**Service Wildcard with Templates:**
```yaml
service_wildcard:
  enabled: true
  severity: high
  message: "⚠️ Service wildcard '{action}' detected for {service} service"
  suggestion: |
    The wildcard '{action}' grants ALL permissions for the {service} service.
    This is overly permissive and violates least-privilege principle.

    Recommended actions:
    1. Review what specific {service} actions are actually needed
    2. Replace '{action}' with explicit action list
    3. If read-only access is sufficient, use '{service}:Get*' and '{service}:List*'
  example: |
    ❌ Avoid:
      "Action": ["{action}"]

    ✅ Better:
      "Action": [
        "{service}:GetObject",
        "{service}:ListBucket",
        "{service}:PutObject"
      ]

    ✅ Or use specific wildcards:
      "Action": [
        "{service}:Get*",
        "{service}:List*"
      ]
```

**Sensitive Action with Templates:**
```yaml
sensitive_action:
  enabled: true
  severity: medium
  # Single action message (uses {action})
  message_single: "🔐 Sensitive action '{action}' requires conditions"
  # Multiple actions message (uses {actions})
  message_multiple: "🔐 Sensitive actions '{actions}' require conditions"
  suggestion: |
    Sensitive actions should be restricted with IAM conditions.

    Consider adding conditions for:
    - ABAC: Match resource/request tags to principal tags
    - IP restrictions: Limit to corporate IP ranges
    - MFA: Require multi-factor authentication
    - Time-based: Restrict to business hours
  example: |
    Add a Condition block to your statement:

    "Condition": {
      "StringEquals": {
        "aws:ResourceTag/owner": "${aws:PrincipalTag/owner}"
      }
    }
```

#### Template Use Cases

**1. Organization-specific messaging:**
```yaml
service_wildcard:
  message: "Policy violates SEC-{service}-001: No service-level wildcards allowed"
  suggestion: |
    Per security policy SEC-{service}-001, the action '{action}' is not permitted.
    Contact security@company.com with your use case for guidance.
```

**2. Different severity levels:**
```yaml
service_wildcard:
  message: "Critical security violation: '{action}' grants excessive {service} permissions"
  suggestion: |
    The {service} service contains sensitive operations.
    Using '{action}' could allow unauthorized access to:
    - {service} data and configurations
    - Potential privilege escalation vectors

    This must be remediated before deployment.
```

**3. Contextual examples:**
```yaml
sensitive_action:
  example: |
    The detected action '{action}' should be constrained.

    Example for development environment:
    "Condition": {
      "StringEquals": {
        "aws:RequestTag/environment": "dev"
      }
    }

    Example for production environment:
    "Condition": {
      "Bool": {"aws:MultiFactorAuthPresent": "true"}
    }
```

#### Template Output Examples

When `s3:*` is detected, with the configuration above:

```
⚠️ Service wildcard 's3:*' detected for s3 service

Suggestion:
The wildcard 's3:*' grants ALL permissions for the s3 service.
This is overly permissive and violates least-privilege principle.

Recommended actions:
1. Review what specific s3 actions are actually needed
2. Replace 's3:*' with explicit action list
3. If read-only access is sufficient, use 's3:Get*' and 's3:List*'

Example:
❌ Avoid:
  "Action": ["s3:*"]

✅ Better:
  "Action": [
    "s3:GetObject",
    "s3:ListBucket",
    "s3:PutObject"
  ]

✅ Or use specific wildcards:
  "Action": [
    "s3:Get*",
    "s3:List*"
  ]
```

#### Important Notes

1. **Placeholder syntax**: Use Python string formatting syntax: `{placeholder_name}`
2. **Field support**: Not all fields support templates - check the check implementation
3. **Escaping braces**: To include literal braces, double them: `{{` for `{` and `}}` for `}`
4. **Case sensitivity**: Placeholder names are case-sensitive
5. **Missing values**: If a placeholder value is not available, the template rendering will fail with an error

### Best Practices for Custom Messages

1. **Be Specific**: Explain exactly what's wrong and why it's a security risk
2. **Provide Context**: Include organization-specific policies or compliance requirements
3. **Show Examples**: Always include concrete before/after code examples
4. **Be Actionable**: Give clear steps on how to fix the issue
5. **Use Multiline**: For longer messages, use YAML's `|` multiline syntax

```yaml
wildcard_action:
  message: "Wildcard actions violate our security policy SEC-001"
  suggestion: |
    Per company policy SEC-001, all IAM policies must follow least-privilege principle.

    Steps to fix:
    1. Review AWS service documentation for your use case
    2. Identify minimal required actions
    3. Replace wildcard with specific action list
    4. Test policy in non-production environment

    Contact security-team@company.com for assistance.
  example: |
    # Forbidden (too permissive)
    "Action": ["*"]

    # Allowed (specific actions only)
    "Action": [
      "s3:GetObject",
      "s3:PutObject",
      "s3:ListBucket"
    ]
```

### Field Availability by Check

Not all checks support all fields. Most common fields:

- ✅ `description` - Supported by all checks
- ✅ `severity` - Supported by all checks
- ✅ `enabled` - Supported by all checks
- ⚠️ `message` - Supported by most checks (wildcards, sensitive actions, etc.)
- ⚠️ `suggestion` - Supported by security checks
- ⚠️ `example` - Supported by security checks

**Default Messages:** See [defaults.py](../iam_validator/core/config/defaults.py) for all built-in messages and fields

## Principal Validation

For resource policies (`--policy-type RESOURCE_POLICY`), validate Principal elements:

### Simple Format (Backward Compatible)

```yaml
principal_validation:
  enabled: true
  severity: high

  # Block dangerous principals
  blocked_principals:
    - "*"
    - "arn:aws:iam::*:root"

  # Whitelist (optional)
  allowed_principals:
    - "arn:aws:iam::123456789012:*"

  # Require conditions (simple format)
  require_conditions_for:
    "*": ["aws:SourceArn", "aws:SourceAccount"]

  # Allow AWS services
  allowed_service_principals:
    - "cloudfront.amazonaws.com"
    - "s3.amazonaws.com"
```

### Advanced Format (Principal Condition Requirements)

Similar to `action_condition_enforcement` but for principals. Supports `all_of`, `any_of`, `none_of` logic with rich metadata:

```yaml
principal_validation:
  enabled: true
  severity: high

  # Advanced condition requirements
  principal_condition_requirements:
    # Public access with critical severity
    - principals:
        - "*"
      severity: critical  # Override global severity
      required_conditions:
        all_of:
          - condition_key: "aws:SourceArn"
            description: "Limit public access by source ARN"
            example: |
              "Condition": {
                "StringEquals": {
                  "aws:SourceArn": "arn:aws:sns:us-east-1:123456789012:my-topic"
                }
              }
          - condition_key: "aws:SourceAccount"
            description: "Limit public access by source account"

    # Cross-account with expected value validation
    - principals:
        - "arn:aws:iam::*:root"
      required_conditions:
        - condition_key: "aws:PrincipalOrgID"
          operator: "StringEquals"
          expected_value: "o-123456"
          description: "Must be from same organization"

    # IAM roles with any_of logic
    - principals:
        - "arn:aws:iam::*:role/*"
      required_conditions:
        any_of:
          - condition_key: "aws:MultiFactorAuthPresent"
            expected_value: true
          - condition_key: "aws:SourceVpce"

    # Prevent insecure transport (none_of)
    - principals:
        - "*"
      required_conditions:
        none_of:
          - condition_key: "aws:SecureTransport"
            expected_value: false
            description: "Never allow insecure transport"
```

**Supported Features:**
- `all_of` - ALL conditions must be present
- `any_of` - At least ONE condition must be present
- `none_of` - NONE of these conditions should be present
- `operator` - Validate specific condition operator (e.g., "IpAddress", "StringEquals")
- `expected_value` - Validate condition value matches expected value
- `severity` - Override severity per-requirement or per-condition
- `description` - Custom description for each condition
- `example` - Custom example for suggestions

**Common Patterns:**

```yaml
# Block public access
blocked_principals: ["*"]

# Organization-only
allowed_principals: ["arn:aws:iam::123456789012:*"]

# Conditional public access (simple)
require_conditions_for:
  "*": ["aws:SourceArn"]

# Conditional public access (advanced)
principal_condition_requirements:
  - principals: ["*"]
    severity: critical
    required_conditions:
      all_of:
        - condition_key: "aws:SourceArn"
        - condition_key: "aws:SourceAccount"

# MFA or VPC endpoint required for roles
principal_condition_requirements:
  - principals: ["arn:aws:iam::*:role/*"]
    required_conditions:
      any_of:
        - condition_key: "aws:MultiFactorAuthPresent"
          expected_value: true
        - condition_key: "aws:SourceVpce"
```

**Wildcard Support:** Patterns support `*`, `?`, `[abc]` matching

**See Also:**
- [Principal Condition Enforcement Example Config](../examples/configs/principal-condition-enforcement.yaml) - Complete examples
- [Action Condition Enforcement](#action-condition-enforcement) - Similar feature for actions

## Best Practices

- Start with minimal config - override only what you need
- Add comments to explain custom settings
- Keep configs in version control
- Reference [full-reference-config.yaml](../examples/configs/full-reference-config.yaml) for all options
- See [Modular Configuration](modular-configuration.md) for Python-based configuration
