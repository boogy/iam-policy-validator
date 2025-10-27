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

## Best Practices

1. **Start Minimal**: Begin with a minimal config file that only overrides what you need
2. **Incremental Changes**: Add overrides incrementally as requirements evolve
3. **Document Overrides**: Add comments explaining why defaults are overridden
4. **Version Control**: Keep config files in version control
5. **Reference Defaults**: Check [defaults.py](../iam_validator/core/defaults.py) to see available options
6. **Customize Messages**: Tailor messages and suggestions to match your organization's security guidelines and terminology
