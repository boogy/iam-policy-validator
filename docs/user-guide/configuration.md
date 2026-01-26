---
title: Configuration
description: Customize IAM Policy Validator behavior
---

# Configuration

IAM Policy Validator works with sensible defaults but supports full customization through YAML configuration files.

## Quick Start

No configuration needed! The validator works out-of-the-box.

To customize, create `iam-validator.yaml`:

```yaml
settings:
  fail_on_severity: [error, critical, high]

wildcard_action:
  severity: critical
```

## Configuration File Discovery

The validator automatically searches for configuration in this order:

1. `--config` flag (explicit path)
2. Current directory: `iam-validator.yaml`, `.iam-validator.yaml`
3. Parent directories (walks up to root)
4. Home directory

## Settings

### fail_on_severity

Control which severities cause validation failures:

```yaml
settings:
  fail_on_severity: [error, critical, high]
```

**Severity Levels:**

| Category     | Levels                              |
| ------------ | ----------------------------------- |
| IAM Validity | `error`, `warning`, `info`          |
| Security     | `critical`, `high`, `medium`, `low` |

### Presets

```yaml
# Strict - fail on everything
fail_on_severity: [error, warning, info, critical, high, medium, low]

# Default - serious issues only
fail_on_severity: [error, critical]

# Relaxed - IAM errors only
fail_on_severity: [error]
```

### hide_severities

Hide specific severity levels from all output to reduce noise:

```yaml
settings:
  # Hide low and info severity findings globally
  hide_severities: [low, info]
```

Hidden issues won't appear in:

- Console output
- JSON/SARIF reports
- GitHub PR comments
- Any other output format

**Per-check override:** You can also set `hide_severities` on individual checks to override the global setting:

```yaml
settings:
  hide_severities: [info] # Global: hide info

wildcard_resource:
  # Override: hide low severity for this check only
  # (useful when conditions reduce risk to LOW)
  hide_severities: [low]
```

## Check Configuration

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

### Custom Messages

```yaml
wildcard_action:
  message: "Wildcard actions violate security policy SEC-001"
  suggestion: |
    Replace with specific actions.
    Contact security@company.com for guidance.
```

## Action Condition Enforcement

Require specific conditions for sensitive actions:

```yaml
action_condition_enforcement:
  enabled: true
  action_condition_requirements:
    - actions: ["iam:PassRole"]
      required_conditions:
        - condition_key: "iam:PassedToService"
          description: "Restrict which services can assume the role"
```

## Principal Validation

For resource policies and trust policies, validate Principal elements:

```yaml
principal_validation:
  enabled: true

  # Block wildcard principal entirely (default: false)
  # When false: allows "*" if appropriate conditions are present
  # When true: blocks "*" regardless of conditions
  block_wildcard_principal: false

  # Block {"Service": "*"} patterns (default: true)
  # This is a dangerous pattern that allows ANY AWS service
  block_service_principal_wildcard: true

  # Explicit block list (evaluated after service principal wildcard check)
  blocked_principals:
    - "arn:aws:iam::*:root"

  # Whitelist mode (when set, only these principals are allowed)
  allowed_principals:
    - "arn:aws:iam::123456789012:*"

  # Service principals whitelist (supports glob patterns)
  allowed_service_principals:
    - "aws:*" # All AWS service principals
```

### Principal Condition Requirements

Require specific conditions when certain principals are used:

```yaml
principal_validation:
  principal_condition_requirements:
    # Require source verification for wildcard principals
    - principals: ["*"]
      required_conditions:
        any_of: # At least ONE must be present
          - condition_key: "aws:SourceArn"
          - condition_key: "aws:SourceAccount"

    # Require MFA for root account access
    - principals: ["arn:aws:iam::*:root"]
      required_conditions:
        all_of: # ALL must be present
          - condition_key: "aws:MultiFactorAuthPresent"
            expected_value: true

    # Forbid specific conditions
    - principals: ["*"]
      required_conditions:
        none_of: # NONE should be present
          - condition_key: "aws:SecureTransport"
            expected_value: false
```

### Use Cases

**Strict mode (block all wildcards):**

```yaml
principal_validation:
  block_wildcard_principal: true
  block_service_principal_wildcard: true
```

**Permissive mode (allow wildcards with conditions):**

```yaml
principal_validation:
  block_wildcard_principal: false
  principal_condition_requirements:
    - principals: ["*"]
      required_conditions:
        any_of:
          - condition_key: "aws:SourceArn"
          - condition_key: "aws:SourceAccount"
          - condition_key: "aws:PrincipalOrgID"
```

## Custom Checks

Load custom checks from a directory:

```yaml
settings:
  custom_checks_dir: "./my-checks"

checks:
  my_custom_check:
    enabled: true
    severity: high
```

## Full Reference

See [examples/configs/full-reference-config.yaml](https://github.com/boogy/iam-policy-validator/blob/main/examples/configs/full-reference-config.yaml) for all available options.
