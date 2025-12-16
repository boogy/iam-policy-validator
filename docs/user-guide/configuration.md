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

| Category | Levels |
|----------|--------|
| IAM Validity | `error`, `warning`, `info` |
| Security | `critical`, `high`, `medium`, `low` |

### Presets

```yaml
# Strict - fail on everything
fail_on_severity: [error, warning, info, critical, high, medium, low]

# Default - serious issues only
fail_on_severity: [error, critical]

# Relaxed - IAM errors only
fail_on_severity: [error]
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

For resource policies, validate Principal elements:

```yaml
principal_validation:
  enabled: true
  blocked_principals:
    - "*"
    - "arn:aws:iam::*:root"
  allowed_principals:
    - "arn:aws:iam::123456789012:*"
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
