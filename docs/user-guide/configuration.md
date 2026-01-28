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

## Environment Variables

The validator supports environment variables for configuration:

| Variable                         | Description                              | Example                          |
| -------------------------------- | ---------------------------------------- | -------------------------------- |
| `IAM_VALIDATOR_CONFIG`           | Path to configuration file               | `/etc/iam-validator/config.yaml` |
| `IAM_VALIDATOR_MCP_INSTRUCTIONS` | Custom instructions for MCP server       | `"Require MFA for all actions"`  |
| `AWS_REGION`                     | AWS region for Access Analyzer           | `us-east-1`                      |
| `AWS_PROFILE`                    | AWS profile for credentials              | `production`                     |

## Configuration Precedence

Configuration is applied in this order (later overrides earlier):

1. **Built-in defaults** (from Python modules)
2. **Configuration file** (YAML)
3. **Environment variables**
4. **CLI arguments** (highest priority)

## Complete Configuration Reference

### Global Settings

All settings under the `settings` key:

```yaml
settings:
  # Validation behavior
  fail_fast: false              # Stop on first error (default: false)
  parallel: true                # Enable parallel execution (default: true)
  max_workers: null             # Max concurrent workers (default: auto)

  # Failure criteria
  fail_on_severity:             # Severities that cause exit code 1
    - error                     # IAM validity errors
    - critical                  # Critical security issues
    - high                      # High severity security issues
    # - medium                  # Uncomment to fail on medium
    # - warning                 # Uncomment to fail on warnings

  # Output filtering
  hide_severities: null         # Hide these severities from output
                                # Example: [low, info]

  # AWS service definitions
  aws_services_dir: null        # Path to offline service definitions
  cache_enabled: true           # Cache AWS definitions (default: true)
  cache_ttl_hours: 168          # Cache TTL in hours (default: 7 days)

  # Template variable support
  allow_template_variables: true  # Support ${var.name} in ARNs

  # GitHub integration
  severity_labels:              # Map severities to PR labels
    error: "iam-validity-error"
    critical: "iam-security-critical"
    high: "iam-security-high"

  # Custom checks
  custom_checks_dir: null       # Auto-discover checks from directory

  # Ignore settings
  ignore_settings:
    enabled: true
    allowed_users: []           # Users allowed to add ignore comments
    post_denial_feedback: false # Post feedback on denied ignores

  # Documentation
  documentation:
    base_url: null              # Custom docs base URL
    include_aws_docs: true      # Include links to AWS docs
```

### Check Configuration

Each check can be configured at the top level using its `check_id`:

```yaml
# Common options for all checks
<check_id>:
  enabled: true                 # Enable/disable check (default: true)
  severity: medium              # Override default severity
  description: "Custom desc"    # Override description
  message: "Custom message"     # Override issue message
  suggestion: "How to fix"      # Override suggestion text
  hide_severities: [low]        # Per-check severity filtering

  # Ignore patterns (available for ALL checks)
  ignore_patterns:
    # Ignore by file path (regex)
    - filepath: "^test/.*"

    # Ignore by action (regex)
    - action: "^s3:Get.*"

    # Ignore by resource ARN (regex)
    - resource: "arn:aws:s3:::.*-test-.*"

    # Ignore by statement SID
    - sid: "AllowReadOnlyAccess"

    # Combine conditions (AND logic)
    - filepath: "^dev/.*"
      action: "^s3:.*"

    # Lists within patterns (OR logic)
    - filepath:
        - "^test/.*"
        - "^examples/.*"
```

### Built-in Checks

All 19 built-in checks with their default settings:

#### AWS Validation Checks

| Check ID                  | Default Severity | Description                                  |
| ------------------------- | ---------------- | -------------------------------------------- |
| `action_validation`       | error            | Actions exist in AWS services                |
| `condition_key_validation`| error            | Condition keys are valid for actions         |
| `condition_type_mismatch` | error            | Operator types match key types               |
| `resource_validation`     | error            | ARN format is valid                          |
| `principal_validation`    | high             | Principal format (resource policies)         |
| `policy_structure`        | error            | Required fields present, valid values        |
| `policy_size`             | error            | Policy doesn't exceed AWS size limits        |
| `sid_uniqueness`          | error            | SIDs are unique across statements            |
| `set_operator_validation` | error            | ForAllValues/ForAnyValue used correctly      |
| `mfa_condition_antipattern`| warning         | MFA anti-patterns detected                   |
| `trust_policy_validation` | high             | Trust policy validation                      |
| `action_resource_matching`| medium           | Actions match resource types                 |
| `policy_type_validation`  | error            | Policy matches declared type                 |

#### Security Best Practices Checks

| Check ID                     | Default Severity | Description                            |
| ---------------------------- | ---------------- | -------------------------------------- |
| `wildcard_action`            | medium           | `Action: "*"` detection                |
| `wildcard_resource`          | medium           | `Resource: "*"` detection              |
| `full_wildcard`              | critical         | `Action + Resource: "*"` (admin access)|
| `service_wildcard`           | high             | `s3:*` style wildcards                 |
| `sensitive_action`           | medium           | 490+ privilege escalation actions      |
| `action_condition_enforcement`| high            | Sensitive actions require conditions   |
| `not_action_not_resource`    | high             | Dangerous NotAction/NotResource        |

### Check-Specific Options

#### wildcard_resource

```yaml
wildcard_resource:
  enabled: true
  severity: medium
  # Actions allowed with Resource: "*"
  allowed_wildcards:
    - "ec2:Describe*"
    - "s3:List*"
    - "iam:Get*"
    - "cloudwatch:Get*"
```

#### service_wildcard

```yaml
service_wildcard:
  enabled: true
  severity: high
  # Services allowed to use wildcards
  allowed_services:
    - "logs"
    - "cloudwatch"
    - "xray"
```

#### sensitive_action

```yaml
sensitive_action:
  enabled: true
  severity: medium
  # Filter by category
  categories:
    - credential_exposure
    - priv_esc
    - data_access
    - resource_exposure
  # Category-specific severities
  category_severities:
    credential_exposure: high
    priv_esc: critical
```

#### action_condition_enforcement

```yaml
action_condition_enforcement:
  enabled: true
  severity: high
  # Custom requirements (see full-reference-config.yaml)
  requirements:
    - actions: ["iam:PassRole"]
      required_conditions:
        - condition_key: "iam:PassedToService"
          description: "Restrict which services can use the role"
```

#### principal_validation

```yaml
principal_validation:
  enabled: true
  severity: high
  block_wildcard_principal: false
  block_service_principal_wildcard: true
  blocked_principals: []
  allowed_principals: []
  allowed_service_principals:
    - "aws:*"
  # Condition requirements for principals
  principal_condition_requirements:
    - principals: ["*"]
      required_conditions:
        any_of:
          - condition_key: "aws:SourceArn"
          - condition_key: "aws:SourceAccount"
```

#### policy_size

```yaml
policy_size:
  enabled: true
  severity: error
  policy_type: "managed"  # managed, inline_user, inline_group, inline_role
  # Override default size limits
  size_limits:
    managed: 6144
    inline_user: 2048
    inline_group: 5120
    inline_role: 10240
```

## Full Reference

See [examples/configs/full-reference-config.yaml](https://github.com/boogy/iam-policy-validator/blob/main/examples/configs/full-reference-config.yaml) for all available options with detailed comments.
