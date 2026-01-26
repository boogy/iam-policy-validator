---
title: Validation Checks
description: All 19 built-in validation checks
---

# Validation Checks

IAM Policy Validator includes 19 built-in checks across three categories.

## Check Categories

<div class="grid cards" markdown>

-   :material-aws:{ .lg .middle } **AWS Validation (10)**

    ---

    Ensure policies comply with AWS IAM rules

    [:octicons-arrow-right-24: AWS Checks](aws-validation.md)

-   :material-shield-lock:{ .lg .middle } **Security Checks (6)**

    ---

    Detect security risks and best practice violations

    [:octicons-arrow-right-24: Security Checks](security-checks.md)

-   :material-cog-outline:{ .lg .middle } **Advanced Checks (3)**

    ---

    Condition enforcement and trust policy validation

    [:octicons-arrow-right-24: Advanced Checks](advanced-checks.md)

</div>

## Quick Reference

### AWS Validation Checks

| Check ID                    | Severity | Description                          |
| --------------------------- | -------- | ------------------------------------ |
| `action_validation`         | error    | Actions exist in AWS                 |
| `condition_key_validation`  | error    | Condition keys are valid             |
| `condition_type_mismatch`   | error    | Operator-value type match            |
| `resource_validation`       | error    | Resource ARN format                  |
| `policy_structure`          | error    | Required fields present              |
| `policy_size`               | error    | Character size limits                |
| `sid_uniqueness`            | warning  | Unique SIDs                          |
| `set_operator_validation`   | error    | ForAllValues/ForAnyValue usage       |
| `principal_validation`      | high     | Principal validation & confused deputy protection |
| `mfa_condition_antipattern` | warning  | MFA anti-patterns                    |

### Security Checks

| Check ID                  | Severity | Description                              |
| ------------------------- | -------- | ---------------------------------------- |
| `wildcard_action`         | medium   | `Action: "*"` detection                  |
| `wildcard_resource`       | medium   | `Resource: "*"` detection                |
| `full_wildcard`           | critical | Both Action and Resource wildcards       |
| `service_wildcard`        | high     | `s3:*` style wildcards                   |
| `sensitive_action`        | medium   | Privilege escalation actions             |
| `not_action_not_resource` | high     | Dangerous NotAction/NotResource patterns |

### Advanced Checks

| Check ID                       | Severity | Description                   |
| ------------------------------ | -------- | ----------------------------- |
| `action_condition_enforcement` | error    | Required conditions           |
| `action_resource_matching`     | medium   | Action-resource compatibility |
| `trust_policy_validation`      | high     | Trust policy structure        |

## Severity Levels

| Level        | Meaning                 | Default Action   |
| ------------ | ----------------------- | ---------------- |
| **critical** | Severe security risk    | Block deployment |
| **high**     | Security concern        | Fix before merge |
| **medium**   | Best practice violation | Address soon     |
| **low**      | Minor improvement       | Optional         |
| **error**    | AWS will reject policy  | Must fix         |
| **warning**  | Potential issue         | Review           |
| **info**     | Informational           | Optional         |

## Configuring Checks

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
full_wildcard:
  message: "Full wildcard violates SEC-001"
  suggestion: "Contact security team for approved patterns"
```
