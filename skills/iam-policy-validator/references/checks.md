# Built-in Checks

22 checks run by default. Group them by intent when explaining findings to the user.

Authoritative per-check docs (risk, examples, remediation): https://boogy.github.io/iam-policy-validator/user-guide/checks/

## AWS correctness (policy will not behave as intended or AWS will reject it)

| Check ID                    | Severity | What it catches                                          |
| --------------------------- | -------- | -------------------------------------------------------- |
| `action_validation`         | error    | Actions that don't exist in AWS                          |
| `condition_key_validation`  | error    | Condition keys not valid for the action's service        |
| `condition_type_mismatch`   | error    | Operator/value type mismatch (e.g. `Bool` with a string) |
| `resource_validation`       | error    | Malformed ARN                                            |
| `policy_structure`          | error    | Missing required fields, invalid `Version`               |
| `policy_size`               | error    | Policy exceeds character limits (incl. SCP/RCP limits)   |
| `policy_type_validation`    | error    | Policy content doesn't match declared `--policy-type`    |
| `sid_uniqueness`            | warning  | Duplicate SIDs within a policy                           |
| `set_operator_validation`   | error    | `ForAllValues` / `ForAnyValue` misuse                    |
| `ifexists_condition_usage`  | warning  | `IfExists` suffix misuse                                 |
| `not_principal_validation`  | warning  | Risky `NotPrincipal` patterns                            |
| `principal_validation`      | high     | Malformed principals (resource/trust policies)           |
| `trust_policy_validation`   | high     | Trust-policy issues + confused deputy risk               |
| `action_resource_matching`  | medium   | Actions don't apply to the supplied resource type        |
| `mfa_condition_antipattern` | warning  | Common MFA condition anti-patterns                       |

## Security / best practice

| Check ID                       | Severity | What it catches                                          |
| ------------------------------ | -------- | -------------------------------------------------------- |
| `full_wildcard`                | critical | `Action: "*"` combined with `Resource: "*"`              |
| `wildcard_action`              | medium   | `Action: "*"`                                            |
| `wildcard_resource`            | medium   | `Resource: "*"`                                          |
| `service_wildcard`             | high     | Service-wide wildcards like `s3:*`                       |
| `sensitive_action`             | medium   | 490+ privilege-escalation actions across 20+ categories  |
| `not_action_not_resource`      | high     | Dangerous `NotAction` / `NotResource` patterns           |
| `action_condition_enforcement` | high     | Sensitive actions missing required conditions (e.g. MFA) |

Severities are defaults; users can override via the YAML config — see `references/configuration.md`.

## When the user asks about a specific concern

- "wildcards" → `full_wildcard`, `wildcard_action`, `wildcard_resource`, `service_wildcard`
- "privilege escalation" / "dangerous actions" → `sensitive_action`, `action_condition_enforcement`
- "trust policy" / "assume role" / "confused deputy" → `trust_policy_validation`
- "invalid / broken" → the `*_validation`, `policy_structure`, `policy_size`, `condition_type_mismatch` group
- "SCP" or "RCP" → set `--policy-type SERVICE_CONTROL_POLICY` / `RESOURCE_CONTROL_POLICY`; `policy_size` + `policy_type_validation` enforce the extra rules
