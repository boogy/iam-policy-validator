# Configuration

Pass a YAML config with `--config iam-validator.yaml`, or let the validator auto-discover `iam-validator.yaml` / `.iam-validator.yaml` from the current directory upwards.

Authoritative reference (with every option): https://boogy.github.io/iam-policy-validator/user-guide/configuration/
Full annotated example: https://github.com/boogy/iam-policy-validator/blob/main/examples/configs/full-reference-config.yaml

## Schema at a glance

The top level has two kinds of keys:

1. `settings:` — global behavior (severity gating, cache, parallelism)
2. One key **per check ID** — each check's config lives at the top level (not nested under `checks:`)

```yaml
# Global behavior
settings:
  fail_on_severity: [error, critical, high]   # which severities fail the run
  hide_severities: [low, info]                # hide from all output
  parallel_execution: true
  cache_enabled: true
  cache_ttl_hours: 168                        # 7 days

# Each check is a top-level key
wildcard_action:
  enabled: true
  severity: high                              # override default (medium)
  message: "Wildcards violate SEC-001"        # custom message
  suggestion: "Use specific actions."         # custom remediation hint
  ignore_patterns:                            # per-check suppressions
    - filepath: "^tests/"
    - sid: "^AllowReadOnly"
    - action: "^s3:(Get|List|Describe).*"

sid_uniqueness:
  enabled: false                              # disable a check entirely

action_condition_enforcement:
  enabled: true
  action_condition_requirements:
    - actions: ["iam:PassRole"]
      required_conditions:
        - condition_key: "iam:PassedToService"
```

## Supported `ignore_patterns` fields

Each pattern object may combine any of (AND across fields, OR across list entries):

| Field           | Matches                                                  |
| --------------- | -------------------------------------------------------- |
| `filepath`      | Policy file path (regex, case-insensitive)               |
| `action`        | Action string in the finding                             |
| `resource`      | Resource ARN in the finding                              |
| `sid`           | Statement `Sid`                                          |
| `condition_key` | Condition key referenced by the finding                  |

## Precedence

CLI flags > environment variables > config file > built-in defaults.

CLI-level behavior such as `--path`, `--policy-type`, `--fail-on-warnings`, and `--aws-services-dir` lives on the command line, not in the YAML. Don't put them in the config.

## Sharing a config across repos

Vendor a `iam-validator.yaml` into each repo, or keep one in a shared location and point `--config /path/to/shared.yaml` at it. There is no implicit global (`~/.iam-validator.yaml`) — configs are explicit.
