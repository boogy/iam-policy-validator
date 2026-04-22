---
name: iam-policy-validator
description: Validate, analyze, and query AWS IAM policies using the iam-policy-validator CLI. Use this skill when the user asks to check, validate, lint, audit, or find security issues in IAM policies, trust policies, SCPs, RCPs, or resource policies; when they mention wildcard actions, privilege escalation, sensitive actions, confused deputy, or overly permissive policies; when they want to run AWS IAM Access Analyzer, generate a SARIF/Markdown/HTML report from policies, query which AWS actions or condition keys exist for a service, or post IAM findings to a GitHub PR. This is the CLI-based alternative to running the MCP server.
---

# IAM Policy Validator (CLI)

Use the `iam-validator` CLI to validate AWS IAM policies against 22 built-in checks (AWS correctness + security best practices) and to query AWS service definitions.

Home page: https://github.com/boogy/iam-policy-validator · Docs: https://boogy.github.io/iam-policy-validator/

## Installation

Preferred — run without installing:

```bash
uvx iam-policy-validator validate --path policy.json
```

Or install in the current project:

```bash
uv add iam-policy-validator       # uv
pip install iam-policy-validator  # pip
```

Verify:

```bash
iam-validator --version
```

Never install `iam-policy-validator[mcp]` for this skill — the MCP server is a separate usage path; this skill is CLI-only.

## Decision guide

Pick the right command from the user's intent:

| User asks                                                   | Command                             |
| ----------------------------------------------------------- | ----------------------------------- |
| "validate / check / lint / audit this policy"               | `iam-validator validate`            |
| "scan the whole policies directory"                         | `iam-validator validate --path DIR` |
| "what would AWS Access Analyzer say?"                       | `iam-validator analyze`             |
| "post these findings to the PR"                             | `iam-validator post-to-pr`          |
| "which S3 actions exist / what condition keys does X have?" | `iam-validator query`               |
| "pre-download AWS service definitions for offline / CI"     | `iam-validator sync-services`       |
| "clear / inspect the cache"                                 | `iam-validator cache`               |

Always run with `--help` when unsure of a flag: `iam-validator <subcommand> --help`.

## Core workflow — validate

```bash
# Single file, console output
iam-validator validate --path policy.json

# Directory, recursive (default). Non-zero exit on errors; add --fail-on-warnings for strict mode.
iam-validator validate --path ./policies/ --fail-on-warnings

# Different policy types
iam-validator validate --path trust.json --policy-type TRUST_POLICY
iam-validator validate --path scp.json   --policy-type SERVICE_CONTROL_POLICY
iam-validator validate --path rcp.json   --policy-type RESOURCE_CONTROL_POLICY

# Alternate output formats (see references/output-formats.md)
iam-validator validate --path policy.json --format sarif    --output results.sarif
iam-validator validate --path policy.json --format markdown --output report.md
iam-validator validate --path policy.json --format html     --output report.html

# With a config file (see references/configuration.md)
iam-validator validate --path ./policies/ --config iam-validator.yaml
```

Exit codes: `0` on success, non-zero when the validator hits errors. By default warnings do not fail the run — pass `--fail-on-warnings` to treat them as failures in CI.

## Policy types

Pass `--policy-type` when validating anything other than a standard identity policy:

- `IDENTITY_POLICY` (default) — user / role / group policies
- `RESOURCE_POLICY` — S3 bucket, SQS, SNS, KMS key policies
- `TRUST_POLICY` — IAM role trust (assume-role) policies
- `SERVICE_CONTROL_POLICY` — AWS Organizations SCP
- `RESOURCE_CONTROL_POLICY` — AWS Organizations RCP

If unsure, try running without the flag first — the validator auto-detects many cases and suggests the right one.

## Common recipes

**Find wildcards / full-admin policies**

Run `validate`; the `full_wildcard`, `wildcard_action`, `wildcard_resource`, and `service_wildcard` checks flag these by default.

**Check for privilege-escalation risks**

Run `validate`; the `sensitive_action` check flags 490+ privilege-escalation actions across 20+ risk categories.

**Trust policy + confused deputy audit**

```bash
iam-validator validate --path role-trust.json --policy-type TRUST_POLICY
```

The `trust_policy_validation` check flags missing `aws:SourceArn` / `aws:SourceAccount` on service principals.

**GitHub PR posting (from CI)**

Two paths:

```bash
# 1. One-shot: validate and post in a single invocation
iam-validator validate --path ./policies/ \
  --github-comment --github-review --github-summary

# 2. Two-phase: generate a JSON report, then post it
iam-validator validate --path ./policies/ --format json --output report.json
iam-validator post-to-pr --report report.json
```

Both require `GITHUB_TOKEN` and a PR context (standard in GitHub Actions).

**AWS Access Analyzer**

```bash
iam-validator analyze --path policy.json
```

Requires AWS credentials with `access-analyzer:ValidatePolicy` permission.

**Query the AWS service catalog (no policy file needed)**

`query` has three subcommands: `action`, `arn`, `condition`.

```bash
# List every action for a service
iam-validator query action --service s3

# Look up a single action (service prefix optional via --name)
iam-validator query action --name s3:GetObject
iam-validator query action --service s3 --name GetObject

# Expand a wildcard pattern
iam-validator query action --name "s3:Get*"

# ARN formats for a service's resource types
iam-validator query arn --service s3

# Condition keys for a service
iam-validator query condition --service s3
```

**Find actions that support a specific condition key**

Use this when the user asks "which S3 actions support `s3:ResourceAccount`?" or needs to scope a policy to actions that accept a given condition.

```bash
# All actions in a service that support the given condition key
iam-validator query action --service s3 --has-condition-key "s3:ResourceAccount"

# Narrow to a pattern within a service
iam-validator query action --name "s3:Get*" --has-condition-key "s3:ResourceAccount"

# Across services — use a global key like aws:SourceVpc
iam-validator query action --service ec2 --has-condition-key "aws:SourceVpc"

# Show the condition keys that each matching action supports
iam-validator query action --service s3 --name "Get*" --show-condition-keys

# Filter ARN resource types by supported condition key
iam-validator query arn --service s3 --has-condition-key "s3:ResourceAccount"

# Machine-readable output for scripting
iam-validator query action --service s3 --has-condition-key "s3:ResourceAccount" --output json
```

Condition keys can be service-scoped (`s3:ResourceAccount`, `kms:ViaService`) or global AWS keys (`aws:SourceVpc`, `aws:PrincipalOrgID`). Both work with `--has-condition-key`.

## References

For details, read only what's needed:

- [references/checks.md](references/checks.md) — the 22 built-in checks with IDs, categories, and severities
- [references/configuration.md](references/configuration.md) — YAML config (disabling checks, ignore patterns, severity overrides)
- [references/output-formats.md](references/output-formats.md) — console / json / markdown / sarif / csv / html / enhanced
- [references/troubleshooting.md](references/troubleshooting.md) — cache, offline mode, rate limits, common errors

When the user wants authoritative per-check detail beyond check IDs, point them at https://boogy.github.io/iam-policy-validator/user-guide/checks/ rather than inventing specifics.

## Guardrails

- Don't fabricate flag names — always verify with `iam-validator <cmd> --help` if uncertain.
- Don't claim a check catches something without looking at [references/checks.md](references/checks.md) or the live docs.
- When editing a user's policy based on findings, show them the finding first; don't silently rewrite.
- If the CLI isn't installed and installing would change the user's environment, ask first; prefer `uvx iam-policy-validator ...` to avoid installing globally.
