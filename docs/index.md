---
title: IAM Policy Validator
description: Stop IAM misconfigurations before they become breaches
---

# IAM Policy Validator

**Stop IAM misconfigurations before they become breaches** — Catch overprivileged permissions, dangerous wildcards, and policy errors before deployment.

<div class="grid cards" markdown>

-   :material-rocket-launch:{ .lg .middle } **Get Started in 5 Minutes**

    ---

    Install with pip and validate your first policy

    [:octicons-arrow-right-24: Getting Started](getting-started/index.md)

-   :material-github:{ .lg .middle } **GitHub Actions Ready**

    ---

    Integrate into your CI/CD pipeline with our GitHub Action

    [:octicons-arrow-right-24: GitHub Actions](integrations/github-actions.md)

-   :material-shield-check:{ .lg .middle } **22 Built-in Checks**

    ---

    AWS validation, security best practices, and advanced enforcement

    [:octicons-arrow-right-24: Check Reference](user-guide/checks/index.md)

-   :material-code-braces:{ .lg .middle } **Python SDK**

    ---

    Programmatic validation in your Python applications

    [:octicons-arrow-right-24: SDK Documentation](developer-guide/sdk/index.md)

</div>

## Why This Tool?

Security teams need to **enforce organization-specific IAM requirements** and **catch dangerous patterns** before policies reach production. Manual review doesn't scale, and AWS's built-in validation only checks syntax, not security.

### Real Problems This Detects

| Problem                          | Example                                            | Impact                |
| -------------------------------- | -------------------------------------------------- | --------------------- |
| **Privilege escalation chains**  | Scattered actions that together grant admin access | Account compromise    |
| **Broken automation**            | `s3:GetObject` on bucket ARN instead of object ARN | Silent failures       |
| **Missing security controls**    | No MFA condition for sensitive actions             | Unauthorized access   |
| **Overly permissive access**     | Wildcard actions and resources                     | Data exposure         |
| **Trust policy vulnerabilities** | Missing OIDC audience, SAML misconfiguration       | Cross-account attacks |
| **Typos and invalid syntax**     | `s3:GetObjekt` instead of `s3:GetObject`           | Deployment failures   |

## Quick Install

=== "pip"

    ```bash
    pip install iam-policy-validator
    ```

=== "uv"

    ```bash
    uv add iam-policy-validator
    ```

=== "pipx"

    ```bash
    pipx install iam-policy-validator
    ```

## Quick Validation

```bash
# Validate a single policy
iam-validator validate --path policy.json

# Validate a directory
iam-validator validate --path ./policies/ --format enhanced

# With custom configuration
iam-validator validate --path ./policies/ --config iam-validator.yaml
```

## Example Output

```
╭──────────────────────────────────────────────────────────────────────────────────────────────────╮
│                                                                                                  │
│                                  IAM Policy Validation Report                                    │
│                                                                                                  │
╰──────────────────────────────────────────────────────────────────────────────────────────────────╯
───────────────────────────────────────── Detailed Results ─────────────────────────────────────────
❌ [1/3] examples/quick-start/user-policy.json • INVALID (IAM errors + security issues)
     2 issue(s) found

Issues (2)
├── 🔴 High
│   └── [Statement 2 @L10] missing_required_condition
│       └── Required: Action(s) `iam:PassRole` require condition `iam:PassedToService`
│           ├── Action: iam:PassRole • Condition: iam:PassedToService
│           └── 💡 Restrict which AWS services can assume the passed role to prevent privilege escalation
│               Example:
│               "Condition": {
│                 "StringEquals": {
│                   "iam:PassedToService": [
│                     "lambda.amazonaws.com",
│                     "ecs-tasks.amazonaws.com",
│                     "ec2.amazonaws.com",
│                     "glue.amazonaws.com"
│                   ]
│                 }
│               }
└── 🔴 Error
    └── [Statement 1 @L5] invalid_action
        └── Action `GetObjekt` not found in service `s3`.
            └── Action: s3:GetObjekt

❌ [2/3] examples/quick-start/s3-policy.json • FAILED (critical security issues)
     1 issue(s) found

Issues (1)
└── 🔴 High
    └── [Statement 1 @L5] missing_required_condition_any_of
        └── Actions `s3:GetObject` require at least ONE of these conditions: `aws:ResourceOrgID` OR
            `aws:ResourceOrgPaths` OR `aws:SourceIp` OR `aws:SourceVpc` OR `aws:SourceVpce` OR
            `aws:ResourceAccount`
            └── 💡 Add at least ONE of these conditions to restrict S3 operations
                [truncated...]

✅ [3/3] examples/quick-start/lambda-policy.json • VALID
     No issues detected

╭──────────────────────────────────────────────────────────────────────────────────────────────────╮
│                                                                                                  │
│  ❌ VALIDATION FAILED                                                                            │
│  2 of 3 policies have critical issues that must be resolved.                                     │
│                                                                                                  │
╰──────────────────────────────────────────────────────────────────────────────────────────────────╯
```

## GitHub Action

```yaml
- uses: boogy/iam-policy-validator@v1
  with:
    path: ./policies/
    fail-on-warnings: true
```

[:octicons-arrow-right-24: Full GitHub Actions Guide](integrations/github-actions.md)

## Features

- **21 Built-in Checks** — AWS validation, security best practices, privilege escalation detection
- **GitHub Action** — Native PR comments, review status, inline annotations
- **Python SDK** — Programmatic validation with async support
- **Custom Checks** — Write organization-specific validation rules
- **Multiple Formats** — Console, JSON, SARIF, HTML, CSV, Markdown
- **Offline Support** — Pre-download AWS service definitions
- **Trust Policies** — Validate IAM roles, OIDC providers, SAML federation

## Support

- [:fontawesome-brands-github: GitHub Issues](https://github.com/boogy/iam-policy-validator/issues) — Bug reports and feature requests
- [:fontawesome-brands-github: GitHub Discussions](https://github.com/boogy/iam-policy-validator/discussions) — Questions and community help
- [:material-file-document: Contributing Guide](contributing/index.md) — How to contribute
