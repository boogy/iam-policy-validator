# IAM Policy Validator

**Stop IAM misconfigurations before they become breaches** — Catch overprivileged permissions, dangerous wildcards, and policy errors before deployment.

[![GitHub Actions](https://img.shields.io/badge/GitHub%20Actions-Ready-blue)](https://github.com/marketplace/actions/iam-policy-validator)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/boogy/iam-policy-validator/badge)](https://scorecard.dev/viewer/?uri=github.com/boogy/iam-policy-validator)

**[Full Documentation](https://boogy.github.io/iam-policy-validator/)**

---

## Table of Contents

- [Why This Tool Exists](#why-this-tool-exists)
- [Quick Start](#quick-start)
- [What Makes This Different](#what-makes-this-different)
- [What Does It Check?](#what-does-it-check)
- [Installation & Usage](#installation--usage)
- [MCP Server](#mcp-server)
- [AWS Access Analyzer (Optional)](#aws-access-analyzer-optional)
- [Comparison with Other Tools](#comparison-with-other-tools)
- [Documentation](#documentation)
- [Contributing](#contributing)
- [License](#license)

---

## Why This Tool Exists

Security teams need to **enforce organization-specific IAM requirements** and **catch dangerous patterns** before policies reach production. Manual review doesn't scale, and AWS's built-in validation in IAM console only checks more syntax and less security.

**Real problems this detects:**

1. **Privilege escalation chains** - Scattered actions that together grant admin access
2. **Broken automation** - Syntactically valid but functionally wrong policies (`s3:GetObject` on bucket ARN)
3. **Missing security controls** - No IAM conditions for sensitive AWS API actions
4. **Overly permissive access** - Wildcard actions and resources that violate least privilege
5. **Trust policy vulnerabilities** - Confused deputy risks, incorrect principals, missing OIDC audience, SAML misconfiguration
6. **Typos and invalid syntax** - Invalid actions (`s3:GetObjekt`), condition keys, or ARN formats before deployment
7. **Your own detection** - Set custom configuration file for custom detections

---

## Quick Start

```bash
pip install iam-policy-validator

# Try it with the example policies (from repository root)
iam-validator validate --path examples/quick-start/ --format enhanced
```

<details>
<summary>See the example policies used (examples/quick-start/)</summary>

**user-policy.json** - Contains typo and missing condition:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "s3:GetObjekt",
      "Resource": "arn:aws:s3:::my-bucket/*"
    },
    {
      "Effect": "Allow",
      "Action": "iam:PassRole",
      "Resource": "arn:aws:iam::123456789012:role/lambda-role"
    }
  ]
}
```

**s3-policy.json** - Sensitive action without conditions:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::my-bucket/*"
    }
  ]
}
```

**lambda-policy.json** - Valid policy:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "lambda:InvokeFunction",
      "Resource": "arn:aws:lambda:us-east-1:123456789012:function:my-function"
    }
  ]
}
```

</details>

<details>
<summary>See the example output</summary>

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

</details>

---

## What Makes This Different

### 1. Enforce Your Organization's Security Rules

Define security requirements as code -- the validator becomes your organization's policy gatekeeper:

```yaml
# .iam-validator.yaml - Your security requirements as code
action_condition_enforcement:
  enabled: true
  action_condition_requirements:
    # Require service-specific PassRole
    - actions: ["iam:PassRole"]
      required_conditions:
        - condition_key: "iam:PassedToService"
          description: "Restrict which services can use passed roles"

    # Enforce IP restrictions for privileged actions (automation from CI/CD)
    - actions:
        ["iam:AttachUserPolicy", "iam:PutUserPolicy", "iam:CreateAccessKey"]
      required_conditions:
        - condition_key: "aws:SourceIp"
          expected_value: ["10.0.0.0/8", "172.16.0.0/12"]
          description: "Only allow from corporate network or CI/CD"

    # Require encryption for S3 uploads
    - actions: ["s3:PutObject"]
      required_conditions:
        - condition_key: "s3:x-amz-server-side-encryption"
          operator: "StringEquals"
          expected_value: "AES256"

    # Enforce tagging requirements
    - actions: ["ec2:RunInstances"]
      required_conditions:
        all_of:
          - condition_key: "aws:RequestTag/CostCenter"
          - condition_key: "aws:RequestTag/Environment"
          - condition_key: "aws:RequestTag/Owner"
```

**Why this matters:** Other tools perform AWS-standard security checks but lack the flexibility to codify your organization's specific security requirements (IP restrictions, tagging mandates, encryption requirements, etc.).

---

### 2. Detect Cross-Statement Privilege Escalation

Privilege escalation often occurs when multiple actions are scattered across different statements. This validator uses `all_of` logic to detect when ALL actions in a dangerous combination exist somewhere in the policy:

```json
{
  "Statement": [
    {
      "Sid": "AllowUserManagement",
      "Action": "iam:CreateUser",
      "Resource": "*"
    },
    { "Sid": "AllowS3Read", "Action": "s3:GetObject", "Resource": "*" },
    {
      "Sid": "AllowPolicyAttachment",
      "Action": "iam:AttachUserPolicy",
      "Resource": "*"
    }
  ]
}
```

**Detected:** Statements 1 and 3 enable privilege escalation -- create a new IAM user, attach `AdministratorAccess`, and escalate to full account access.

**Built-in escalation patterns** (enabled by default):

- User privilege escalation (`iam:CreateUser` + `iam:AttachUserPolicy`)
- Role privilege escalation (`iam:CreateRole` + `iam:AttachRolePolicy`)
- Lambda function backdoor (`lambda:CreateFunction` + `lambda:InvokeFunction`)
- Lambda code injection (`lambda:UpdateFunctionCode` + `lambda:InvokeFunction`)
- Policy version manipulation (`iam:CreatePolicyVersion` + `iam:SetDefaultPolicyVersion`)
- EC2 instance privilege escalation (`ec2:RunInstances` + `iam:PassRole`)

Additionally detects **[hundreds of sensitive actions](iam_validator/core/config/sensitive_actions.py)** across 4 categories (credential exposure, data access, privilege escalation, resource exposure) that should have IAM conditions.
List of actions copied from [primeharbor/sensitive_iam_actions](https://github.com/primeharbor/sensitive_iam_actions).

See [Security Checks Documentation](https://boogy.github.io/iam-policy-validator/user-guide/checks/security-checks/) for all built-in patterns and custom configuration.

---

### 3. Catch Functionally Broken Policies

Validates that actions and resources are **compatible** -- catches policies that pass AWS validation but fail at runtime:

```json
{
  "Effect": "Allow",
  "Action": "s3:GetObject",
  "Resource": "arn:aws:s3:::mybucket"
}
```

**Detected:** `s3:GetObject` operates on **objects**, not buckets. This policy does nothing.
**Fix:** `"Resource": "arn:aws:s3:::mybucket/*"`

More action-resource mismatches this catches:

| Broken Policy                                                  | Problem                                             | Fix                   |
| -------------------------------------------------------------- | --------------------------------------------------- | --------------------- |
| `s3:ListBucket` with `arn:aws:s3:::bucket/*`                   | `ListBucket` needs a bucket ARN, not an object ARN  | `arn:aws:s3:::bucket` |
| `iam:ListUsers` with `arn:aws:iam::*:user/bob`                 | `ListUsers` is global, needs wildcard               | `*`                   |
| `ec2:DescribeInstances` with `arn:aws:ec2:*:*:instance/i-1234` | Describe actions don't support resource-level perms | `*`                   |

**Why this matters:** These policies look correct but fail silently in production. AWS validates syntax, not action-resource compatibility.

---

### 4. Uses Official AWS Service Definitions

Fetches **real AWS service data** from AWS's official IAM service definition API (JSON endpoint) -- always accurate and up-to-date:

- **Actions**: Validates against 250+ AWS services with complete action lists
- **Condition keys**: Checks valid keys for each action
- **Resource types**: Validates ARN formats and resource compatibility
- **Auto-updating**: Fetches latest definitions on-demand or use cached versions

```bash
# Query AWS service definitions (like Policy Sentry)
iam-validator query action --service s3 --access-level write
iam-validator query condition --service s3 --name s3:prefix
iam-validator query arn --service lambda --name function

# Download for offline use
iam-validator sync-services --output-dir ./aws-services
iam-validator validate --path policies/ --aws-services-dir ./aws-services
```

---

### 5. Built for CI/CD and Developer Workflows

**GitHub PR Integration:**

- **Diff-aware filtering**: Only comments on lines you actually changed
- **Line-specific feedback**: Inline comments on policy files with exact line numbers
- **Smart cleanup**: Updates existing comments, removes stale ones
- **Severity-based reviews**: Auto-approve or request changes based on findings

**Multiple output formats:** Console, JSON, SARIF (GitHub Code Scanning), Markdown, HTML, CSV

**Example GitHub Action:**

```yaml
- uses: boogy/iam-policy-validator@v1
  with:
    path: policies/
    create-review: true # Inline PR comments
    github-summary: true # Actions summary tab
    fail-on-warnings: true # Block merge on warnings too
```

---

## What Does It Check?

### AWS Correctness (14 checks)

Validates against official AWS IAM requirements:

| Check                        | What It Does                                                                               |
| ---------------------------- | ------------------------------------------------------------------------------------------ |
| **Policy Structure**         | Required fields (Version, Statement, Effect), valid JSON/YAML, outdated version warnings   |
| **Action Validation**        | Actions exist in AWS services (detects typos: `s3:GetObjekt`)                              |
| **Condition Keys**           | Valid condition keys for actions (e.g., `s3:prefix` valid for `s3:ListBucket`)             |
| **Condition Types**          | Operator-value type matching (IP/CIDR format, ARN format, Bool values, type compatibility) |
| **IfExists Validation**      | Validates proper usage of `IfExists` suffix on condition operators                         |
| **Resource ARNs**            | Correct ARN format and patterns                                                            |
| **Principal Validation**     | Valid principals in resource/trust policies                                                |
| **NotPrincipal Validation**  | Detects unsupported `NotPrincipal`+`Allow` and deprecated `NotPrincipal` usage patterns    |
| **Policy Size**              | AWS limits (6144 bytes managed, 10240 inline, 20480 resource, 5120 SCP)                    |
| **SID Uniqueness**           | Statement IDs unique within policy                                                         |
| **Set Operators**            | Correct `ForAllValues`/`ForAnyValue` usage with arrays                                     |
| **MFA Conditions**           | Detect insecure MFA patterns (`!= false` instead of `== true`)                             |
| **Policy Type**              | RCP/SCP-specific requirements (size limits, Principal/NotPrincipal restrictions)           |
| **Action-Resource Matching** | Actions compatible with resources (catches functional errors)                              |

### Security Best Practices (7 checks)

Identifies overly permissive configurations:

| Check                     | What It Catches                                                   |
| ------------------------- | ----------------------------------------------------------------- |
| **Wildcard Action**       | `Action: "*"` grants all AWS permissions                          |
| **Wildcard Resource**     | `Resource: "*"` applies to all resources                          |
| **Full Wildcard**         | Both `Action: "*"` AND `Resource: "*"` (admin access)             |
| **Service Wildcards**     | `s3:*`, `iam:*`, `ec2:*` (overly broad)                           |
| **NotAction/NotResource** | Dangerous `NotAction`/`NotResource` patterns with implicit grants |
| **Sensitive Actions**     | 490+ privilege escalation patterns and dangerous actions          |
| **Condition Enforcement** | Organization-specific condition requirements                      |

**Note on Sensitive Actions:** This check has two modes:

- `all_of`: **Policy-wide** detection (e.g., `iam:CreateUser` in statement 0 + `iam:AttachUserPolicy` in statement 2)
- `any_of`: **Per-statement** detection (e.g., any statement with `iam:PutUserPolicy`)

### Trust Policy Validation (opt-in)

Specialized checks for role assumption:

- **Confused deputy detection** -- flags service principals (e.g., `sns.amazonaws.com`) without `aws:SourceArn`/`aws:SourceAccount` conditions, with a curated safe-service list verified against AWS documentation
- Correct principal types (`AssumeRoleWithSAML` needs `Federated` principal)
- SAML/OIDC provider ARN validation
- Required conditions (`SAML:aud`, OIDC audience)
- Federated identity best practices

---

## Installation & Usage

### CLI

```bash
pip install iam-policy-validator

# Validate (no AWS credentials needed)
iam-validator validate --path policies/

# With AWS Access Analyzer (requires AWS credentials)
iam-validator analyze --path policies/ --run-all-checks

# Different policy types
iam-validator validate --path trust-policies/ --policy-type TRUST_POLICY

# Output formats
iam-validator validate --path policies/ --format json --output report.json
iam-validator validate --path policies/ --format sarif --output code-scanning.sarif
```

### Python Library

```python
from iam_validator.sdk import validate_file, validate_directory, quick_validate

# Validate a single file
result = await validate_file("policy.json")
for issue in result.issues:
    print(f"{issue.severity}: {issue.message} at line {issue.line_number}")

# Validate a directory
results = await validate_directory("./policies")
for result in results:
    if not result.is_valid:
        print(f"{result.file_path}: {len(result.issues)} issues")

# Quick one-liner validation
issues = await quick_validate("policy.json")
```

See the [Python Library Guide](https://boogy.github.io/iam-policy-validator/developer-guide/sdk/) for the full SDK reference.

### Configuration

All checks are customizable via `.iam-validator.yaml`:

```yaml
settings:
  enable_builtin_checks: true
  fail_on_severity: high

# Detect cross-statement privilege escalation
sensitive_action:
  enabled: true
  sensitive_actions:
    # Policy-wide: ALL actions must exist somewhere in policy
    - all_of:
        - "iam:CreateUser"
        - "iam:AttachUserPolicy"
    - all_of:
        - "lambda:CreateFunction"
        - "iam:PassRole"

    # Per-statement: ANY action in a single statement
    - any_of:
        - "iam:PutUserPolicy"
        - "iam:PutGroupPolicy"

# Enforce your organization's conditions
action_condition_enforcement:
  enabled: true
  action_condition_requirements:
    - actions: ["iam:PassRole"]
      required_conditions:
        - condition_key: "iam:PassedToService"

    # IP restrictions for admin actions (automation from CI/CD IPs)
    - actions: ["iam:CreateUser", "iam:DeleteUser", "iam:CreateAccessKey"]
      required_conditions:
        - condition_key: "aws:SourceIp"
          expected_value: ["10.0.0.0/8", "52.94.76.0/24"] # Corporate + GitHub Actions

# Ignore patterns
ignore_patterns:
  - filepath: "terraform/modules/admin/*.json"
    reason: "Admin policies reviewed separately"
```

For the full configuration reference including how `action_condition_enforcement` and `sensitive_action` work together, see:

- [Configuration Guide](https://boogy.github.io/iam-policy-validator/user-guide/configuration/)
- [Full Reference Config](https://github.com/boogy/iam-policy-validator/blob/main/examples/configs/full-reference-config.yaml)

---

## MCP Server

Use the IAM Policy Validator as an [MCP](https://modelcontextprotocol.io/) server for AI assistants like Claude Desktop. Provides 36 tools across validation, policy generation, AWS service querying, analysis, and organization config management.

```bash
# Quick start with uvx (no installation needed)
uvx --from "iam-policy-validator[mcp]" iam-validator-mcp

# Or install with MCP extras
pip install "iam-policy-validator[mcp]"
iam-validator-mcp
```

See the [MCP Server Documentation](https://boogy.github.io/iam-policy-validator/integrations/mcp-server/) for Claude Desktop configuration and tool reference.

---

## AWS Access Analyzer (Optional)

Optionally enable AWS Access Analyzer to validate policy syntax, then perform security checks on top of that validation:

```bash
# Check for public access (S3, SNS, SQS, etc.)
iam-validator analyze --path bucket-policy.json \
  --policy-type RESOURCE_POLICY \
  --check-no-public-access \
  --public-access-resource-type "AWS::S3::Bucket"

# Prevent specific actions
iam-validator analyze --path policy.json \
  --check-access-not-granted "s3:DeleteBucket iam:DeleteUser"

# Compare against baseline (detect permission creep)
iam-validator analyze --path new-policy.json \
  --check-no-new-access baseline-policy.json
```

**Note:** Access Analyzer requires AWS credentials. Built-in checks work offline.

---

## Comparison with Other Tools

| Feature                        | IAM Policy Validator           | Policy Sentry              | IAM Lens                      | IAMSpy                 |
| ------------------------------ | ------------------------------ | -------------------------- | ----------------------------- | ---------------------- |
| **Primary Purpose**            | Pre-deployment validation      | Least-privilege generation | Runtime permission analysis   | Permission enumeration |
| **Use Case**                   | CI/CD policy scanning          | Policy creation            | "What can this principal do?" | Pentesting/audit       |
| **Custom Security Rules**      | Full support                   | No                         | No                            | No                     |
| **Cross-Statement Patterns**   | Privilege escalation detection | N/A                        | N/A                           | N/A                    |
| **Action-Resource Validation** | Catches incompatible pairs     | Generates correct pairs    | N/A                           | No                     |
| **Organization Conditions**    | IP, tags, encryption, etc.     | No                         | No                            | No                     |
| **CI/CD Ready**                | GitHub Actions native          | Manual setup               | Manual setup                  | Manual                 |
| **PR Line Comments**           | Diff-aware                     | No                         | No                            | No                     |
| **AWS Service Data**           | Official API (auto-update)     | Official API               | Real AWS account data         | Static                 |
| **Offline Mode**               | Yes                            | Needs internet             | Needs AWS account             | Yes                    |
| **Query Permissions**          | Yes                            | Excellent                  | Yes (different approach)      | Enumerate only         |

**These tools are complementary, not competing.** Choose based on your use case:

- **This tool** -- Pre-deployment CI/CD validation with custom security rules and PR integration
- **[Policy Sentry](https://github.com/salesforce/policy_sentry)** -- Generate least-privilege policies from scratch (great for policy _creation_)
- **[IAM Lens](https://github.com/welldone-cloud/aws-iam-lens)** -- Runtime permission analysis and request simulation (great for _understanding_ existing permissions)
- **[IAMSpy](https://github.com/WithSecureLabs/IAMSpy)** -- Enumerate existing permissions in AWS accounts (security assessment/pentesting)
- **[Parliament](https://github.com/duo-labs/parliament)** -- Basic IAM policy linting (this tool extends Parliament's ARN pattern matching)
- **[Cloudsplaining](https://github.com/salesforce/cloudsplaining)** -- Scan existing AWS account policies for security issues (runtime audit)
- **[AWS Access Analyzer](https://aws.amazon.com/iam/access-analyzer/)** -- AWS's built-in validation and external access detection (this tool can optionally integrate with it)

---

## Documentation

- [Check Reference](https://boogy.github.io/iam-policy-validator/user-guide/checks/) - All checks with examples
- [Configuration Guide](https://boogy.github.io/iam-policy-validator/user-guide/configuration/) - Customize checks and behavior
- [GitHub Actions Guide](https://boogy.github.io/iam-policy-validator/integrations/github-actions/) - CI/CD integration
- [Python Library Guide](https://boogy.github.io/iam-policy-validator/developer-guide/sdk/) - Use as Python package
- [MCP Server Guide](https://boogy.github.io/iam-policy-validator/integrations/mcp-server/) - AI assistant integration
- [Trust Policy Examples](https://github.com/boogy/iam-policy-validator/tree/main/examples/trust-policies) - Trust policy validation examples
- [Configuration Examples](https://github.com/boogy/iam-policy-validator/tree/main/examples/configs) - Config file templates
- [Custom Checks](https://boogy.github.io/iam-policy-validator/developer-guide/custom-checks/) - Add your own validation rules
- [Changelog](https://boogy.github.io/iam-policy-validator/changelog/) - Version history and migration guides

---

## Contributing

Contributions welcome! See [CONTRIBUTING.md](CONTRIBUTING.md).

```bash
git clone https://github.com/boogy/iam-policy-validator.git
cd iam-policy-validator
uv sync --extra dev
uv run pytest
```

---

## License

MIT License - see [LICENSE](LICENSE).

- **Third-party code:** ARN pattern matching derived from [Parliament](https://github.com/duo-labs/parliament) (BSD 3-Clause).

---

## Support

- **Issues**: [GitHub Issues](https://github.com/boogy/iam-policy-validator/issues)
