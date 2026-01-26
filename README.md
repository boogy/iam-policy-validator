# IAM Policy Validator

**Stop IAM misconfigurations before they become breaches** — Catch overprivileged permissions, dangerous wildcards, and policy errors before deployment.

[![GitHub Actions](https://img.shields.io/badge/GitHub%20Actions-Ready-blue)](https://github.com/marketplace/actions/iam-policy-validator)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/boogy/iam-policy-validator/badge)](https://scorecard.dev/viewer/?uri=github.com/boogy/iam-policy-validator)

**[📖 Full Documentation](https://boogy.github.io/iam-policy-validator/)**

---

## Why This Tool Exists

Security teams need to **enforce organization-specific IAM requirements** and **catch dangerous patterns** before policies reach production. Manual review doesn't scale, and AWS's built-in validation in IAM console only checks more syntax and less security.

**Real problems this detects:**

1. **Privilege escalation chains** - Scattered actions that together grant admin access
2. **Broken automation** - Syntactically valid but functionally wrong policies (`s3:GetObject` on bucket ARN)
3. **Missing security controls** - No IAM conditions for sensitive AWS API actions
4. **Overly permissive access** - Wildcard actions and resources that violate least privilege
5. **Trust policy vulnerabilities** - Incorrect principals, missing OIDC audience, SAML misconfiguration
6. **Typos and invalid syntax** - Invalid actions (`s3:GetObjekt`), condition keys, or ARN formats before deployment
7. **Your own detection** - Set custom configuration file for custom detections

---

## Quick Start

```bash
pip install iam-policy-validator

# Try it with the example policies (from repository root)
iam-validator validate --path examples/quick-start/ --format enhanced
```

**Example output:**

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

```
╭──────────────────────────────────────────────────────────────────────────────────────────────────╮
│                                                                                                  │
│                              IAM Policy Validation Report (v1.14.1)                              │
│                                                                                                  │
╰──────────────────────────────────────────────────────────────────────────────────────────────────╯
───────────────────────────────────────── Detailed Results ─────────────────────────────────────────
❌ [1/3] examples/quick-start/user-policy.json • INVALID (IAM errors + security issues)
     2 issue(s) found

Issues (2)
├── 🔴 High
│   └── [Statement 2 @L10] missing_required_condition
│       └── Required: Action(s) ``iam:PassRole`` require condition `iam:PassedToService`
│           ├── Action: iam:PassRole • Condition: iam:PassedToService
│           └── 💡 Restrict which AWS services can assume the passed role to prevent privilege escalation
│
│               Note: Found 1 statement(s) with these actions in the policy.
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
        └── Actions `s3:GetObject` require at least ONE of these conditions: `aws:ResourceOrgID` OR `aws:ResourceOrgPaths` OR `aws:SourceIp` OR
            `aws:SourceVpc` OR `aws:SourceVpce` OR `aws:ResourceAccount`
            ├── Action: s3:GetObject
            └── 💡 Add at least ONE of these conditions:
                - **Option 1**: `aws:ResourceOrgID` - Restrict S3 operations to resources within your AWS Organization (value:
                `${aws:PrincipalOrgID}`)
                - **Option 2**: `aws:ResourceOrgPaths` - Restrict S3 operations to resources within your AWS Organization path (value:
                `${aws:PrincipalOrgPaths}`)
                - **Option 3**: `aws:SourceIp` - Restrict S3 operations by source IP address and same account
                - **Option 4**: `aws:SourceVpc` - Restrict S3 operations by source VPC and same account
                - **Option 5**: `aws:SourceVpce` - Restrict S3 operations by VPC endpoint and same account
                - **Option 6**: `aws:ResourceAccount` - Restrict S3 operations to resources within the same AWS account (value:
                `${aws:PrincipalAccount}`)

                Note: Found 1 statement(s) with these actions in the policy.

✅ [3/3] examples/quick-start/lambda-policy.json • VALID
     No issues detected

╭──────────────────────────────────────────────────────────────────────────────────────────────────╮
│                                                                                                  │
│  ❌ VALIDATION FAILED                                                                            │
│  2 of 3 policies have critical issues that must be resolved.                                     │
│                                                                                                  │
╰──────────────────────────────────────────────────────────────────────────────────────────────────╯
```

### In GitHub PRs

```yaml
# .github/workflows/iam-validator.yml
- uses: boogy/iam-policy-validator@v1
  with:
    path: policies/
    github-review: true
```

**Result:** Line-specific comments on policy files showing what's wrong and how to fix it.

---

## What Makes This Different

### 🎯 **1. Enforce Your Organization's Security Rules**

Define security requirements as code—the validator becomes your organization's policy gatekeeper:

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

**Real-world use cases:**

- 🏢 **Corporate network only**: Require `aws:SourceIp` for admin actions (automation from CI/CD IPs)
- 🏷️ **Cost tracking**: Enforce resource tagging before creation
- 🔐 **Encryption mandates**: Require encryption conditions on data operations
- ⏰ **Time-based access**: Require `aws:CurrentTime` conditions for temporary access
- 🔒 **Service restrictions**: Limit `iam:PassRole` to specific AWS services
- 🌐 **VPC restrictions**: Require `aws:SourceVpc` for sensitive operations

**Why this matters:** Other tools perform AWS-standard security checks but lack the flexibility to codify your organization's specific security requirements (IP restrictions, tagging mandates, encryption requirements, etc.).

---

### 🔍 **2. Detect Cross-Statement Privilege Escalation**

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

**🚨 Detected:** Statements 1 and 3 enable privilege escalation:

1. Create new IAM user
2. Attach `AdministratorAccess` policy to that user
3. Escalate to full account access

**Built-in escalation patterns** (enabled by default):

- User privilege escalation (`iam:CreateUser` + `iam:AttachUserPolicy`)
- Role privilege escalation (`iam:CreateRole` + `iam:AttachRolePolicy`)
- Lambda function backdoor (`lambda:CreateFunction` + `lambda:InvokeFunction`)
- Lambda code injection (`lambda:UpdateFunctionCode` + `lambda:InvokeFunction`)
- Policy version manipulation (`iam:CreatePolicyVersion` + `iam:SetDefaultPolicyVersion`)
- EC2 instance privilege escalation (`ec2:RunInstances` + `iam:PassRole`)

Additionally detects **[hundreds of sensitive actions](iam_validator/core/config/sensitive_actions.py)** across 4 categories (credential exposure, data access, privilege escalation, resource exposure) that should have IAM conditions.
List of actions copied from [primeharbor/sensitive_iam_actions](https://github.com/primeharbor/sensitive_iam_actions).

**Extend with custom patterns:**

```yaml
sensitive_action:
  sensitive_actions:
    # Add your own cross-statement patterns
    - all_of: ["cloudformation:CreateStack", "iam:PassRole"]
      severity: critical
      message: "CloudFormation + PassRole enables infrastructure privilege escalation"
```

See [Security Checks Documentation](docs/user-guide/checks/security-checks.md) for all built-in patterns and custom configuration.

**Comparison:**

- **This tool**: 6 built-in escalation patterns + hundreds of sensitive actions + extensible
- **IAM Lens**: Runtime permission evaluator ("what can this principal do?"), not policy validator
- **Policy Sentry**: Generates policies, doesn't scan for escalation
- **IAMSpy**: Enumerates permissions, different use case

---

### ⚙️ **3. Catch Functionally Broken Policies**

Validates that actions and resources are **compatible**—catches policies that pass AWS validation but fail at runtime:

```json
{
  "Effect": "Allow",
  "Action": "s3:GetObject",
  "Resource": "arn:aws:s3:::mybucket"
}
```

**🚨 Detected:** `s3:GetObject` operates on **objects**, not buckets. This policy does nothing.
**💡 Fix:** `"Resource": "arn:aws:s3:::mybucket/*"`

**More examples:**

```json
// BAD: s3:ListBucket with object ARN
{"Action": "s3:ListBucket", "Resource": "arn:aws:s3:::bucket/*"}
// ✅ FIX: s3:ListBucket needs bucket ARN
{"Action": "s3:ListBucket", "Resource": "arn:aws:s3:::bucket"}

// BAD: iam:ListUsers with user-specific ARN
{"Action": "iam:ListUsers", "Resource": "arn:aws:iam::*:user/bob"}
// ✅ FIX: iam:ListUsers is global, needs wildcard
{"Action": "iam:ListUsers", "Resource": "*"}

// BAD: ec2:DescribeInstances with specific instance
{"Action": "ec2:DescribeInstances", "Resource": "arn:aws:ec2:*:*:instance/i-1234"}
// ✅ FIX: Describe actions don't support resource-level permissions
{"Action": "ec2:DescribeInstances", "Resource": "*"}
```

**Why this matters:** These policies look correct but fail silently in production. AWS validates syntax, not action-resource compatibility.

---

### 🔧 **4. Uses Official AWS Service Definitions**

Fetches **real AWS service data** from AWS's official IAM service definition API (JSON endpoint)—always accurate and up-to-date:

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

**Comparison:**

- **This tool**: Official AWS API, auto-updates, offline mode
- **Policy Sentry**: Official AWS API, excellent query capabilities
- **IAM Lens**: Uses actual AWS account data (runtime analysis)
- **IAMSpy**: Static database, may lag behind AWS updates

---

### 🎨 **5. Built for CI/CD and Developer Workflows**

**GitHub PR Integration:**

- **Diff-aware filtering**: Only comments on lines you actually changed
- **Line-specific feedback**: Inline comments on policy files with exact line numbers
- **Smart cleanup**: Updates existing comments, removes stale ones
- **Severity-based reviews**: Auto-approve or request changes based on findings

**Multiple output formats:**

- Console (colored terminal)
- JSON (automation/API)
- SARIF (GitHub Code Scanning)
- Markdown (documentation)
- HTML (interactive reports)
- CSV (spreadsheet analysis)

**Example GitHub Action:**

```yaml
- uses: boogy/iam-policy-validator@v1
  with:
    path: policies/
    github-review: true # Inline PR comments
    github-summary: true # Actions summary tab
    fail-on-severity: high # Block merge on high/critical
```

---

## What Does It Check?

### ✅ **AWS Correctness (12 checks)**

Validates against official AWS IAM requirements:

| Check                        | What It Does                                                                        |
| ---------------------------- | ----------------------------------------------------------------------------------- |
| **Policy Structure**         | Required fields (Version, Statement, Effect), valid JSON/YAML                       |
| **Action Validation**        | Actions exist in AWS services (detects typos: `s3:GetObjekt`)                       |
| **Condition Keys**           | Valid condition keys for actions (e.g., `s3:prefix` valid for `s3:ListBucket`)      |
| **Condition Types**          | Values match expected types (IP for `aws:SourceIp`, Bool for `aws:SecureTransport`) |
| **Resource ARNs**            | Correct ARN format and patterns                                                     |
| **Principal Validation**     | Valid principals in resource/trust policies                                         |
| **Policy Size**              | AWS limits (6144 bytes managed, 10240 inline, 20480 resource)                       |
| **SID Uniqueness**           | Statement IDs unique within policy                                                  |
| **Set Operators**            | Correct `ForAllValues`/`ForAnyValue` usage with arrays                              |
| **MFA Conditions**           | Detect insecure MFA patterns (`!= false` instead of `== true`)                      |
| **Policy Type**              | RCP/SCP-specific requirements                                                       |
| **Action-Resource Matching** | Actions compatible with resources (catches functional errors)                       |

### 🔒 **Security Best Practices (6 checks)**

Identifies overly permissive configurations:

| Check                     | What It Catches                                          |
| ------------------------- | -------------------------------------------------------- |
| **Wildcard Action**       | `Action: "*"` grants all AWS permissions                 |
| **Wildcard Resource**     | `Resource: "*"` applies to all resources                 |
| **Full Wildcard**         | Both `Action: "*"` AND `Resource: "*"` (admin access)    |
| **Service Wildcards**     | `s3:*`, `iam:*`, `ec2:*` (overly broad)                  |
| **Sensitive Actions**     | 490+ privilege escalation patterns and dangerous actions |
| **Condition Enforcement** | Organization-specific condition requirements             |

**Note on Sensitive Actions:** This check has two modes:

- `all_of`: **Policy-wide** detection (e.g., `iam:CreateUser` in statement 0 + `iam:AttachUserPolicy` in statement 2)
- `any_of`: **Per-statement** detection (e.g., any statement with `iam:PutUserPolicy`)

### 🔐 **Trust Policy Validation (opt-in)**

Specialized checks for role assumption:

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
from iam_validator.core.policy_loader import PolicyLoader
from iam_validator.core.policy_checks import validate_policies

loader = PolicyLoader()
policies = loader.load_from_path("./policies")
results = await validate_policies(policies)

for result in results:
    if not result.is_valid:
        for issue in result.issues:
            print(f"{issue.severity}: {issue.message} at line {issue.line_number}")
```

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

#### Understanding Configuration: Two Ways to Control Action Validation

The validator provides two complementary approaches for action-specific validation:

**Option 1: Enforce Required Conditions** (`action_condition_enforcement`)

Use this when you want to **mandate specific conditions** for certain actions:

```yaml
action_condition_enforcement:
  enabled: true
  requirements:
    # Enforce that iam:PassRole must specify which service can use the role
    - actions: ["iam:PassRole"]
      required_conditions:
        - condition_key: "iam:PassedToService"
          description: "Prevent privilege escalation by restricting service access"

    # Enforce MFA for credential creation
    - actions: ["iam:CreateAccessKey"]
      required_conditions:
        - condition_key: "aws:MultiFactorAuthPresent"
          expected_value: true
```

**What this does:**

- ✅ **Validates** that required conditions exist in the policy
- ✅ **Fails validation** when conditions are missing
- ✅ **Prevents duplicate warnings** (automatically filters from `sensitive_action` check)
- ✅ **Specific guidance** per action about which conditions are required

**Option 2: Suggest Best Practices** (`sensitive_action`)

Use this when you want to **flag actions without conditions** and provide ABAC guidance:

```yaml
sensitive_action:
  enabled: true
  # Uses built-in list of 490+ sensitive actions across 4 categories:
  # - credential_exposure: Actions that expose credentials/secrets
  # - data_access: Actions that retrieve sensitive data
  # - priv_esc: Actions that enable privilege escalation
  # - resource_exposure: Actions that modify resource policies

  # Optionally add your own sensitive actions
  sensitive_actions:
    - "custom:SensitiveAction"
```

**What this does:**

- ⚠️ **Suggests** that actions should have conditions (doesn't enforce specific ones)
- ⚠️ **Generic ABAC guidance** (tag matching, MFA, IP restrictions)
- ✅ **Automatic filtering** (skips actions already validated by `action_condition_enforcement`)

**Decision Matrix:**

| Your Goal                                           | Use This                       | Config Example                                   |
| --------------------------------------------------- | ------------------------------ | ------------------------------------------------ |
| **Must enforce** specific conditions for compliance | `action_condition_enforcement` | Require `iam:PassedToService` for `iam:PassRole` |
| **Want to suggest** general security improvements   | `sensitive_action`             | Flag `s3:GetObject` without any conditions       |
| **Organization-specific** rules (IP, tags, MFA)     | `action_condition_enforcement` | Require corporate IPs for admin actions          |
| **General best practices** (ABAC)                   | `sensitive_action`             | Suggest tag-based access control                 |

**How They Work Together:**

1. `action_condition_enforcement` validates **specific required conditions** (strict enforcement)
2. `sensitive_action` suggests **ABAC best practices** for actions without conditions (general guidance)
3. **Automatic deduplication** prevents showing both warnings for the same action
4. Actions in `action_condition_enforcement` are automatically filtered from `sensitive_action`

**Example - Complete Configuration:**

```yaml
# Strict enforcement for critical actions
action_condition_enforcement:
  enabled: true
  requirements:
    - actions: ["iam:PassRole"]
      required_conditions:
        - condition_key: "iam:PassedToService"

    - actions: ["s3:GetObject", "s3:GetObjectVersion"]
      required_conditions:
        any_of:
          - condition_key: "aws:ResourceOrgID"
          - condition_key: "aws:SourceVpc"

# General suggestions for other sensitive actions
sensitive_action:
  enabled: true
  # Will NOT warn about iam:PassRole or s3:GetObject (already covered above)
  # Will warn about other sensitive actions like iam:CreateUser, s3:DeleteObject, etc.
```

For more details, see:

- [Configuration Guide](docs/user-guide/configuration.md) - How to configure condition requirements
- [examples/configs/full-reference-config.yaml](examples/configs/full-reference-config.yaml) - Complete configuration reference

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

## Comparison Matrix

| Feature                        | IAM Policy Validator              | IAM Lens                      | IAMSpy                 | Policy Sentry              |
| ------------------------------ | --------------------------------- | ----------------------------- | ---------------------- | -------------------------- |
| **Primary Purpose**            | Pre-deployment validation         | Runtime permission analysis   | Permission enumeration | Least-privilege generation |
| **Use Case**                   | CI/CD policy scanning             | "What can this principal do?" | Pentesting/audit       | Policy creation            |
| **Custom Security Rules**      | ✅ Full support                   | ❌ No                         | ❌ No                  | ❌ No                      |
| **Cross-Statement Patterns**   | ✅ Privilege escalation detection | N/A (different purpose)       | N/A                    | N/A                        |
| **Action-Resource Validation** | ✅ Catches incompatible pairs     | N/A                           | ❌ No                  | ✅ Generates correct       |
| **Organization Conditions**    | ✅ IP, tags, encryption, etc.     | ❌ No                         | ❌ No                  | ❌ No                      |
| **CI/CD Ready**                | ✅ GitHub Actions native          | ⚠️ Manual setup               | ⚠️ Manual              | ⚠️ Manual                  |
| **PR Line Comments**           | ✅ Diff-aware                     | ❌ No                         | ❌ No                  | ❌ No                      |
| **AWS Service Data**           | ✅ Official API (auto-update)     | ✅ Real AWS account data      | ⚠️ Static              | ✅ Official API            |
| **Offline Mode**               | ✅ Yes                            | ❌ Needs AWS account          | ✅ Yes                 | ❌ Needs internet          |
| **Query Permissions**          | ✅ Yes                            | ✅ Yes (different approach)   | ⚠️ Enumerate only      | ✅ Excellent               |

**Choose this tool if you:**

- Need **pre-deployment validation** in CI/CD
- Want to **enforce organization-specific security requirements**
- Need to catch **privilege escalation patterns**
- Want to validate **action-resource compatibility**
- Need **PR integration with line comments**

**Choose IAM Lens if you:**

- Need **runtime permission analysis** ("can this user do X?")
- Want to **simulate real AWS requests**
- Need to understand **effective permissions across policies**

**Choose Policy Sentry if you:**

- Need to **generate least-privilege policies** from scratch
- Want to **query AWS permissions** for policy writing

**IAMSpy is for:**

- **Enumerating existing permissions** in AWS accounts
- **Security assessment** (pentesting, not validation)

---

## Documentation

**Guides:**

- [Check Reference](docs/user-guide/checks/) - All checks with examples
- [Configuration Guide](docs/user-guide/configuration.md) - Customize checks and behavior
- [GitHub Actions Guide](docs/integrations/github-actions.md) - CI/CD integration
- [Python Library Guide](docs/developer-guide/sdk/) - Use as Python package
- [Trust Policy Examples](examples/trust-policies/) - Trust policy validation examples
- [Changelog](CHANGELOG.md) - Version history and migration guides

**Examples:**

- [Configuration Examples](examples/configs/) - Config file templates
- [Workflow Examples](examples/github-actions/) - GitHub Actions workflows
- [Custom Checks](examples/custom_checks/) - Add your own validation rules

---

## Related Tools & Resources

Other tools in the IAM security ecosystem that serve different purposes:

### Policy Analysis & Generation

- **[Parliament](https://github.com/duo-labs/parliament)** - IAM policy linter that checks for syntax errors and basic security issues. This validator uses Parliament's ARN pattern matching logic.
- **[Policy Sentry](https://github.com/salesforce/policy_sentry)** - Generates least-privilege IAM policies from AWS service definitions. Great for policy creation; this validator focuses on policy validation.
- **[Cloudsplaining](https://github.com/salesforce/cloudsplaining)** - Scans existing AWS account policies for security issues. Runtime analysis vs. pre-deployment validation.

### Permission Analysis

- **[IAM Dataset](https://github.com/glassechidna/iam-dataset)** - Curated dataset of AWS IAM actions, resources, and conditions scraped from AWS documentation. Useful reference for policy authors.
- **[IAMSpy](https://github.com/WithSecureLabs/IAMSpy)** - Enumerates IAM permissions for roles/users in an AWS account. Pentesting/audit tool, not a validator.
- **[IAM Lens](https://github.com/welldone-cloud/aws-iam-lens)** - Runtime permission evaluator that answers "what can this principal do?". Complements pre-deployment validation.

### AWS Official Tools

- **[AWS Access Analyzer](https://aws.amazon.com/iam/access-analyzer/)** - AWS's built-in policy validation and external access detection. This validator can optionally integrate with it.
- **[AWS IAM Policy Simulator](https://policysim.aws.amazon.com/)** - Test policies against AWS resources to see if actions are allowed.

**When to use this validator vs. others:**

- Use this for **pre-deployment CI/CD validation** with custom security rules
- Use Policy Sentry for **generating** least-privilege policies
- Use Cloudsplaining/IAMSpy for **auditing existing** AWS accounts
- Use IAM Lens for **runtime permission analysis**
- Use Parliament if you only need basic syntax/ARN validation

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
