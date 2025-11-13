# IAM Policy Validator

> **⚡ Catch IAM policy security issues and errors before they reach production** - A comprehensive validation tool for AWS IAM policies with built-in security checks and optional AWS Access Analyzer integration.

[![GitHub Actions](https://img.shields.io/badge/GitHub%20Actions-Ready-blue)](https://github.com/marketplace/actions/iam-policy-validator)
[![Python 3.12+](https://img.shields.io/badge/python-3.12+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/boogy/iam-policy-validator/badge)](https://scorecard.dev/viewer/?uri=github.com/boogy/iam-policy-validator)

## 🚀 Why IAM Policy Validator?

**IAM policy errors are costly and dangerous.** A single misconfigured policy can:
- ❌ Grant unintended admin access (privilege escalation)
- ❌ Expose sensitive data to the public
- ❌ Break production deployments with invalid syntax
- ❌ Create security vulnerabilities that persist for months

**This tool prevents these issues** by:
- ✅ **Dual validation** - built-in checks + optional AWS Access Analyzer
- ✅ **Catches real threats** - Privilege escalation, wildcards, missing conditions
- ✅ **PR integration** - Automated validation in GitHub Actions
- ✅ **Saves security team time** - Catches common issues before manual review
- ✅ **Developer-friendly** - Clear errors with fix suggestions
- ✅ **Zero setup** - Works as a GitHub Action out of the box

## ✨ What Makes It Special

### 🔍 Two Validation Layers

**1. Built-in Checks (No AWS Credentials Required)**
- **Security & Compliance Checks** - Works offline, no AWS account needed
- **Privilege Escalation Detection** - Detects dangerous IAM actions and configurable combination patterns
- **Wildcard Analysis** - Catches overly permissive wildcards (`*`, `s3:*`)
- **Sensitive Action Enforcement** - 490 actions requiring conditions (MFA, IP, tags)
- **AWS Requirements Validation** - Actions, conditions, ARN formats, policy size

**2. AWS Access Analyzer (Optional)**
- **Official AWS Validation** - Syntax, semantics, and security checks
- **Public Access Detection** - Checks 29+ resource types (S3, Lambda, SNS, etc.)
- **Policy Comparison** - Detect new permissions vs baseline
- **Cross-account Analysis** - Validates external access

### 🎯 Developer Experience
- **Auto-detects IAM policies** - Scans mixed JSON/YAML repos automatically
- **PR comments & reviews** - Line-specific feedback in GitHub
- **7 output formats** - Console, JSON, Markdown, SARIF, CSV, HTML, Enhanced
- **Extensible** - Add custom checks via Python plugins

**📖 See [full feature documentation](docs/README.md) for details**

## 📈 What It Catches

### Example 1: Privilege Escalation (Built-in Check)
```json
{
  "Statement": [
    {"Effect": "Allow", "Action": "iam:CreateUser", "Resource": "*"},
    {"Effect": "Allow", "Action": "iam:AttachUserPolicy", "Resource": "*"}
  ]
}
```

**Detected:**
```
🚨 CRITICAL: Privilege escalation risk detected!
Actions ['iam:CreateUser', 'iam:AttachUserPolicy'] enable:
  1. Create new IAM user
  2. Attach AdministratorAccess to that user
  3. Gain full AWS account access
```

### Example 2: Overly Permissive Wildcards (Built-in Check)
```json
{
  "Effect": "Allow",
  "Action": "s3:*",
  "Resource": "*"
}
```

**Detected:**
```
❌ HIGH: Service wildcard 's3:*' detected
❌ MEDIUM: Wildcard resource '*' - applies to all S3 buckets
❌ CRITICAL: Full wildcard (Action + Resource) grants excessive access
```

### Example 3: Missing Required Conditions (Built-in Check)
```json
{
  "Effect": "Allow",
  "Action": "iam:PassRole",
  "Resource": "*"
}
```

**Detected:**
```
❌ HIGH: iam:PassRole missing required condition
💡 Add condition: iam:PassedToService to restrict role passing
```

### Example 4: Public Access (Access Analyzer - Optional)
```json
{
  "Principal": "*",
  "Action": "s3:GetObject",
  "Resource": "arn:aws:s3:::private-bucket/*"
}
```

**Detected:**
```
🛑 CRITICAL: Resource policy allows public internet access
Principal "*" grants world-readable access to S3 bucket
💡 Use specific AWS principals or add aws:SourceIp conditions
```

## Quick Start

### GitHub Action (Recommended)

Create `.github/workflows/iam-validator.yml`:

```yaml
name: IAM Policy Validation

on:
  pull_request:
    paths: ['policies/**/*.json']

jobs:
  validate:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      pull-requests: write
    steps:
      - uses: actions/checkout@v5
      - uses: boogy/iam-policy-validator@v1
        with:
          path: policies/
          fail-on-warnings: true
```

**With AWS Access Analyzer (optional):**
```yaml
      - uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: arn:aws:iam::123456789012:role/GitHubActionsRole
          aws-region: us-east-1
      - uses: boogy/iam-policy-validator@v1
        with:
          path: policies/
          use-access-analyzer: true
          run-all-checks: true  # Run both Access Analyzer + built-in checks
```

**📖 For all GitHub Action inputs and advanced workflows, see [GitHub Actions Guide](docs/github-actions-workflows.md)**

### CLI Tool

```bash
# Install
pip install iam-policy-validator

# Validate (built-in checks only - no AWS credentials needed)
iam-validator validate --path ./policies/

# Validate with AWS Access Analyzer (requires AWS credentials)
iam-validator analyze --path ./policies/

# With both Access Analyzer + built-in checks
iam-validator analyze --path ./policies/ --run-all-checks

# Different policy types
iam-validator validate --path ./policies/ --policy-type RESOURCE_POLICY

# Output formats
iam-validator validate --path ./policies/ --format json --output report.json
```

**📖 See [CLI documentation](docs/README.md) for all commands and options**

### Python Library

```python
from iam_validator.core.policy_loader import PolicyLoader
from iam_validator.core.policy_checks import validate_policies

# Load and validate
loader = PolicyLoader()
policies = loader.load_from_path("./policies")
results = await validate_policies(policies)
```

**📖 See [Python Library Guide](docs/python-library-usage.md) for complete examples**

## Built-in Validation Checks

**All checks are fully configurable** - Enable/disable checks, adjust severity levels, add custom requirements, and define ignore patterns through the configuration file.

### Core Checks (18 always-on + 1 opt-in)

The validator includes **19 built-in checks** organized into three categories:

### AWS Correctness Checks (12)
Validates policies against AWS IAM requirements:
- **Policy structure** - Validates fundamental IAM policy grammar (Version, Effect, required fields, conflicts)
- **Action validation** - Verify actions exist in AWS services
- **Condition key validation** - Check condition keys are valid for actions
- **Condition type matching** - Ensure condition values match expected types
- **Resource ARN validation** - Validate ARN formats and patterns
- **Principal validation** - Check principal formats (resource policies)
- **Policy size limits** - Enforce AWS size constraints
- **SID uniqueness** - Ensure statement IDs are unique
- **Set operator validation** - Validate ForAllValues/ForAnyValue usage
- **MFA condition patterns** - Detect common MFA anti-patterns
- **Policy type validation** - Enforce policy type requirements (RCP, SCP, etc.)
- **Action-resource matching** - Detect impossible action-resource combinations

### Security Best Practices (6)
Identifies security risks and overly permissive permissions:
- **Wildcard action** (`Action: "*"`)
- **Wildcard resource** (`Resource: "*"`)
- **Full wildcard** (CRITICAL: both `Action: "*"` and `Resource: "*"`)
- **Service wildcards** (`s3:*`, `iam:*`, etc.)
- **Sensitive actions** - ~490 actions across 4 risk categories requiring conditions
- **Action condition enforcement** - Enforce required conditions (MFA, IP, SourceArn, etc.)

### Trust Policy Validation (1 - Opt-in, Disabled by Default)
Specialized validation for role assumption policies:
- **Trust policy validation** - Validates action-principal coupling for assume role actions
  - Ensures correct principal types (`AssumeRoleWithSAML` → Federated, etc.)
  - Validates SAML/OIDC provider ARN formats
  - Enforces required conditions (`SAML:aud`, OIDC audience, etc.)
  - Use with `--policy-type TRUST_POLICY` flag
  - See [Trust Policy Examples](examples/trust-policies/README.md)

### Configuration & Customization

All checks can be customized via a yaml configuration file ex: `.iam-validator.yaml`:

```yaml
settings:
  enable_builtin_checks: true
  fail_on_severity: high

# Customize individual checks
wildcard_action:
  enabled: true
  severity: critical

# Detect privilege escalation patterns
sensitive_action:
  enabled: true
  severity: critical
  sensitive_actions:
    # all_of: Detects when ALL actions exist across the entire policy
    # (checks multiple statements - finds scattered dangerous combinations)
    - all_of:
        - "iam:CreateUser"
        - "iam:AttachUserPolicy"

    # any_of: Detects when ANY action exists in a single statement
    # (per-statement check - flags individual dangerous actions)
    - any_of:
        - "iam:PutUserPolicy"
        - "iam:PutGroupPolicy"
        - "iam:PutRolePolicy"

    # Lambda backdoor: Needs both actions somewhere in policy
    - all_of:
        - "lambda:CreateFunction"
        - "iam:PassRole"

    # Regex patterns work with all_of (policy-wide check)
    - all_of:
        - "iam:Create.*"  # Any IAM Create action
        - "iam:Attach.*"  # Any IAM Attach action

# Enforce required conditions for sensitive actions
action_condition_enforcement:
  enabled: true
  action_condition_requirements:
    - actions: ["iam:PassRole"]
      severity: critical
      required_conditions:
        - condition_key: "iam:PassedToService"

# Ignore specific patterns
ignore_patterns:
  - filepath: "terraform/modules/admin/*.json"
  - action: "s3:*"
    filepath: "policies/s3-admin-policy.json"
```

**📖 Complete documentation:**
- [Check Reference Guide](docs/check-reference.md) - All 19 checks with examples
- [Configuration Guide](docs/configuration.md) - Full configuration options
- [Condition Requirements](docs/condition-requirements.md) - Action-specific requirements
- [Privilege Escalation Detection](docs/privilege-escalation.md) - How privilege escalation works
- [Trust Policy Validation](examples/trust-policies/README.md) - Trust policy examples and validation

## Output Formats & GitHub Integration

### Output Formats
- **Console** - Clean terminal output with colors
- **Enhanced** - Visual output with progress bars
- **JSON** - Structured data for automation
- **Markdown** - GitHub PR comments
- **SARIF** - GitHub Code Scanning integration
- **CSV** - Spreadsheet analysis
- **HTML** - Interactive reports

### GitHub PR Integration

**Three comment modes (use any combination):**
- `--github-comment` - Summary in PR conversation
- `--github-review` - Line-specific review comments on files
- `--github-summary` - Overview in GitHub Actions summary tab

**Smart comment management:**
- Automatically cleans up old comments from previous runs
- Updates summaries instead of duplicating
- No stale comments left behind

**📖 See [GitHub Integration Guide](docs/github-actions-workflows.md) for detailed examples**

## AWS Access Analyzer (Optional)

In addition to the 19 built-in checks, optionally enable AWS Access Analyzer for additional validation capabilities that require AWS credentials:

### Access Analyzer Capabilities

**Custom Policy Checks:**
- `check-access-not-granted` - Verify policies DON'T grant specific actions (max 100 actions)
- `check-no-new-access` - Compare against baseline to detect permission creep
- `check-no-public-access` - Validate 29+ resource types for public exposure

**Example:**
```bash
# Prevent dangerous actions
iam-validator analyze --path policies/ \
  --check-access-not-granted "s3:DeleteBucket iam:AttachUserPolicy"

# Compare against baseline
iam-validator analyze --path new-policy.json \
  --check-no-new-access baseline-policy.json

# Check for public access
iam-validator analyze --path bucket-policy.json \
  --policy-type RESOURCE_POLICY \
  --check-no-public-access \
  --public-access-resource-type "AWS::S3::Bucket"
```

**Supported Policy Types:**
- `IDENTITY_POLICY` (default) - User/role policies
- `RESOURCE_POLICY` - S3, SNS, KMS resource policies
- `SERVICE_CONTROL_POLICY` - AWS Organizations SCPs
- `RESOURCE_CONTROL_POLICY` - AWS Organizations RCPs (2024)

**📖 See [Access Analyzer documentation](docs/custom-checks.md) for complete details**

## 📚 Documentation

**Guides:**
- [Check Reference](docs/check-reference.md) - All 19 checks with examples
- [Configuration Guide](docs/configuration.md) - Customize checks and behavior
- [GitHub Actions Guide](docs/github-actions-workflows.md) - CI/CD integration
- [Python Library Guide](docs/python-library-usage.md) - Use as Python package
- [Trust Policy Guide](examples/trust-policies/README.md) - Trust policy validation
- [Contributing Guide](CONTRIBUTING.md) - How to contribute

**Examples:**
- [Configuration Examples](examples/configs/) - 9+ config file templates
- [Workflow Examples](examples/github-actions/) - GitHub Actions workflows
- [Custom Checks](examples/custom_checks/) - Add your own validation rules
- [Trust Policies](examples/trust-policies/) - Trust policy examples

## 🤝 Contributing

Contributions are welcome! See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup and guidelines.

**Quick start:**
```bash
git clone https://github.com/YOUR-USERNAME/iam-policy-validator.git
cd iam-policy-validator
uv sync --extra dev
uv run pytest
```

## 📄 License

MIT License - see [LICENSE](LICENSE) file for details.

**Third-party code:** ARN pattern matching in [iam_validator/sdk/arn_matching.py](iam_validator/sdk/arn_matching.py) is derived from [Parliament](https://github.com/duo-labs/parliament) (BSD 3-Clause License).

## 🆘 Support

- **Issues**: [GitHub Issues](https://github.com/boogy/iam-policy-validator/issues)
