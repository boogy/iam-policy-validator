# IAM Policy Validator

> **Catch IAM policy errors before they reach production** - A comprehensive security and validation tool for AWS IAM policies that combines AWS's official Access Analyzer with powerful custom security checks.

[![GitHub Actions](https://img.shields.io/badge/GitHub%20Actions-Ready-blue)](https://github.com/marketplace/actions/iam-policy-validator)
[![Python 3.12+](https://img.shields.io/badge/python-3.12+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

## 🚀 Why IAM Policy Validator?

**IAM policy errors are costly and dangerous.** A single misconfigured policy can:
- ❌ Grant unintended admin access (privilege escalation)
- ❌ Expose sensitive data to the public
- ❌ Break production deployments with invalid syntax
- ❌ Create security vulnerabilities that persist for months

**This tool prevents these issues** by:
- ✅ **Validating early** - Catch errors in PRs before merge
- ✅ **Comprehensive checks** - AWS Access Analyzer + 15+ security checks
- ✅ **Smart filtering** - Auto-detects IAM policies from mixed JSON/YAML files
- ✅ **Developer-friendly** - Clear error messages with fix suggestions
- ✅ **Zero setup** - Works as a GitHub Action out of the box

## ✨ Key Features

### 🔍 Multi-Layer Validation
- **AWS IAM Access Analyzer** - Official AWS validation (syntax, permissions, security)
- **Custom Security Checks** - 15+ specialized checks for best practices
- **Policy Comparison** - Detect new permissions vs baseline (prevent scope creep)
- **Public Access Detection** - Check 29+ AWS resource types for public exposure
- **Privilege Escalation Detection** - Identify dangerous action combinations

### 🎯 Smart & Efficient
- **Automatic IAM Policy Detection** - Scans mixed repos, filters non-IAM files automatically
- **Wildcard Expansion** - Expands `s3:Get*` patterns to validate specific actions
- **Offline Validation** - Download AWS service definitions for air-gapped environments
- **JSON + YAML Support** - Native support for both formats
- **Streaming Mode** - Memory-efficient processing for large policy sets

### ⚡ Performance Optimized
- **Service Pre-fetching** - Common AWS services cached at startup (faster validation)
- **LRU Memory Cache** - Recently accessed services cached with TTL
- **Request Coalescing** - Duplicate API requests automatically deduplicated
- **Parallel Execution** - Multiple checks run concurrently
- **HTTP/2 Support** - Multiplexed connections for better API performance

### 📊 Output Formats
- **Console** (default) - Clean terminal output with colors and tables
- **Enhanced** - Modern visual output with progress bars and tree structure
- **JSON** - Structured format for programmatic processing
- **Markdown** - GitHub-flavored markdown for PR comments
- **SARIF** - GitHub code scanning integration format
- **CSV** - Spreadsheet-compatible for analysis
- **HTML** - Interactive reports with filtering and search

### 🔌 Extensibility
- **Plugin System** - Easy-to-add custom validation checks
- **Configuration-Driven** - YAML-based configuration for all aspects
- **CI/CD Ready** - GitHub Actions, GitLab CI, Jenkins, CircleCI

## 📈 Real-World Impact

### Common IAM Policy Issues This Tool Catches

**Before IAM Policy Validator:**
```json
{
  "Statement": [{
    "Effect": "Allow",
    "Action": "s3:*",            // ❌ Too permissive
    "Resource": "*"              // ❌ All buckets!
  }]
}
```
**Issue:** Grants full S3 access to ALL buckets (data breach risk)

**After IAM Policy Validator:**
```
❌ MEDIUM: Statement applies to all resources (*)
❌ HIGH: Wildcard action 's3:*' with resource '*' is overly permissive
💡 Suggestion: Specify exact actions and bucket ARNs
```

### Privilege Escalation Detection

**Dangerous combination across multiple statements:**
```json
{
  "Statement": [
    {"Action": "iam:CreateUser"},      // Seems innocent
    {"Action": "iam:AttachUserPolicy"} // Also seems innocent
  ]
}
```

**What the validator catches:**
```
🚨 CRITICAL: Privilege escalation risk detected!
Actions ['iam:CreateUser', 'iam:AttachUserPolicy'] allow:
  1. Create new IAM user
  2. Attach AdministratorAccess policy to that user
  3. Gain full AWS account access

💡 Add conditions or separate these permissions
```

### Public Access Prevention

**Before merge:**
```json
{
  "Principal": "*",  // ❌ Anyone on the internet!
  "Action": "s3:GetObject",
  "Resource": "arn:aws:s3:::my-private-data/*"
}
```

**Blocked by validator:**
```
🛑 CRITICAL: Resource policy allows public access
29 resource types checked: AWS::S3::Bucket
Principal "*" grants internet-wide access to private data

💡 Use specific AWS principals or add IP restrictions
```

## Quick Start

### As a GitHub Action (Recommended) ⭐

The IAM Policy Validator is available as **both** a standalone GitHub Action and a Python module. Choose the approach that best fits your needs:

#### **Option A: Standalone GitHub Action** (Recommended - Zero Setup)

Use the published action directly - it handles all setup automatically:

Create `.github/workflows/iam-policy-validator.yml`:

```yaml
name: IAM Policy Validation

on:
  pull_request:
    paths:
      - 'policies/**/*.json'

jobs:
  validate:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      pull-requests: write

    steps:
      - name: Checkout code
        uses: actions/checkout@v5

      - name: Validate IAM Policies
        uses: boogy/iam-policy-validator@v1
        with:
          path: policies/
          post-comment: true
          create-review: true
          fail-on-warnings: true
```

**Benefits:**
- ✅ Zero setup - action handles Python, uv, and dependencies
- ✅ Automatic dependency caching
- ✅ Simple, declarative configuration
- ✅ Perfect for CI/CD workflows

#### With AWS Access Analyzer (Standalone Action)

Use AWS's official policy validation service:

```yaml
name: IAM Policy Validation with Access Analyzer

on:
  pull_request:
    paths:
      - 'policies/**/*.json'

jobs:
  validate:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      pull-requests: write
      id-token: write  # Required for AWS OIDC

    steps:
      - name: Checkout code
        uses: actions/checkout@v5

      - name: Configure AWS Credentials
        uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: arn:aws:iam::123456789012:role/GitHubActionsRole
          aws-region: us-east-1

      - name: Validate with Access Analyzer
        uses: boogy/iam-policy-validator@v1
        with:
          path: policies/
          use-access-analyzer: true
          run-all-checks: true
          post-comment: true
          create-review: true
          fail-on-warnings: true
```

#### **Option B: As Python Module/CLI Tool**

For advanced use cases or when you need more control:

```yaml
name: IAM Policy Validation (CLI)

on:
  pull_request:
    paths:
      - 'policies/**/*.json'

jobs:
  validate:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      pull-requests: write

    steps:
      - name: Checkout code
        uses: actions/checkout@v5

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.12'

      - name: Install uv
        uses: astral-sh/setup-uv@v3

      - name: Install dependencies
        run: uv sync

      - name: Validate IAM Policies
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
          GITHUB_REPOSITORY: ${{ github.repository }}
          GITHUB_PR_NUMBER: ${{ github.event.pull_request.number }}
        run: |
          uv run iam-validator validate \
            --path ./policies/ \
            --github-comment \
            --github-review \
            --fail-on-warnings \
            --log-level info
```

**Use this when you need:**
- Advanced CLI options (e.g., `--log-level`, `--custom-checks-dir`, `--stream`)
- Full control over the Python environment
- Integration with existing Python workflows
- Multiple validation commands in sequence

#### Custom Policy Checks (Standalone Action)

Enforce specific security requirements:

```yaml
name: IAM Policy Security Validation

on:
  pull_request:
    paths:
      - 'policies/**/*.json'

jobs:
  validate-security:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      pull-requests: write
      id-token: write

    steps:
      - name: Checkout code
        uses: actions/checkout@v5

      - name: Configure AWS Credentials
        uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: ${{ secrets.AWS_ROLE_ARN }}
          aws-region: us-east-1

      # Prevent dangerous actions
      - name: Check for Dangerous Actions
        uses: boogy/iam-policy-validator@v1
        with:
          path: policies/
          use-access-analyzer: true
          check-access-not-granted: "s3:DeleteBucket iam:CreateAccessKey iam:AttachUserPolicy"
          post-comment: true
          fail-on-warnings: true

      # Check S3 bucket policies for public access
      - name: Check S3 Public Access
        uses: boogy/iam-policy-validator@v1
        with:
          path: s3-policies/
          use-access-analyzer: true
          policy-type: RESOURCE_POLICY
          check-no-public-access: true
          public-access-resource-type: "AWS::S3::Bucket"
          post-comment: true
          fail-on-warnings: true

      # Compare against baseline to prevent new permissions
      - name: Checkout baseline from main
        uses: actions/checkout@v5
        with:
          ref: main
          path: baseline

      - name: Check for New Access
        uses: boogy/iam-policy-validator@v1
        with:
          path: policies/role-policy.json
          use-access-analyzer: true
          check-no-new-access: baseline/policies/role-policy.json
          post-comment: true
          fail-on-warnings: true
```

---

### Choosing the Right Approach

| Feature               | Standalone Action        | Python Module/CLI                                                        |
| --------------------- | ------------------------ | ------------------------------------------------------------------------ |
| Setup Required        | None - fully automated   | Manual (Python, uv, dependencies)                                        |
| Configuration         | YAML inputs              | CLI arguments                                                            |
| Advanced Options      | Limited to action inputs | Full CLI access (`--log-level`, `--custom-checks-dir`, `--stream`, etc.) |
| Custom Checks         | Via config file only     | Via config file or `--custom-checks-dir`                                 |
| Best For              | CI/CD, simple workflows  | Development, advanced workflows, testing                                 |
| Dependency Management | Automatic                | Manual                                                                   |

**Recommendation:** Use the **Standalone Action** for production CI/CD workflows, and the **Python Module/CLI** for development, testing, or when you need advanced features.

#### Multiple Paths (Standalone Action)

Validate policies across multiple directories:

```yaml
- name: Validate Multiple Paths
  uses: boogy/iam-policy-validator@v1
  with:
    path: |
      iam/
      s3-policies/
      lambda-policies/special-policy.json
    post-comment: true
    fail-on-warnings: true
```

#### Custom Configuration

Use a custom configuration file to customize validation rules:

```yaml
name: IAM Policy Validation with Custom Config

on:
  pull_request:
    paths:
      - 'policies/**/*.json'
      - '.iam-validator.yaml'

jobs:
  validate:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      pull-requests: write

    steps:
      - name: Checkout code
        uses: actions/checkout@v5

      - name: Validate with Custom Config
        uses: boogy/iam-policy-validator@v1
        with:
          path: policies/
          config-file: .iam-validator.yaml
          post-comment: true
          create-review: true
          fail-on-warnings: true
```

**Example `.iam-validator.yaml`:**
```yaml
settings:
  fail_fast: false
  enable_builtin_checks: true

# Custom check configurations
security_best_practices_check:
  enabled: true
  wildcard_action_check:
    enabled: true
    severity: high

action_condition_enforcement_check:
  enabled: true
  severity: critical
  action_condition_requirements:
    - actions:
        - "iam:PassRole"
      severity: critical
      required_conditions:
        - condition_key: "iam:PassedToService"
```

See [default-config.yaml](default-config.yaml) for a complete configuration example.

### GitHub Action Inputs

#### Core Options
| Input              | Description                                                 | Required | Default |
| ------------------ | ----------------------------------------------------------- | -------- | ------- |
| `path`             | Path(s) to IAM policy file or directory (newline-separated) | Yes      | -       |
| `config-file`      | Path to custom configuration file (.yaml)                   | No       | `""`    |
| `fail-on-warnings` | Fail validation if warnings are found                       | No       | `false` |
| `recursive`        | Recursively search directories for policy files             | No       | `true`  |

#### GitHub Integration
| Input           | Description                                | Required | Default |
| --------------- | ------------------------------------------ | -------- | ------- |
| `post-comment`  | Post validation results as PR comment      | No       | `true`  |
| `create-review` | Create line-specific review comments on PR | No       | `true`  |

#### Output Options
| Input         | Description                                                                      | Required | Default   |
| ------------- | -------------------------------------------------------------------------------- | -------- | --------- |
| `format`      | Output format: `console`, `enhanced`, `json`, `markdown`, `sarif`, `csv`, `html` | No       | `console` |
| `output-file` | Path to save output file (for non-console formats)                               | No       | `""`      |

#### AWS Access Analyzer
| Input                    | Description                                                                 | Required | Default           |
| ------------------------ | --------------------------------------------------------------------------- | -------- | ----------------- |
| `use-access-analyzer`    | Use AWS IAM Access Analyzer for validation                                  | No       | `false`           |
| `access-analyzer-region` | AWS region for Access Analyzer                                              | No       | `us-east-1`       |
| `policy-type`            | Policy type: `IDENTITY_POLICY`, `RESOURCE_POLICY`, `SERVICE_CONTROL_POLICY` | No       | `IDENTITY_POLICY` |
| `run-all-checks`         | Run custom checks after Access Analyzer (sequential mode)                   | No       | `false`           |

#### Custom Policy Checks (Access Analyzer)
| Input                         | Description                                                                 | Required | Default           |
| ----------------------------- | --------------------------------------------------------------------------- | -------- | ----------------- |
| `check-access-not-granted`    | Actions that should NOT be granted (space-separated, max 100)               | No       | `""`              |
| `check-access-resources`      | Resources to check with check-access-not-granted (space-separated, max 100) | No       | `""`              |
| `check-no-new-access`         | Path to baseline policy to compare against (detect new permissions)         | No       | `""`              |
| `check-no-public-access`      | Check that resource policies do not allow public access                     | No       | `false`           |
| `public-access-resource-type` | Resource type(s) for public access check (29+ types supported, or `all`)    | No       | `AWS::S3::Bucket` |

#### Advanced Options
| Input               | Description                                                    | Required | Default   |
| ------------------- | -------------------------------------------------------------- | -------- | --------- |
| `custom-checks-dir` | Path to directory containing custom validation checks          | No       | `""`      |
| `log-level`         | Logging level: `debug`, `info`, `warning`, `error`, `critical` | No       | `warning` |

**💡 Pro Tips:**
- Use `custom-checks-dir` to add organization-specific validation rules
- Set `log-level: debug` when troubleshooting workflow issues
- Configure `aws-services-dir` in your config file for offline validation
- The action automatically filters IAM policies from mixed JSON/YAML files

See [examples/github-actions/](examples/github-actions/) for 8 ready-to-use workflow examples.

### As a CLI Tool

Install and use locally for development:

```bash
# Install from PyPI
pip install iam-policy-validator

# Or install with pipx (recommended for CLI tools)
pipx install iam-policy-validator

# Validate a single policy
iam-validator validate --path policy.json

# Validate all policies in a directory
iam-validator validate --path ./policies/

# Validate multiple paths
iam-validator validate --path policy1.json --path ./policies/ --path ./more-policies/

# Generate JSON output
iam-validator validate --path ./policies/ --format json --output report.json

# Validate with AWS IAM Access Analyzer
iam-validator analyze --path policy.json

# Analyze with specific region and profile
iam-validator analyze --path policy.json --region us-west-2 --profile my-profile

# Sequential validation: Access Analyzer → Custom Checks
iam-validator analyze \
  --path policy.json \
  --github-comment \
  --run-all-checks \
  --github-review
```

### Custom Policy Checks

AWS IAM Access Analyzer provides specialized checks to validate policies against specific security requirements:

#### 1. CheckAccessNotGranted - Prevent Dangerous Actions

Verify that policies do NOT grant specific actions (max 100 actions, 100 resources per check):

```bash
# Check that policies don't grant dangerous S3 actions
iam-validator analyze \
  --path ./policies/ \
  --check-access-not-granted s3:DeleteBucket s3:DeleteObject

# Scope to specific resources
iam-validator analyze \
  --path ./policies/ \
  --check-access-not-granted s3:PutObject \
  --check-access-resources "arn:aws:s3:::production-bucket/*"

# Prevent privilege escalation
iam-validator analyze \
  --path ./policies/ \
  --check-access-not-granted \
    iam:CreateAccessKey \
    iam:AttachUserPolicy \
    iam:PutUserPolicy
```

**Supported:** IDENTITY_POLICY, RESOURCE_POLICY

#### 2. CheckNoNewAccess - Validate Policy Updates

Ensure policy changes don't grant new permissions:

```bash
# Compare updated policy against baseline
iam-validator analyze \
  --path ./new-policy.json \
  --check-no-new-access ./old-policy.json

# In CI/CD - compare against main branch
git show main:policies/policy.json > baseline-policy.json
iam-validator analyze \
  --path policies/policy.json \
  --check-no-new-access baseline-policy.json
```

**Supported:** IDENTITY_POLICY, RESOURCE_POLICY

#### 3. CheckNoPublicAccess - Prevent Public Exposure

Validate that resource policies don't allow public access (29+ resource types):

```bash
# Check S3 bucket policies
iam-validator analyze \
  --path ./bucket-policy.json \
  --policy-type RESOURCE_POLICY \
  --check-no-public-access \
  --public-access-resource-type "AWS::S3::Bucket"

# Check multiple resource types
iam-validator analyze \
  --path ./resource-policies/ \
  --policy-type RESOURCE_POLICY \
  --check-no-public-access \
  --public-access-resource-type "AWS::S3::Bucket" "AWS::Lambda::Function" "AWS::SNS::Topic"

# Check ALL 29 resource types
iam-validator analyze \
  --path ./resource-policies/ \
  --policy-type RESOURCE_POLICY \
  --check-no-public-access \
  --public-access-resource-type all
```

**Supported Resource Types** (29 total, or use `all`):
- **Storage**: S3 Bucket, S3 Access Point, S3 Express, S3 Glacier, S3 Outposts, S3 Tables, EFS
- **Database**: DynamoDB Table/Stream, OpenSearch Domain
- **Messaging**: Kinesis Stream, SNS Topic, SQS Queue
- **Security**: KMS Key, Secrets Manager Secret, IAM Assume Role Policy
- **Compute**: Lambda Function
- **API**: API Gateway REST API
- **DevOps**: CodeArtifact Domain, Backup Vault, CloudTrail

See [docs/custom-policy-checks.md](docs/custom-policy-checks.md) for complete documentation.

### As a Python Package

Use as a library in your Python applications:

```python
import asyncio
from iam_validator.core.policy_loader import PolicyLoader
from iam_validator.core.policy_checks import validate_policies
from iam_validator.core.report import ReportGenerator

async def main():
    # Load policies
    loader = PolicyLoader()
    policies = loader.load_from_path("./policies")

    # Validate
    results = await validate_policies(policies)

    # Generate report
    generator = ReportGenerator()
    report = generator.generate_report(results)
    generator.print_console_report(report)

asyncio.run(main())
```

**📚 For comprehensive Python library documentation, see:**
- **[Python Library Usage Guide](docs/python-library-usage.md)** - Complete guide with examples
- **[Library Examples](examples/library-usage/)** - Runnable code examples

## Validation Checks

### 1. Action Validation

Verifies that IAM actions exist in AWS services:

```json
{
  "Effect": "Allow",
  "Action": "s3:GetObject",  // ✅ Valid
  "Resource": "*"
}
```

```json
{
  "Effect": "Allow",
  "Action": "s3:InvalidAction",  // ❌ Invalid - action doesn't exist
  "Resource": "*"
}
```

### 2. Condition Key Validation

Checks that condition keys are valid for the specified actions:

```json
{
  "Effect": "Allow",
  "Action": "s3:GetObject",
  "Resource": "*",
  "Condition": {
    "StringEquals": {
      "aws:RequestedRegion": "us-east-1"  // ✅ Valid global condition key
    }
  }
}
```

### 3. Resource ARN Validation

Ensures ARNs follow proper AWS format:

```json
{
  "Effect": "Allow",
  "Action": "s3:GetObject",
  "Resource": "arn:aws:s3:::my-bucket/*"  // ✅ Valid ARN
}
```

```json
{
  "Effect": "Allow",
  "Action": "s3:GetObject",
  "Resource": "not-a-valid-arn"  // ❌ Invalid ARN format
}
```

### 4. Security Best Practices

Identifies potential security risks:

- Overly permissive wildcard usage (`*` for both Action and Resource)
- Sensitive actions without conditions
- Administrative permissions without restrictions

## GitHub Integration Features

### Smart PR Comment Management

The validator intelligently manages PR comments to keep your PRs clean:

**Comment Lifecycle:**
1. **Old Comments Cleanup**: Automatically removes outdated bot comments from previous runs
2. **Summary Comment**: Updates existing summary (no duplicates)
3. **Review Comments**: Posts line-specific issues
4. **Streaming Mode**: Progressive comments appear as files are validated

**Behavior:**
- ✅ **No Duplicates**: Summary comments are updated, not duplicated
- ✅ **Clean PR**: Old review comments automatically deleted before new validation
- ✅ **Identifiable**: All bot comments tagged with `🤖 IAM Policy Validator`
- ✅ **Progressive**: In streaming mode, comments appear file-by-file

**Example:**
```
Run 1: Finds 5 issues → Posts 5 review comments + 1 summary
Run 2: Finds 3 issues → Deletes old 5 comments → Posts 3 new comments + updates summary
Result: PR always shows current state, no stale comments
```

## Example Output

### Console Output

```
╭─────────────────── Validation Summary ───────────────────╮
│ Total Policies: 3                                        │
│ Valid: 2 Invalid: 1                                      │
│ Total Issues: 5                                          │
╰──────────────────────────────────────────────────────────╯

❌ policies/invalid_policy.json
  ERROR       invalid_action      Statement 0: Action 's3:InvalidAction' not found
  WARNING     overly_permissive   Statement 1: Statement allows all actions (*)
  ERROR       security_risk       Statement 1: Statement allows all actions on all resources
```

### GitHub PR Comment

```markdown
## ❌ IAM Policy Validation Failed

### Summary
| Metric           | Count |
| ---------------- | ----- |
| Total Policies   | 3     |
| Valid Policies   | 2 ✅   |
| Invalid Policies | 1 ❌   |
| Total Issues     | 5     |

### Detailed Findings

#### `policies/invalid_policy.json`

**Errors:**
- **Statement 0**: Action 's3:InvalidAction' not found in service 's3'
  - Action: `s3:InvalidAction`

**Warnings:**
- **Statement 1**: Statement allows all actions on all resources - CRITICAL SECURITY RISK
  - 💡 Suggestion: This grants full administrative access. Restrict to specific actions and resources.
```

## 📚 Documentation

**[📖 Complete Documentation →](DOCS.md)**

The comprehensive [DOCS.md](DOCS.md) file contains everything you need:
- Installation & Quick Start
- GitHub Actions Integration
- CLI Reference & Examples
- Custom Policy Checks (CheckAccessNotGranted, CheckNoNewAccess, CheckNoPublicAccess)
- Configuration Guide
- Creating Custom Validation Rules
- Performance Optimization
- Troubleshooting

**Additional Resources:**
- **[Examples Directory](examples/)** - Real-world examples:
  - [GitHub Actions Workflows](examples/github-actions/)
  - [Custom Checks](examples/custom_checks/)
  - [Configuration Files](examples/configs/)
  - [Test IAM Policies](examples/iam-test-policies/)
- **[AWS Services Backup Guide](docs/aws-services-backup.md)** - Offline validation
- **[Contributing Guide](CONTRIBUTING.md)** - Contribution guidelines
- **[Publishing Guide](docs/development/PUBLISHING.md)** - Release process

## 🤝 Contributing

Contributions are welcome! We appreciate your help in making this project better.

### How to Contribute

1. **Read the [Contributing Guide](CONTRIBUTING.md)** - Comprehensive guide for contributors
2. **Check [existing issues](https://github.com/boogy/iam-policy-validator/issues)** - Find something to work on
3. **Fork the repository** - Create your own copy
4. **Make your changes** - Follow our code quality standards
5. **Submit a Pull Request** - We'll review and merge

### Development Setup

```bash
# Clone your fork
git clone https://github.com/YOUR-USERNAME/iam-policy-validator.git
cd iam-policy-validator

# Install dependencies
uv sync --extra dev

# Run tests
uv run pytest

# Run linting
uv run ruff check .
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for detailed instructions.

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🆘 Support

- **Documentation**: Check the [docs/](docs/) directory
- **Issues**: Report bugs or request features via [GitHub Issues](https://github.com/boogy/iam-policy-validator/issues)
- **Questions**: Ask questions in [GitHub Discussions](https://github.com/boogy/iam-policy-validator/discussions)
