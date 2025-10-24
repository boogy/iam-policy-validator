# IAM Validator

A high-performance GitHub Action and Python CLI tool that validates AWS IAM policies for correctness and security by checking against the official AWS Service Reference API.

## ✨ Features

### Core Validation
- **Real-time Validation**: Validates IAM actions against AWS's official service reference API
- **AWS IAM Access Analyzer Integration**: Validate policies using AWS's official policy validation service
- **Custom Policy Checks**: Verify policies don't grant specific actions, check for new access, and detect public exposure (29+ resource types supported)
- **Condition Key Checking**: Verifies that condition keys are valid for each action
- **ARN Format Validation**: Ensures resource ARNs follow proper AWS format with compiled regex patterns
- **Security Best Practices**: Identifies overly permissive policies and security risks

### Performance Enhancements
- **Service Pre-fetching**: Common AWS services cached at startup for faster validation
- **LRU Memory Cache**: Recently accessed services cached with TTL support
- **Request Coalescing**: Duplicate API requests automatically deduplicated
- **Parallel Check Execution**: Multiple validation checks run concurrently
- **HTTP/2 Support**: Multiplexed connections for better API performance
- **Optimized Connection Pool**: 20 keepalive connections, 50 max connections

### GitHub Integration
- **PR Comments**: Post detailed validation reports as PR comments
- **Line-Specific Reviews**: Add review comments on exact policy lines
- **Label Management**: Automatically add/remove PR labels based on results
- **Commit Status**: Set commit status to pass/fail based on validation
- **Comment Updates**: Update existing comments instead of creating duplicates

### Output Formats
- **Console**: Rich terminal output with colors and tables
- **JSON**: Structured format for programmatic processing
- **Markdown**: GitHub-flavored markdown for PR comments
- **SARIF**: GitHub code scanning integration format
- **CSV**: Spreadsheet-compatible format for analysis
- **HTML**: Interactive reports with filtering and search

### Extensibility
- **Plugin System**: Easy-to-add custom validation checks
- **Middleware Support**: Cross-cutting concerns like caching, timing, error handling
- **Formatter Registry**: Pluggable output format system
- **Configuration-Driven**: YAML-based configuration for all aspects

## Quick Start

### As a GitHub Action

#### Option 1: Basic Validation (Custom Checks Only)

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
        uses: actions/checkout@v4

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
            --fail-on-warnings
```

#### Option 2: Sequential Validation (Recommended) ⭐

Run AWS Access Analyzer first, then custom checks if it passes:

```yaml
name: Sequential IAM Policy Validation

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
        uses: actions/checkout@v4

      - name: Configure AWS Credentials
        uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: arn:aws:iam::123456789012:role/GitHubActionsRole
          aws-region: us-east-1

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.12'

      - name: Install uv
        uses: astral-sh/setup-uv@v3

      - name: Install dependencies
        run: uv sync

      - name: Sequential Validation
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
          GITHUB_REPOSITORY: ${{ github.repository }}
          GITHUB_PR_NUMBER: ${{ github.event.pull_request.number }}
        run: |
          # Posts 2 separate PR comments:
          # 1. Access Analyzer results (immediate)
          # 2. Custom validation (only if Access Analyzer passes)
          uv run iam-validator analyze \
            --path ./policies/ \
            --github-comment \
            --run-all-checks \
            --github-review \
            --fail-on-warnings
```

**Why Sequential Validation?**
- ✅ Access Analyzer validates first (fast, official AWS validation)
- ✅ If errors found, stops immediately (saves time)
- ✅ Only runs custom checks if Access Analyzer passes
- ✅ Two separate PR comments for clear separation

#### Option 3: Multiple Paths

Validate policies across multiple directories and files:

```yaml
name: Multi-Path IAM Policy Validation

on:
  pull_request:
    paths:
      - 'iam/**/*.json'
      - 's3-policies/**/*.json'
      - 'lambda-policies/**/*.json'

jobs:
  validate:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      pull-requests: write

    steps:
      - name: Checkout code
        uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.12'

      - name: Install uv
        uses: astral-sh/setup-uv@v3

      - name: Install dependencies
        run: uv sync

      - name: Validate Multiple Paths
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
          GITHUB_REPOSITORY: ${{ github.repository }}
          GITHUB_PR_NUMBER: ${{ github.event.pull_request.number }}
        run: |
          uv run iam-validator validate \
            --path ./iam/ \
            --path ./s3-policies/ \
            --path ./lambda-policies/special-policy.json \
            --github-comment \
            --github-review \
            --fail-on-warnings
```

#### Option 4: Custom Policy Checks in GitHub Actions

Use custom policy checks to enforce specific security requirements:

```yaml
name: IAM Policy Security Validation

on:
  pull_request:
    paths:
      - 'policies/**/*.json'

jobs:
  validate-with-custom-checks:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      pull-requests: write
      id-token: write

    steps:
      - name: Checkout code
        uses: actions/checkout@v4

      - name: Configure AWS Credentials
        uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: ${{ secrets.AWS_ROLE_ARN }}
          aws-region: us-east-1

      # Prevent dangerous actions
      - name: Check for Dangerous Actions
        uses: boogy/iam-policy-auditor@v1
        with:
          path: policies/
          use-access-analyzer: true
          check-access-not-granted: "s3:DeleteBucket iam:CreateAccessKey iam:AttachUserPolicy"
          post-comment: true
          fail-on-warnings: true

      # Check S3 bucket policies for public access
      - name: Check S3 Public Access
        uses: boogy/iam-policy-auditor@v1
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
        uses: boogy/iam-policy-auditor@v1
        with:
          path: policies/role-policy.json
          use-access-analyzer: true
          check-no-new-access: baseline/policies/role-policy.json
          post-comment: true
          fail-on-warnings: true
```

See [examples/github-actions/](examples/github-actions/) for more workflow examples including resource policies, multi-region validation, and custom policy checks.

### As a CLI Tool

```bash
# Clone and install
git clone https://github.com/boogy/iam-policy-auditor.git
cd iam-policy-auditor
uv sync

# Validate a single policy
uv run iam-validator validate --path policy.json

# Validate all policies in a directory
uv run iam-validator validate --path ./policies/

# Validate multiple paths (files and directories)
uv run iam-validator validate --path policy1.json --path ./policies/ --path ./more-policies/

# Generate JSON output
uv run iam-validator validate --path ./policies/ --format json --output report.json

# Post validation results to a PR with line-specific comments
uv run iam-validator validate --path ./policies/ --github-comment --github-review

# Two-step workflow: generate report, then post to PR
uv run iam-validator validate --path ./policies/ --format json --output report.json
uv run iam-validator post-to-pr --report report.json

# Validate with AWS IAM Access Analyzer
uv run iam-validator analyze --path policy.json

# Analyze with specific region and profile
uv run iam-validator analyze --path policy.json --region us-west-2 --profile my-profile

# Post Access Analyzer results to PR
uv run iam-validator analyze --path policy.json --github-comment

# Sequential validation: Access Analyzer → Custom Checks (if AA passes)
uv run iam-validator analyze \
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
uv run iam-validator analyze \
  --path ./policies/ \
  --check-access-not-granted s3:DeleteBucket s3:DeleteObject

# Scope to specific resources (wildcards only in resource ID portion)
uv run iam-validator analyze \
  --path ./policies/ \
  --check-access-not-granted s3:PutObject \
  --check-access-resources "arn:aws:s3:::production-bucket/*"

# Prevent privilege escalation
uv run iam-validator analyze \
  --path ./policies/ \
  --check-access-not-granted \
    iam:CreateAccessKey \
    iam:AttachUserPolicy \
    iam:PutUserPolicy
```

**Supported:** IDENTITY_POLICY, RESOURCE_POLICY

#### 2. CheckNoNewAccess - Validate Policy Updates

Ensure policy changes don't grant new permissions (both policies must be same type):

```bash
# Compare updated policy against baseline
uv run iam-validator analyze \
  --path ./new-policy.json \
  --check-no-new-access ./old-policy.json

# In CI/CD - compare against main branch
git show main:policies/policy.json > baseline-policy.json
uv run iam-validator analyze \
  --path policies/policy.json \
  --check-no-new-access baseline-policy.json
```

**Supported:** IDENTITY_POLICY, RESOURCE_POLICY

#### 3. CheckNoPublicAccess - Prevent Public Exposure

Validate that resource policies don't allow public access (RESOURCE_POLICY only, 29+ resource types):

```bash
# Check S3 bucket policies
uv run iam-validator analyze \
  --path ./bucket-policy.json \
  --policy-type RESOURCE_POLICY \
  --check-no-public-access \
  --public-access-resource-type "AWS::S3::Bucket"

# Check Lambda function policies
uv run iam-validator analyze \
  --path ./lambda-policy.json \
  --policy-type RESOURCE_POLICY \
  --check-no-public-access \
  --public-access-resource-type "AWS::Lambda::Function"

# Check KMS key policies
uv run iam-validator analyze \
  --path ./kms-policy.json \
  --policy-type RESOURCE_POLICY \
  --check-no-public-access \
  --public-access-resource-type "AWS::KMS::Key"

# Check multiple resource types at once
uv run iam-validator analyze \
  --path ./resource-policies/ \
  --policy-type RESOURCE_POLICY \
  --check-no-public-access \
  --public-access-resource-type "AWS::S3::Bucket" "AWS::Lambda::Function" "AWS::SNS::Topic"

# Check ALL 29 resource types
uv run iam-validator analyze \
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

See [docs/custom-policy-checks.md](docs/custom-policy-checks.md) for complete documentation and examples.

### As a Python Package

```bash
# Install from PyPI (once published)
pip install iam-policy-validator

# Or install from source
pip install git+https://github.com/boogy/iam-policy-auditor.git
```

```python
import asyncio
from iam_validator.core import PolicyLoader, validate_policies, ReportGenerator

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

## Memory Management & Performance

### Streaming Mode (Recommended for Large Policy Sets)

The validator supports two processing modes:

#### 1. **Batch Mode (Default)**
Loads all policies into memory at once. Best for:
- Small to medium policy sets (< 100 files)
- When you need the full summary upfront
- Local development

#### 2. **Streaming Mode** (`--stream`)
Processes policies one-by-one. Best for:
- Large policy sets (100+ files)
- CI/CD environments (auto-enabled)
- Limited memory environments
- Progressive feedback (see results as they come)

```bash
# Enable streaming mode explicitly
uv run iam-validator validate --path ./policies/ --stream

# Streaming mode with GitHub PR comments (posts per-file reviews progressively)
uv run iam-validator validate \
  --path ./policies/ \
  --stream \
  --github-comment \
  --github-review
```

**Streaming Benefits:**
- ✅ **Lower Memory Usage**: Only one policy in memory at a time
- ✅ **Progressive Feedback**: See results immediately as files are processed
- ✅ **Partial Results**: Get results even if later files fail
- ✅ **Better CI/CD Experience**: GitHub PR comments appear progressively
- ✅ **Auto-enabled in CI**: Automatically detects CI environment

**File Size Limits:**
- Default max file size: 100MB per policy file
- Files exceeding limit are skipped with a warning
- Prevents memory exhaustion from unexpectedly large files

### GitHub Action Memory Optimization

The GitHub Action automatically uses streaming mode in CI environments:

```yaml
- name: Validate Large Policy Set
  run: |
    # Streaming is auto-enabled in CI
    uv run iam-validator validate \
      --path ./policies/ \
      --github-comment \
      --github-review
```

## Configuration

### GitHub Action Inputs

| Input              | Description                                                 | Required | Default |
| ------------------ | ----------------------------------------------------------- | -------- | ------- |
| `path`             | Path(s) to IAM policy file or directory (newline-separated) | Yes      | -       |
| `fail-on-warnings` | Fail validation if warnings are found                       | No       | `false` |
| `post-comment`     | Post validation results as PR comment                       | No       | `true`  |
| `create-review`    | Create line-specific review comments on PR                  | No       | `true`  |

### Environment Variables

For GitHub integration:

- `GITHUB_TOKEN`: GitHub API token (automatically provided in GitHub Actions)
- `GITHUB_REPOSITORY`: Repository in format `owner/repo`
- `GITHUB_PR_NUMBER`: Pull request number

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

### Post PR Comments

Automatically posts validation results as PR comments:

```python
async with GitHubIntegration() as github:
    await github.post_comment(validation_report)
```

### Line-Specific Comments

Add comments to specific lines in policy files:

```python
comments = [
    {
        "path": "policies/policy.json",
        "line": 5,
        "body": "Invalid action detected here",
    }
]
await github.create_review_with_comments(comments)
```

### Manage Labels

Add or remove labels based on validation results:

```python
# Add labels
await github.add_labels(["iam-policy", "security-review"])

# Remove labels
await github.remove_label("needs-review")

# Set labels (replaces all existing)
await github.set_labels(["approved", "security-validated"])
```

### Set Commit Status

Update commit status based on validation:

```python
await github.set_commit_status(
    state="success",  # or "error", "failure", "pending"
    context="IAM Policy Validator",
    description="All policies validated successfully"
)
```

## CLI Usage

### Analyze Command (AWS IAM Access Analyzer)

The `analyze` command uses AWS IAM Access Analyzer's ValidatePolicy API to validate IAM policies. This provides AWS's official policy validation with detailed findings about errors, security warnings, and suggestions.

**New in latest version:** Post results to GitHub PRs and run sequential validation (Access Analyzer → Custom Checks).

**Prerequisites**: You need AWS credentials configured. The tool will use the standard AWS credential chain (environment variables, AWS profile, IAM role, etc.).

```bash
iam-validator analyze --path PATH [OPTIONS]

Options:
  --path PATH, -p PATH          Path to IAM policy file or directory (required)
  --format {console,json,markdown}
                                Output format (default: console)
  --output OUTPUT, -o OUTPUT    Output file path (only for json/markdown)
  --region REGION, -r REGION    AWS region for Access Analyzer (default: us-east-1)
  --policy-type {IDENTITY_POLICY,RESOURCE_POLICY,SERVICE_CONTROL_POLICY}
                                Type of IAM policy to validate (default: IDENTITY_POLICY)
  --profile PROFILE             AWS profile name to use for credentials
  --github-comment              Post Access Analyzer results as GitHub PR comment
  --run-all-checks              Run full validation if Access Analyzer passes
  --github-review               Add line-specific review comments (requires --run-all-checks)
  --no-recursive                Don't recursively search directories
  --fail-on-warnings            Fail validation if warnings are found
  --verbose, -v                 Enable verbose logging
```

**Examples**:

```bash
# Analyze a single identity policy
iam-validator analyze --path policy.json

# Analyze an S3 bucket policy (resource policy)
iam-validator analyze --path bucket-policy.json --policy-type RESOURCE_POLICY

# Analyze multiple paths
iam-validator analyze --path ./iam/ --path ./s3-policies/ --path bucket-policy.json

# Analyze with specific AWS profile and region
iam-validator analyze --path policy.json --profile prod --region us-west-2

# Post Access Analyzer results to PR
iam-validator analyze --path policy.json --github-comment

# Sequential validation: Run Access Analyzer, then custom checks if it passes
iam-validator analyze \
  --path policy.json \
  --github-comment \
  --run-all-checks \
  --github-review

# Generate JSON output
iam-validator analyze --path ./policies/ --format json --output analyzer-report.json

# Fail on any finding (including warnings and suggestions)
iam-validator analyze --path policy.json --fail-on-warnings
```

**Access Analyzer Finding Types**:
- **ERROR**: Syntax errors or invalid policy elements that prevent the policy from working
- **SECURITY_WARNING**: Security issues that should be addressed
- **WARNING**: Best practice violations or potential issues
- **SUGGESTION**: Recommendations for policy improvements

### Validate Command

```bash
iam-validator validate --path PATH [OPTIONS]

Options:
  --path PATH, -p PATH          Path to IAM policy file or directory (required)
  --format {console,json,markdown}
                                Output format (default: console)
  --output OUTPUT, -o OUTPUT    Output file path (only for json/markdown)
  --no-recursive                Don't recursively search directories
  --fail-on-warnings            Fail validation if warnings are found
  --github-comment              Post validation results as GitHub PR comment
  --github-review               Create line-specific review comments (requires --github-comment)
  --verbose, -v                 Enable verbose logging
```

### Post-to-PR Command

```bash
iam-validator post-to-pr --report REPORT [OPTIONS]

Options:
  --report REPORT, -r REPORT    Path to JSON report file (required)
  --create-review               Create line-specific review comments (default: true)
  --no-review                   Don't create line-specific review comments
  --add-summary                 Add summary comment (default: true)
  --no-summary                  Don't add summary comment
  --verbose, -v                 Enable verbose logging
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

## Development

### Project Structure

```
iam-policy-auditor/
├── action.yaml                          # GitHub Action definition
├── pyproject.toml                       # Python project configuration
├── iam_validator/                       # Main Python package
│   ├── iam_validator/
│   │   ├── __init__.py
│   │   ├── models.py                   # Pydantic models
│   │   ├── aws_fetcher.py              # AWS Service Reference API client
│   │   ├── github_integration.py       # GitHub API client
│   │   ├── cli.py                      # CLI interface
│   │   ├── utils.py                    # Utility functions
│   │   └── core/
│   │       ├── policy_loader.py        # Policy file loader
│   │       ├── policy_checks.py        # Validation logic
│   │       └── report.py               # Report generation
│   └── pyproject.toml
└── examples/
    ├── sample_policy.json              # Valid example
    └── invalid_policy.json             # Invalid example
```

### Running Tests

```bash
cd iam-policy-validator
uv run pytest
```

### Type Checking

```bash
uv run mypy iam_validator/
```

## Architecture

### AWS Service Reference API

The validator fetches real-time service information from AWS's official service reference API:

```
https://servicereference.us-east-1.amazonaws.com/
```

This ensures validation is always up-to-date with the latest AWS services and actions.

### Validation Flow

1. **Load Policies**: Parse JSON/YAML policy files
2. **Fetch Service Data**: Get service information from AWS API (with caching)
3. **Validate Actions**: Check each action against service definitions
4. **Validate Conditions**: Verify condition keys are valid for actions
5. **Validate Resources**: Check ARN format and structure
6. **Security Checks**: Identify security best practice violations
7. **Generate Report**: Create formatted output in desired format
8. **GitHub Integration**: Post comments/labels to PR (if enabled)

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
  - [Sample Policies](examples/policies/)
- **[Contributing Guide](CONTRIBUTING.md)** - Contribution guidelines
- **[Publishing Guide](docs/development/PUBLISHING.md)** - Release process

## 🤝 Contributing

Contributions are welcome! We appreciate your help in making this project better.

### How to Contribute

1. **Read the [Contributing Guide](CONTRIBUTING.md)** - Comprehensive guide for contributors
2. **Check [existing issues](https://github.com/boogy/iam-policy-auditor/issues)** - Find something to work on
3. **Fork the repository** - Create your own copy
4. **Make your changes** - Follow our code quality standards
5. **Submit a Pull Request** - We'll review and merge

### Development Setup

```bash
# Clone your fork
git clone https://github.com/YOUR-USERNAME/iam-policy-auditor.git
cd iam-policy-auditor

# Install dependencies
uv sync --extra dev

# Run tests
make test

# Run quality checks
make check
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for detailed instructions.

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🆘 Support

- **Documentation**: Check the [docs/](docs/) directory
- **Issues**: Report bugs or request features via [GitHub Issues](https://github.com/boogy/iam-policy-auditor/issues)
- **Questions**: Ask questions in [GitHub Discussions](https://github.com/boogy/iam-policy-auditor/discussions)
