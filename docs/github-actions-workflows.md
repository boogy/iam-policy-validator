# GitHub Actions Workflow Examples

This directory contains example GitHub Actions workflows for validating IAM policies using the IAM Policy Auditor.

## Available Workflows

### 1. Basic Validation (`basic-validation.yml`)

Simple workflow that validates IAM policies on every pull request using custom checks.

**Features:**
- Validates on PR changes to policy files
- Posts results as PR comment
- Adds line-specific review comments
- Fails on warnings

**Use case:** Standard validation for most projects.

### 2. Access Analyzer Only (`access-analyzer-only.yml`)

Uses only AWS IAM Access Analyzer for validation.

**Features:**
- Official AWS validation service
- Requires AWS credentials (OIDC recommended)
- Fast validation
- Posts results to PR

**Use case:** When you want official AWS validation without custom checks.

### 3. Sequential Validation (`sequential-validation.yml`) ⭐ **RECOMMENDED**

Runs Access Analyzer first, then custom checks if it passes.

**Features:**
- Two-stage validation (Access Analyzer → Custom Checks)
- Early exit if Access Analyzer finds errors
- Two separate PR comments
- Saves time by skipping custom checks on basic errors

**Use case:** Best of both worlds - official AWS validation followed by custom security checks.

### 4. Two-Step Validation (`two-step-validation.yml`)

Separates validation from PR commenting into two jobs.

**Features:**
- Generate report in one job
- Review before posting (optional)
- Post to PR in separate job
- Useful for approval workflows

**Use case:** When you need to review validation results before posting to PR.

### 5. Resource Policy Validation (`resource-policy-validation.yml`)

Specialized workflow for validating resource policies (S3 bucket policies, SNS topics, etc.).

**Features:**
- Validates resource policies (not identity policies)
- Separate validation for S3 policies
- Uses `--policy-type RESOURCE_POLICY` flag

**Use case:** Projects with S3 bucket policies, SNS topic policies, or other resource-based policies.

### 6. Multi-Region Validation (`multi-region-validation.yml`)

Validates policies across multiple AWS regions.

**Features:**
- Matrix strategy for multiple regions
- Validates in us-east-1, us-west-2, eu-west-1
- Aggregates results across regions
- Posts summary to PR

**Use case:** Ensure policies work consistently across regions.

## Quick Start

1. **Choose a workflow** from the examples above
2. **Copy to your repository**: `.github/workflows/iam-validation.yml`
3. **Update paths** to match your repository structure
4. **Configure AWS credentials** (if using Access Analyzer)
5. **Commit and push** to trigger the workflow

## AWS Credentials Setup

Most workflows require AWS credentials for Access Analyzer. We recommend using OpenID Connect (OIDC) for secure authentication:

### Option 1: OIDC (Recommended)

1. **Create IAM Role** in AWS:

```bash
# Create trust policy
cat > trust-policy.json <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Federated": "arn:aws:iam::YOUR_ACCOUNT_ID:oidc-provider/token.actions.githubusercontent.com"
      },
      "Action": "sts:AssumeRoleWithWebIdentity",
      "Condition": {
        "StringEquals": {
          "token.actions.githubusercontent.com:aud": "sts.amazonaws.com"
        },
        "StringLike": {
          "token.actions.githubusercontent.com:sub": "repo:YOUR_ORG/YOUR_REPO:*"
        }
      }
    }
  ]
}
EOF

# Create the role
aws iam create-role \
  --role-name GitHubActionsRole \
  --assume-role-policy-document file://trust-policy.json
```

2. **Attach policy** for Access Analyzer:

```bash
cat > access-analyzer-policy.json <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "access-analyzer:ValidatePolicy",
      "Resource": "*"
    }
  ]
}
EOF

aws iam put-role-policy \
  --role-name GitHubActionsRole \
  --policy-name AccessAnalyzerValidation \
  --policy-document file://access-analyzer-policy.json
```

3. **Use in workflow**:

```yaml
- name: Configure AWS Credentials
  uses: aws-actions/configure-aws-credentials@v4
  with:
    role-to-assume: arn:aws:iam::YOUR_ACCOUNT_ID:role/GitHubActionsRole
    aws-region: us-east-1
```

### Option 2: AWS Access Keys (Not Recommended)

If you can't use OIDC, store AWS credentials as GitHub Secrets:

1. Add secrets: `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY`
2. Use in workflow:

```yaml
- name: Configure AWS Credentials
  uses: aws-actions/configure-aws-credentials@v4
  with:
    aws-access-key-id: ${{ secrets.AWS_ACCESS_KEY_ID }}
    aws-secret-access-key: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
    aws-region: us-east-1
```

## Customization

### Change Policy Paths

Update the `paths` filter and `--path` argument:

```yaml
on:
  pull_request:
    paths:
      - 'iam/**/*.json'  # Your policy directory

# ...

run: |
  uv run iam-validator validate --path ./iam/
```

### Adjust Failure Behavior

```yaml
# Fail on warnings
--fail-on-warnings

# Don't fail on warnings (only fail on errors)
# Remove the --fail-on-warnings flag
```

### Change Output Format

```yaml
# Console output (default)
--format console

# JSON output
--format json --output report.json

# Markdown output
--format markdown --output report.md
```

### Control GitHub Output

The validator provides **three independent options** for displaying validation results:

```yaml
# 1. PR Summary Comment - Posts to PR conversation
--github-comment

# 2. Line-Specific Review Comments - Posts to "Files changed" tab
--github-review

# 3. GitHub Actions Job Summary - Posts to Actions tab
--github-summary

# All three for maximum visibility
--github-comment --github-review --github-summary

# Only inline review comments (clean, minimal)
--github-review

# Only Actions job summary (no PR interaction)
--github-summary

# PR comment + Actions summary (no inline comments)
--github-comment --github-summary

# No GitHub output (local/CI validation only)
# Remove all GitHub flags
```

**Review Status Logic:**
- Review comments use `fail_on_severity` config to determine status
- If any issues match severities in config → REQUEST_CHANGES
- Otherwise → COMMENT
- Default: REQUEST_CHANGES for `error` and `critical` severities

## Environment Variables

All workflows support these environment variables:

| Variable            | Description                    | Required                |
| ------------------- | ------------------------------ | ----------------------- |
| `GITHUB_TOKEN`      | GitHub API token               | Yes (for PR comments)   |
| `GITHUB_REPOSITORY` | Repository (owner/repo)        | Yes (for PR comments)   |
| `GITHUB_PR_NUMBER`  | Pull request number            | Yes (for PR comments)   |
| `AWS_REGION`        | AWS region for Access Analyzer | No (default: us-east-1) |

## Troubleshooting

### Workflow fails with "access-analyzer:ValidatePolicy permission denied"

**Solution:** Ensure your AWS role has the `access-analyzer:ValidatePolicy` permission.

### No PR comments appear

**Solution:** Check that the workflow has `pull-requests: write` permission:

```yaml
permissions:
  contents: read
  pull-requests: write
```

### Line-specific comments on wrong lines

**Solution:** Ensure policy files are well-formatted JSON. Use `jq` to format:

```bash
jq '.' policy.json > formatted.json
```

## Additional Resources

- [CLI Reference](../../docs/reference/CLI.md)
- [PR Comments Guide](../../docs/guides/PR_COMMENTS.md)
- [Main README](../../README.md)
