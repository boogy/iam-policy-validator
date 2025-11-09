# Example Configuration Files

This directory contains example configuration files for different use cases and environments. Choose the one that best matches your needs or use them as a starting point for customization.

## Quick Reference

| Config File | Use Case | Fail On | Best For |
|------------|----------|---------|----------|
| [basic-config.yaml](basic-config.yaml) | Default setup | error, critical | Getting started |
| [full-reference-config.yaml](full-reference-config.yaml) | Complete documentation | error, critical, high | Learning all options |
| [strict-security.yaml](strict-security.yaml) | Production security | error, critical, high, medium | Production environments |
| [development-config.yaml](development-config.yaml) | Development | error, critical | Local development |
| [ci-cd-config.yaml](ci-cd-config.yaml) | CI/CD pipelines | error, critical, high | GitHub Actions, Jenkins |
| [security-audit-config.yaml](security-audit-config.yaml) | Comprehensive audits | all severities | Compliance, audits |
| [resource-policy-config.yaml](resource-policy-config.yaml) | Resource policies | error, critical, high | S3, SNS, KMS policies |
| [minimal-validation-config.yaml](minimal-validation-config.yaml) | Syntax only | error | Quick validation |
| [privilege-escalation-focus-config.yaml](privilege-escalation-focus-config.yaml) | Security focus | error, critical, high | Security reviews |

## Configuration Files

### 1. [basic-config.yaml](basic-config.yaml)
**Purpose:** Minimal configuration with sensible defaults
**Recommended for:** New users, general-purpose validation

```bash
iam-validator validate policies/ --config examples/configs/basic-config.yaml
```

**Features:**
- All built-in checks enabled with defaults
- Fails on: `error`, `critical`
- Balanced security and usability
- Good starting point for most teams

---

### 2. [full-reference-config.yaml](full-reference-config.yaml)
**Purpose:** Complete documentation of all available options
**Recommended for:** Learning the tool, advanced customization

**Features:**
- Documents all 18 built-in checks
- Shows all configuration options with comments
- Includes examples for every feature
- Reference for custom configurations

**Key Sections:**
- Global settings and severity levels
- Ignore patterns documentation
- All 18 checks with full options
- Action condition enforcement examples
- Category-based sensitive action filtering
- Principal validation for resource policies

**Note:** This is a reference document. Most users should start with a simpler config and add options as needed.

---

### 3. [strict-security.yaml](strict-security.yaml)
**Purpose:** Enforces strict security best practices
**Recommended for:** Production environments, compliance requirements

```bash
iam-validator validate policies/ --config examples/configs/strict-security.yaml
```

**Features:**
- Fails on: `error`, `critical`, `high`, `medium`
- Minimal allowed wildcards (read-only only)
- Strict action condition requirements
- Elevated severity for security issues
- Comprehensive IAM validation

**Use this when:**
- Deploying to production
- Meeting compliance requirements (SOC 2, PCI DSS)
- Enforcing least-privilege access
- Preventing privilege escalation

---

### 4. [development-config.yaml](development-config.yaml)
**Purpose:** Balanced validation for local development
**Recommended for:** Developer laptops, local testing

```bash
iam-validator validate policies/ --config examples/configs/development-config.yaml
```

**Features:**
- Fails on: `error`, `critical` only
- Security checks downgraded to `low` severity
- Ignores test/example directories
- Action condition enforcement disabled
- Fast feedback, helpful warnings

**Use this when:**
- Developing policies locally
- Rapid iteration needed
- Learning IAM policy syntax
- Prototyping access patterns

---

### 5. [ci-cd-config.yaml](ci-cd-config.yaml)
**Purpose:** Optimized for continuous integration pipelines
**Recommended for:** GitHub Actions, GitLab CI, Jenkins, CircleCI

```bash
iam-validator validate policies/ --config examples/configs/ci-cd-config.yaml
```

**Features:**
- `fail_fast: true` (stops on first error)
- Higher concurrency (`max_concurrent: 20`)
- Fails on: `error`, `critical`, `high`
- Focused on critical security issues
- Allows wildcards in test files only

**GitHub Actions Example:**
```yaml
- name: Validate IAM Policies
  uses: boogy/iam-policy-validator@v1
  with:
    config: examples/configs/ci-cd-config.yaml
    policy-path: policies/
```

**Use this when:**
- Validating PRs before merge
- Running in CI/CD pipelines
- Enforcing policy standards across team
- Preventing security regressions

---

### 6. [security-audit-config.yaml](security-audit-config.yaml)
**Purpose:** Comprehensive security audit with maximum strictness
**Recommended for:** Security audits, compliance reviews, penetration testing prep

```bash
iam-validator validate policies/ --config examples/configs/security-audit-config.yaml
```

**Features:**
- Fails on: ALL severity levels (error, warning, critical, high, medium, low)
- Reports every possible issue
- Maximum strictness on all checks
- Category-based sensitive action severities
- Blocks all public and cross-account access

**Use this when:**
- Conducting security audits
- Preparing for penetration testing
- Meeting compliance audit requirements
- Reviewing legacy policies for issues
- Generating comprehensive security reports

---

### 7. [resource-policy-config.yaml](resource-policy-config.yaml)
**Purpose:** Specialized validation for resource-based policies
**Recommended for:** S3 bucket policies, SNS topics, KMS keys, Lambda functions

```bash
iam-validator validate bucket-policy.json \
  --policy-type RESOURCE_POLICY \
  --config examples/configs/resource-policy-config.yaml
```

**Features:**
- Principal validation focus (critical)
- Blocks public access (`Principal: "*"`)
- Requires conditions for cross-account access
- Enforces secure transport
- Organization-based access control

**Validates:**
- S3 bucket policies
- SNS topic policies
- SQS queue policies
- KMS key policies
- Lambda function policies
- Secrets Manager resource policies

**Use this when:**
- Reviewing S3 bucket policies
- Validating cross-account access
- Preventing public data exposure
- Enforcing organization boundaries

---

### 8. [minimal-validation-config.yaml](minimal-validation-config.yaml)
**Purpose:** Only validates AWS IAM syntax, no security checks
**Recommended for:** Quick syntax validation, CI gates

```bash
iam-validator validate policies/ --config examples/configs/minimal-validation-config.yaml
```

**Features:**
- Fails on: `error` only (IAM validity)
- All security checks disabled
- Only checks if policy will work in AWS
- Fastest validation mode
- No best practice recommendations

**Use this when:**
- Only checking syntax errors
- Validating third-party policies
- Running quick pre-commit checks
- Working with legacy policies
- Speed is critical

---

### 9. [privilege-escalation-focus-config.yaml](privilege-escalation-focus-config.yaml)
**Purpose:** Focused on detecting privilege escalation paths
**Recommended for:** Security reviews, IAM security assessments

```bash
iam-validator validate policies/ --config examples/configs/privilege-escalation-focus-config.yaml
```

**Features:**
- Fails on: `error`, `critical`, `high`
- Only checks `priv_esc` category sensitive actions
- Detects dangerous action combinations
- Requires MFA for IAM operations
- Enforces permissions boundaries
- Custom messages for escalation risks

**Detects:**
- `iam:CreateUser` + `iam:AttachUserPolicy` combinations
- `iam:PassRole` with Lambda/EC2 (role assumption attacks)
- IAM policy version manipulation
- Missing permissions boundaries
- MFA bypass opportunities

**Use this when:**
- Conducting IAM security reviews
- Assessing privilege escalation risks
- Reviewing developer/contractor access
- Preparing for security certifications

---

## Additional Configuration Files

### Policy-Level Condition Enforcement
- **[policy-level-condition-enforcement-config.yaml](policy-level-condition-enforcement-config.yaml)**
  Demonstrates policy-level action detection for privilege escalation patterns

### Principal Validation Variants
- **[principal-validation-strict.yaml](principal-validation-strict.yaml)**
  No public or cross-account access allowed

- **[principal-validation-relaxed.yaml](principal-validation-relaxed.yaml)**
  Allows cross-account with organization restrictions

- **[principal-validation-public-with-conditions.yaml](principal-validation-public-with-conditions.yaml)**
  Allows public access with required conditions

- **[principal-condition-enforcement.yaml](principal-condition-enforcement.yaml)**
  Advanced principal condition requirements

### Offline Validation
- **[offline-validation.yaml](offline-validation.yaml)**
  Uses pre-downloaded AWS service definitions for air-gapped environments

---

## Usage Examples

### Local Development
```bash
# Quick check during development
iam-validator validate my-policy.json --config examples/configs/development-config.yaml
```

### CI/CD Pipeline
```yaml
# .github/workflows/validate-policies.yml
- name: Validate IAM Policies
  run: |
    iam-validator validate policies/ \
      --config examples/configs/ci-cd-config.yaml \
      --format json \
      --output-file results.json
```

### Pre-Production Review
```bash
# Before deploying to production
iam-validator validate policies/ \
  --config examples/configs/strict-security.yaml \
  --format enhanced
```

### Security Audit
```bash
# Comprehensive security audit
iam-validator validate all-policies/ \
  --config examples/configs/security-audit-config.yaml \
  --format html \
  --output-file audit-report.html
```

### Resource Policy Validation
```bash
# Validate S3 bucket policy
iam-validator validate s3-bucket-policy.json \
  --policy-type RESOURCE_POLICY \
  --config examples/configs/resource-policy-config.yaml
```

---

## Customization Guide

### Starting from Scratch

1. **Start with basic-config.yaml**
   ```bash
   cp examples/configs/basic-config.yaml my-config.yaml
   ```

2. **Add ignore patterns for your codebase**
   ```yaml
   wildcard_action:
     ignore_patterns:
       - filepath_regex: "^terraform/modules/.*"
       - statement_sid: "AllowTerraformBackend"
   ```

3. **Adjust fail_on_severity for your workflow**
   ```yaml
   settings:
     fail_on_severity:
       - error
       - critical
       # Add high/medium as you improve policies
   ```

4. **Enable stricter checks gradually**
   ```yaml
   action_condition_enforcement:
     enabled: true  # Start here
     severity: high
   ```

### Environment-Based Configuration

Use different configs per environment:

```bash
# Development
iam-validator validate policies/ --config config/dev.yaml

# Staging
iam-validator validate policies/ --config config/staging.yaml

# Production
iam-validator validate policies/ --config config/prod.yaml
```

### Combining with Python API

For advanced customization, use Python API with config:

```python
from iam_validator import IAMPolicyValidator

validator = IAMPolicyValidator(
    config_file="examples/configs/strict-security.yaml"
)

# Override specific settings programmatically
validator.config["sensitive_action"]["categories"] = ["priv_esc"]
validator.config["settings"]["fail_on_severity"].append("medium")

issues = validator.validate_file("policy.json")
```

---

## Configuration Best Practices

### 1. **Start Loose, Tighten Gradually**
- Begin with `development-config.yaml`
- Add checks as team learns IAM best practices
- Move to `strict-security.yaml` for production

### 2. **Use Environment-Specific Configs**
- Development: Relaxed (fast feedback)
- CI/CD: Moderate (catch critical issues)
- Production: Strict (maximum security)

### 3. **Leverage Ignore Patterns**
- Don't disable entire checks
- Use regex patterns to ignore specific cases
- Document why each pattern exists

### 4. **Focus on High-Value Checks First**
- Privilege escalation detection
- Public access prevention
- Sensitive action conditions

### 5. **Customize Sensitive Actions**
- Use categories to focus on relevant risks
- Override severities per category
- Add custom action patterns for your org

---

## See Also

- [Configuration Guide](../../docs/configuration.md) - Complete configuration reference
- [Condition Requirements](../../docs/condition-requirements.md) - Action condition enforcement
- [Custom Checks](../../docs/custom-checks.md) - Writing custom validation checks
- [Privilege Escalation](../../docs/privilege-escalation.md) - Understanding escalation risks
- [Modular Configuration](../../docs/modular-configuration.md) - Python-based configuration system

---

## Getting Help

If you need help choosing the right configuration:

1. **New to IAM Policy Validator?**
   Start with `basic-config.yaml`

2. **Deploying to production?**
   Use `strict-security.yaml`

3. **Running in CI/CD?**
   Use `ci-cd-config.yaml`

4. **Validating resource policies?**
   Use `resource-policy-config.yaml`

5. **Need comprehensive security audit?**
   Use `security-audit-config.yaml`

For questions or issues, please [open an issue](https://github.com/iam-policy-auditor/issues) or refer to the [documentation](../../README.md).
