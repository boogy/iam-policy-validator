# IAM Policy Validator Documentation

Comprehensive documentation for validating AWS IAM policies with confidence.

## 🚀 Start Here

| Document                      | Purpose                  | Audience  |
| ----------------------------- | ------------------------ | --------- |
| **[README.md](../README.md)** | Quick start and overview | New users |
| **[DOCS.md](../DOCS.md)**     | Complete reference guide | All users |

## 📖 Core Documentation

### Validation & Checks
- **[Check Reference Guide](check-reference.md)** - All 19 checks with pass/fail examples
  - Policy structure validation
  - AWS correctness checks (11)
  - Security best practices (6)
  - Trust policy validation (opt-in)
- **[Configuration Reference](configuration.md)** - Customize validation rules and behavior
- **[Condition Requirements](condition-requirements.md)** - Enforce IAM conditions on sensitive actions
- **[Privilege Escalation Detection](privilege-escalation.md)** - Detect cross-statement risks

### Integration & Usage
- **[GitHub Actions Workflows](github-actions-workflows.md)** - CI/CD integration guide
- **[GitHub Actions Examples](github-actions-examples.md)** - Workflow patterns and examples
- **[Python Library Usage](python-library-usage.md)** - Programmatic validation in Python
- **[Custom Checks Guide](custom-checks.md)** - Write organization-specific checks

### Advanced Topics
- **[Modular Configuration](modular-configuration.md)** - Python-based configuration architecture
- **[Smart Filtering](smart-filtering.md)** - Automatic IAM policy detection
- **[AWS Services Backup](aws-services-backup.md)** - Offline validation setup
- **[AWS API Configuration](aws-api-configuration.md)** - AWS Access Analyzer integration

## 👨‍💻 Developer Resources

### Development
- **[Contributing Guide](../CONTRIBUTING.md)** - Development setup and guidelines
- **[Publishing Guide](development/PUBLISHING.md)** - Release process
- **[Pre-release Guide](development/pre-release-guide.md)** - Pre-release workflow
- **[Roadmap](ROADMAP.md)** - Planned features and improvements

### SDK & API
- **[SDK Documentation](SDK.md)** - Python SDK reference

## 📚 Examples

Find practical examples in [examples/](../examples/):

### Configuration Examples
- [Configuration Files](../examples/configs/) - 9+ config templates
  - Basic, strict security, offline, CI/CD configs
  - Principal validation variants
  - Privilege escalation focus

### Code Examples
- [GitHub Actions](../examples/github-actions/) - 7+ workflow examples
- [Custom Checks](../examples/custom_checks/) - 8+ custom check implementations
- [Library Usage](../examples/library-usage/) - 5 Python examples

### Test Cases
- [Test Policies](../examples/iam-test-policies/) - 50+ test policies
- [Trust Policies](../examples/trust-policies/) - Trust policy examples
  - AWS service roles
  - Cross-account access
  - SAML federation
  - OIDC federation (GitHub Actions)

## 🔗 Quick Links by Task

**I want to...**
- **Get started quickly** → [README.md](../README.md) → [Quick Start](../DOCS.md#quick-start)
- **Understand all checks** → [Check Reference Guide](check-reference.md)
- **Configure the validator** → [Configuration Reference](configuration.md)
- **Use in GitHub Actions** → [GitHub Actions Guide](github-actions-workflows.md)
- **Use as Python library** → [Python Library Guide](python-library-usage.md)
- **Validate trust policies** → [Trust Policy Examples](../examples/trust-policies/README.md)
- **Write custom checks** → [Custom Checks Guide](custom-checks.md)
- **Detect privilege escalation** → [Privilege Escalation Guide](privilege-escalation.md)
- **Work offline** → [AWS Services Backup](aws-services-backup.md)
- **Contribute** → [Contributing Guide](../CONTRIBUTING.md)
