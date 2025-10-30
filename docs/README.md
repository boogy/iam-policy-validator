# IAM Policy Validator Documentation

This directory contains comprehensive documentation for the IAM Policy Validator.

## Main Documentation

**[→ Complete Documentation (DOCS.md)](../DOCS.md)** - Start here for comprehensive user documentation

**[→ Quick Start (README.md)](../README.md)** - Project overview and quick start guide

## Documentation Index

### User Guides
- **[AWS Services Backup](aws-services-backup.md)** - Download AWS services for offline validation
- **[Configuration Reference](configuration.md)** - YAML configuration options and examples
- **[Custom Checks Guide](custom-checks.md)** - Creating custom validation rules
- **[Privilege Escalation Detection](privilege-escalation.md)** - Policy-level privilege escalation patterns
- **[Smart Filtering](smart-filtering.md)** ⭐ - Automatic IAM policy detection and filtering

### Integration Guides
- **[GitHub Actions Workflows](github-actions-workflows.md)** - Complete workflow setup guide with OIDC
- **[GitHub Actions Examples](github-actions-examples.md)** - Additional workflow patterns and use cases

### Developer Documentation
- **[Publishing Guide](development/PUBLISHING.md)** - Release process and version management

## Examples

All practical examples are in the **[examples/](../examples/)** directory:
- **[GitHub Actions Workflows](../examples/github-actions/)** - 8 ready-to-use workflow examples
- **[Custom Checks](../examples/custom_checks/)** - 8 custom validation check implementations
- **[Configuration Files](../examples/configs/)** - 3 essential configuration examples
- **[Test IAM Policies](../examples/iam-test-policies/)** - 36 test policies (JSON + YAML) covering various scenarios

---

**Quick Links:**
- [Installation Guide](../DOCS.md#installation)
- [CLI Reference](../DOCS.md#cli-reference)
- [Custom Policy Checks](../DOCS.md#custom-policy-checks)
- [Contributing Guide](../CONTRIBUTING.md)
