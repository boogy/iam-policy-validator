# IAM Policy Validator Documentation

Comprehensive documentation for validating AWS IAM policies with confidence.

## Start Here

| Document                      | Purpose                  | Audience  |
| ----------------------------- | ------------------------ | --------- |
| **[README.md](../README.md)** | Quick start and overview | New users |
| **[DOCS.md](../DOCS.md)**     | Complete reference guide | All users |

## User Guides

### Getting Started
- **[Python Library Usage](python-library-usage.md)** - Programmatic validation in Python
- **[Configuration Reference](configuration.md)** - Customize validation rules
- **[Custom Checks Guide](custom-checks.md)** - Write organization-specific checks

### Advanced Topics
- **[Condition Requirements](condition-requirements.md)** - Enforce IAM conditions on sensitive actions
- **[Modular Configuration](modular-configuration.md)** - Python-based configuration architecture
- **[Privilege Escalation Detection](privilege-escalation.md)** - Detect cross-statement risks
- **[Smart Filtering](smart-filtering.md)** - Automatic IAM policy detection

### Integration
- **[GitHub Actions Workflows](github-actions-workflows.md)** - CI/CD integration guide
- **[GitHub Actions Examples](github-actions-examples.md)** - Workflow patterns
- **[AWS Services Backup](aws-services-backup.md)** - Offline validation setup

## Developer Resources

- **[Roadmap](ROADMAP.md)** - Planned features and improvements
- **[Publishing Guide](development/PUBLISHING.md)** - Release process
- **[Contributing Guide](../CONTRIBUTING.md)** - Development guidelines

## Examples

Find practical examples in [examples/](../examples/):
- [GitHub Actions](../examples/github-actions/) - 9 workflow examples
- [Custom Checks](../examples/custom_checks/) - Example implementations
- [Configurations](../examples/configs/) - 8 configuration files
- [Test Policies](../examples/iam-test-policies/) - 56 test policies
- [Library Usage](../examples/library-usage/) - 5 Python examples
