# Security Policy

## Overview

The IAM Policy Validator is a security-focused tool designed to catch IAM policy errors before they reach production. We take the security of this project seriously, as it plays a critical role in helping organizations maintain secure AWS environments.

## Reporting a Vulnerability

We appreciate responsible disclosure of security vulnerabilities. If you discover a security issue, please report it privately.

### Where to Report

**DO NOT** create a public GitHub issue for security vulnerabilities.

Instead, please report security issues via one of these methods:

1. **GitHub Security Advisories** (Preferred)

   - Go to the [Security Advisories page](https://github.com/boogy/iam-policy-validator/security/advisories)
   - Click "Report a vulnerability"
   - Provide detailed information about the vulnerability

2. **Email** (Alternative)
   - Send to: `0xboogy [at] gmail [dot] com`
   - Use the subject line: `[SECURITY] IAM Policy Validator - <Brief Description>`

### What to Include

When reporting a vulnerability, please include:

- **Description**: A clear description of the vulnerability
- **Impact**: The potential impact and severity assessment
- **Steps to Reproduce**: Detailed steps to reproduce the issue
- **Proof of Concept**: Code, configuration, or commands demonstrating the vulnerability
- **Affected Versions**: Which versions are impacted
- **Suggested Fix**: If you have recommendations for fixing the issue
- **Your Contact Information**: How we can reach you for follow-up questions

### Example Report Format

```
## Vulnerability Description
[Describe the vulnerability]

## Impact
[Describe the potential impact]

## Steps to Reproduce
1. [Step 1]
2. [Step 2]
3. [Step 3]

## Affected Versions
- Version: 1.7.0
- Components: [e.g., policy parser, AWS API client]

## Suggested Fix
[Optional: Your recommendations]

## Contact
- Name: [Your name]
- Email: [Your email]
```

## Response Timeline

> [!NOTE]: This is an open source project maintained by volunteers in their free time. While we take security seriously and will make our best effort to respond promptly, the timelines below are goals rather than guarantees. Critical security issues will be prioritized, but actual resolution times may vary based on maintainer availability and the complexity of the issue.

We aim to respond to security reports according to the following timeline:

- **Initial Response**: Within 48-72 hours of report submission (best effort)
- **Status Update**: Within 1 week with initial assessment
- **Resolution Timeline**: Varies based on severity and maintainer availability
  - **Critical**: Prioritized for urgent patching (best effort within 1-2 weeks)
  - **High**: Addressed as soon as possible (typically 2-4 weeks)
  - **Medium**: Included in upcoming releases (typically 4-8 weeks)
  - **Low**: Addressed in regular maintenance cycles

We appreciate your patience and understanding as we work to address security issues while balancing other project commitments.

## Security Update Process

When a security vulnerability is confirmed:

1. **Acknowledgment**: We'll acknowledge receipt and confirm the issue
2. **Investigation**: Our team will investigate and assess the severity
3. **Fix Development**: We'll develop and test a fix
4. **Coordinated Disclosure**: We'll coordinate disclosure timing with the reporter
5. **Release**: We'll release a patched version
6. **Advisory**: We'll publish a security advisory with details
7. **Credit**: We'll credit the reporter (unless they prefer to remain anonymous)

## Security Best Practices

### For Users

When using IAM Policy Validator in production:

1. **Use Latest Version**: Always use the latest stable release
2. **Review Dependencies**: Regularly update dependencies to patch known vulnerabilities
3. **Secure AWS Credentials**:
   - Never commit AWS credentials to version control
   - Use IAM roles with OIDC for GitHub Actions (avoid long-lived credentials)
   - Follow the principle of least privilege for validation roles
4. **GitHub Token Security**:
   - Use the automatic `github.token` when possible
   - If using custom tokens, use fine-grained permissions
   - Rotate tokens regularly
5. **Configuration Files**: Review `.iam-validator.yaml` for sensitive data before committing
6. **Custom Checks**: Audit custom validation checks for security issues
7. **Network Security**: When using offline validation, verify downloaded AWS service definitions

### Recommended IAM Policy for Validator

When using AWS Access Analyzer, grant minimal permissions:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "access-analyzer:ValidatePolicy",
        "access-analyzer:CheckAccessNotGranted",
        "access-analyzer:CheckNoNewAccess",
        "access-analyzer:CheckNoPublicAccess"
      ],
      "Resource": "*"
    }
  ]
}
```

### For Contributors

When contributing to the project:

1. **Code Review**: All code changes require security-focused review
2. **Dependency Updates**: Use `uv lock` to ensure reproducible builds
3. **Secrets Management**: Never commit secrets, API keys, or credentials
4. **Input Validation**: Validate and sanitize all user inputs
5. **Secure Defaults**: Use secure defaults in all configurations
6. **Testing**: Write security-focused tests for new features
7. **Documentation**: Document security implications of new features

## Known Security Considerations

### AWS Credentials

- The tool requires AWS credentials when using Access Analyzer features
- Credentials are handled by boto3 and never logged or stored by this tool
- We recommend using temporary credentials via IAM roles with OIDC

### GitHub Token Access

- GitHub tokens are used for posting comments and reviews
- Tokens require `contents: read` and `pull-requests: write` permissions
- The tool only accesses the specific PR/repository being validated
- Tokens are never logged or persisted to disk

### Policy Content

- The tool processes IAM policy documents that may contain sensitive information
- Policy content is only sent to AWS Access Analyzer when explicitly enabled
- No policy content is sent to third-party services
- Logs may contain policy content - review log levels in production

### Third-Party Dependencies

- We use standard Python dependencies (httpx, boto3, pydantic, etc.)
- Dependencies are pinned in `uv.lock` for reproducibility
- We monitor dependencies for known vulnerabilities via GitHub Dependabot
- Regular dependency updates are performed and tested

### Offline Validation

- AWS service definitions can be cached locally for air-gapped environments
- Cached definitions should be periodically refreshed
- Verify the integrity of downloaded service definitions

## Security Features

The validator includes security features to help users:

1. **19 Built-in Security Checks**: Detect overly permissive policies, privilege escalation paths, and security anti-patterns
2. **AWS Access Analyzer Integration**: Leverage AWS's official policy validation service
3. **Privilege Escalation Detection**: Identify dangerous action combinations
4. **Public Access Detection**: Check 29+ AWS resource types for public exposure
5. **Action Condition Enforcement**: Ensure sensitive actions have required conditions
6. **Policy Comparison**: Detect new permissions vs baseline to prevent scope creep
7. **Wildcard Detection**: Flag overly permissive wildcards in actions and resources

### Safe Harbor

We support safe harbor for security researchers who:

- Make a good faith effort to avoid privacy violations and data destruction
- Report vulnerabilities privately and allow reasonable time for fixes
- Do not exploit vulnerabilities for malicious purposes
- Follow responsible disclosure practices

### GitHub Integration

Configure minimal permissions for GitHub Actions:

```yaml
permissions:
  contents: read # Required: Read repository content
  pull-requests: write # Required: Post PR comments
  id-token: write # Required only for AWS OIDC authentication
```

## Contact

For security-related questions or concerns:

- **Security Issues**: Use GitHub Security Advisories or email `0xboogy [at] gmail [dot] com`
- **General Questions**: Use [GitHub Discussions](https://github.com/boogy/iam-policy-validator/discussions)
- **Bug Reports**: Use [GitHub Issues](https://github.com/boogy/iam-policy-validator/issues) (non-security only)

## Acknowledgments

We appreciate the security research community's efforts in responsibly disclosing vulnerabilities. Security researchers who report valid vulnerabilities will be credited in:

- Security advisories (unless they prefer to remain anonymous)
- Release notes for the patched version
- This SECURITY.md file (Hall of Fame section below)

### Security Researchers Hall of Fame

_Thank you to the following researchers who have helped improve the security of this project:_

- None yet - be the first!

## Additional Resources

- [OWASP Secure Coding Practices](https://owasp.org/www-project-secure-coding-practices-quick-reference-guide/)
- [AWS Security Best Practices](https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html)
- [GitHub Security Best Practices](https://docs.github.com/en/code-security/getting-started/github-security-features)
- [Contributing Guide](CONTRIBUTING.md)

---

**Last Updated**: 2026-01-19
**Policy Version**: 1.1
