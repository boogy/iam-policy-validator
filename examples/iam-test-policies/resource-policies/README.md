# Resource Policy Test Examples

This directory contains comprehensive resource policy examples designed to test various validation scenarios supported by the IAM Policy Validator.

## Overview

Resource-based policies are attached to AWS resources (like S3 buckets, SNS topics, KMS keys) and specify who can access the resource and what actions they can perform. These test policies demonstrate both **secure** and **insecure** configurations to help validate the tool's detection capabilities.

## Policy Categories

### S3 Bucket Policies

| File | Description | Test Scenario |
|------|-------------|---------------|
| `s3-bucket-policy-public.json` | Public read access without conditions | ❌ Should fail: Public access (`*`) without required conditions |
| `s3-bucket-policy-public-with-conditions.json` | Public access restricted to CloudFront | ✅ Should pass: Public access with `aws:SourceArn` condition |
| `s3-bucket-policy-cloudfront.json` | CloudFront OAI access | ✅ Should pass: Service principal with proper conditions |
| `s3-bucket-policy-specific-account.json` | Cross-account access to specific account | ✅ Should pass: Specific account ARN |
| `s3-bucket-policy-cross-account-org.json` | Cross-account with org validation | ✅ Should pass: Wildcard root with `aws:PrincipalOrgID` |
| `s3-bucket-policy-insecure-transport.json` | Allows HTTP connections | ❌ Should fail: `aws:SecureTransport` set to `false` |
| `s3-bucket-policy-wildcard-actions.json` | Uses wildcard actions (`s3:*`, `s3:Get*`) | ⚠️ Should warn: Wildcard actions detected |
| `s3-bucket-policy-vpc-endpoint.json` | VPC endpoint restricted access | ✅ Should pass: Public access with `aws:SourceVpce` |
| `s3-bucket-policy-ip-restriction.json` | IP-based access control with HTTPS enforcement | ✅ Should pass: Multiple security layers |

### SNS Topic Policies

| File | Description | Test Scenario |
|------|-------------|---------------|
| `sns-topic-policy-public-no-conditions.json` | Public publish without conditions | ❌ Should fail: Public principal without conditions |
| `sns-topic-policy-cross-account.json` | Cross-account with MFA (existing) | ✅ Should pass: Specific ARNs with conditions |
| `sns-topic-policy-eventbridge.json` | EventBridge integration | ✅ Should pass: Public with `aws:SourceArn` |
| `sns-topic-policy-cross-account-mfa.json` | Cross-account requiring MFA | ✅ Should pass: MFA enforcement |
| `sns-topic-policy-org-wide.json` | Organization-wide access | ✅ Should pass: Org ID validation |

### SQS Queue Policies

| File | Description | Test Scenario |
|------|-------------|---------------|
| `sqs-queue-policy-public.json` | Public access without restrictions | ❌ Should fail: Public access without conditions |
| `sqs-queue-policy-sns-subscription.json` | SNS topic subscription | ✅ Should pass: Public with source ARN/account |
| `sqs-queue-policy-cross-account-role.json` | Cross-account role with VPC endpoint | ✅ Should pass: Specific roles with VPC restriction |
| `sqs-queue-policy-iam-users-mfa.json` | IAM users requiring MFA and IP | ✅/⚠️ Depends on config: Tests MFA+IP requirements |

### KMS Key Policies

| File | Description | Test Scenario |
|------|-------------|---------------|
| `kms-key-policy-cross-account.json` | Cross-account without restrictions (existing) | ❌ Should fail: Cross-account root without org check |
| `kms-key-policy-insecure.json` | Overly permissive cross-account | ❌ Should fail: `arn:aws:iam::*:root` without conditions |
| `kms-key-policy-org-restricted.json` | Organization-scoped with service restrictions | ✅ Should pass: Org ID + service validation |
| `kms-key-policy-service-specific.json` | Service-specific with encryption context | ✅ Should pass: Service principals with context checks |

### Lambda Function Policies

| File | Description | Test Scenario |
|------|-------------|---------------|
| `lambda-permission-api-gateway.json` | API Gateway invoke (existing) | ✅ Should pass: Service principal with source ARN |
| `lambda-permission-s3-trigger.json` | S3 event trigger | ✅ Should pass: S3 service with account validation |
| `lambda-permission-eventbridge-multiple.json` | Multiple EventBridge rules | ✅ Should pass: Multiple source ARNs |
| `lambda-permission-public-url.json` | Public function URL | ⚠️ Should warn: Public access for webhook |
| `lambda-permission-cross-account-invoke.json` | Cross-account invoke | ⚠️ May warn: Cross-account without conditions |

### Other Resource Policies

| File | Description | Test Scenario |
|------|-------------|---------------|
| `secrets-manager-policy-cross-account.json` | Cross-account secret access | ✅ Should pass: Specific roles with version condition |
| `ecr-repository-policy-public.json` | Public container registry | ❌ Should fail: Public ECR without conditions |
| `ecr-repository-policy-org-restricted.json` | Organization-scoped ECR | ✅ Should pass: Org-restricted registry |
| `efs-filesystem-policy-vpc-only.json` | VPC-restricted file system | ✅ Should pass: Mount target restriction |
| `glacier-vault-policy-cross-account.json` | Cross-account backup vault | ✅ Should pass: Org-scoped archive access |
| `opensearch-domain-policy-ip-restricted.json` | IP-restricted OpenSearch | ✅ Should pass: IP-based access control |
| `backup-vault-policy-org-access.json` | Centralized backup with delete protection | ✅ Should pass: Org access + deny policy |

## Validation Checks Tested

### Principal Validation
- **Public Access (`*`)**: Must have conditions like `aws:SourceArn`, `aws:SourceAccount`, `aws:SourceVpce`, or `aws:SourceIp`
- **Cross-Account Root (`arn:aws:iam::*:root`)**: Should have `aws:PrincipalOrgID` condition
- **IAM Roles**: May require MFA or VPC endpoint (based on config)
- **IAM Users**: May require MFA and IP restrictions (based on config)

### Security Checks
- **Insecure Transport**: Policies must never allow `aws:SecureTransport: false`
- **Wildcard Actions**: Detection of `*`, `s3:*`, `s3:Get*` patterns
- **Wildcard Resources**: Policies using `"Resource": "*"`
- **Service Wildcards**: Actions like `s3:*` expanding to 100+ permissions

### Action & Resource Validation
- **Action Validation**: Checks if actions are valid for the service
- **Condition Key Validation**: Validates condition keys are appropriate
- **Policy Size**: Ensures policies don't exceed AWS limits
- **SID Uniqueness**: Verifies statement IDs are unique

## Usage with IAM Policy Validator

### Test All Policies
```bash
# Validate all resource policies with default checks
iam-validator validate examples/iam-test-policies/resource-policies/

# Use strict security configuration
iam-validator validate examples/iam-test-policies/resource-policies/ \
  --config examples/configs/strict-security.yaml

# Generate detailed report
iam-validator validate examples/iam-test-policies/resource-policies/ \
  --format enhanced \
  --output validation-report.txt
```

### Test Specific Scenarios

**Public Access Validation:**
```bash
# Should catch policies without proper conditions
iam-validator validate examples/iam-test-policies/resource-policies/s3-bucket-policy-public.json
iam-validator validate examples/iam-test-policies/resource-policies/sns-topic-policy-public-no-conditions.json
```

**Insecure Transport Detection:**
```bash
# Should fail on aws:SecureTransport=false
iam-validator validate examples/iam-test-policies/resource-policies/s3-bucket-policy-insecure-transport.json
```

**Cross-Account Security:**
```bash
# Should require organization validation
iam-validator validate examples/iam-test-policies/resource-policies/kms-key-policy-insecure.json
```

**Wildcard Action Detection:**
```bash
# Should detect and warn about wildcards
iam-validator validate examples/iam-test-policies/resource-policies/s3-bucket-policy-wildcard-actions.json
```

### Configuration-Specific Testing

Different configurations enable different checks:

```bash
# Basic validation (public access + prevent insecure transport)
iam-validator validate examples/iam-test-policies/resource-policies/ \
  --config examples/configs/basic-config.yaml

# Strict validation (all principal requirements + action enforcement)
iam-validator validate examples/iam-test-policies/resource-policies/ \
  --config examples/configs/strict-security.yaml

# Principal-focused validation
iam-validator validate examples/iam-test-policies/resource-policies/ \
  --config examples/configs/principal-validation-strict.yaml
```

## Expected Validation Results

### Policies That Should FAIL ❌
- `s3-bucket-policy-public.json` - Public access without conditions
- `s3-bucket-policy-insecure-transport.json` - Allows HTTP
- `sns-topic-policy-public-no-conditions.json` - Public SNS without conditions
- `sqs-queue-policy-public.json` - Public SQS without conditions
- `kms-key-policy-insecure.json` - Cross-account without org check
- `ecr-repository-policy-public.json` - Public ECR without conditions

### Policies That Should WARN ⚠️
- `s3-bucket-policy-wildcard-actions.json` - Wildcard actions
- `lambda-permission-public-url.json` - Public function URL
- `lambda-permission-cross-account-invoke.json` - Cross-account without conditions
- `sqs-queue-policy-iam-users-mfa.json` - Depends on principal validation config

### Policies That Should PASS ✅
- All policies with proper condition enforcement
- Service-specific policies with source validation
- Org-restricted cross-account policies
- VPC endpoint and IP-restricted policies

## Testing Framework Integration

These policies can be used in automated testing:

```python
# Python example
from iam_validator import Validator
from iam_validator.core.config_loader import load_config

config = load_config("examples/configs/strict-security.yaml")
validator = Validator(config)

# Test that insecure policies fail
result = validator.validate_file(
    "examples/iam-test-policies/resource-policies/s3-bucket-policy-public.json"
)
assert result.has_errors, "Public policy without conditions should fail"

# Test that secure policies pass
result = validator.validate_file(
    "examples/iam-test-policies/resource-policies/s3-bucket-policy-vpc-endpoint.json"
)
assert not result.has_errors, "VPC endpoint policy should pass"
```

## Contributing

When adding new test policies:
1. Follow the naming convention: `{service}-{resource}-policy-{scenario}.json`
2. Add documentation to this README
3. Include clear SID values explaining the scenario
4. Test with multiple configurations
5. Document expected validation results

## Related Documentation

- [Configuration Guide](../../docs/configuration.md)
- [Principal Validation](../../docs/configuration.md#principal-validation)
- [Condition Requirements](../../docs/condition-requirements.md)
- [GitHub Actions Examples](../github-actions/)
