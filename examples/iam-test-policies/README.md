# IAM Test Policies

This directory contains example IAM policies organized by policy type for testing and validation.

## Directory Structure

### 📁 identity-policies/
Identity-based policies that can be attached to IAM users, groups, or roles.

**Characteristics:**
- No `Principal` element (implicit - the attached entity)
- Define what actions the identity can perform
- Examples: user policies, role policies, group policies

**Validate with:**
```bash
iam-validator validate --path identity-policies/ --policy-type IDENTITY_POLICY
```

**Count:** 40 policies (JSON and YAML)

---

### 📁 resource-policies/
Resource-based policies attached to AWS resources (S3 buckets, SNS topics, KMS keys, etc.).

**Characteristics:**
- MUST have `Principal` element (who can access)
- Attached directly to resources
- Define who can access the resource and what they can do
- Examples: S3 bucket policies, SNS topic policies, KMS key policies, Lambda permissions

**Validate with:**
```bash
iam-validator validate --path resource-policies/ --policy-type RESOURCE_POLICY
```

**Advanced validation with principal security checks:**
```bash
iam-validator validate \
  --path resource-policies/ \
  --policy-type RESOURCE_POLICY \
  --config ../../configs/principal-validation-strict.yaml
```

**Count:** 7 policies

---

### 📁 resource-control-policies/
AWS Organizations Resource Control Policies (RCPs) for resource-level access control.

**Characteristics:**
- Effect MUST be `"Deny"` (only AWS-managed RCPFullAWSAccess can use "Allow")
- Principal MUST be `"*"` (use Condition to restrict)
- Action cannot use `"*"` alone (must be service-specific like `"s3:*"`)
- Only 5 supported services: `s3`, `sts`, `sqs`, `secretsmanager`, `kms`
- NotAction and NotPrincipal NOT supported
- Must have Resource or NotResource element

**Validate with:**
```bash
iam-validator validate --path resource-control-policies/ --policy-type RESOURCE_CONTROL_POLICY
```

**Count:** 6 policies

**Examples included:**
- ✅ Valid: Enforce encryption in transit
- ❌ Invalid: Allow effect (must be Deny)
- ❌ Invalid: Unsupported service (EC2)
- ❌ Invalid: Wildcard action ("*" not allowed)
- ❌ Invalid: Specific principal (must be "*")
- ❌ Invalid: NotAction element

---

### 📁 service-control-policies/
AWS Organizations Service Control Policies (SCPs) for permission guardrails.

**Characteristics:**
- Must NOT have `Principal` element (applies to all principals in OU)
- Typically uses `Deny` effect for guardrails
- Sets maximum available permissions for accounts in organization
- Examples: Prevent region usage, deny root user actions, enforce tagging

**Validate with:**
```bash
iam-validator validate --path service-control-policies/ --policy-type SERVICE_CONTROL_POLICY
```

**Count:** 3 policies

**Examples included:**
- Deny root account usage
- Restrict AWS regions
- Require MFA for all operations

---

## Quick Testing

### Test all policy types
```bash
# Test each type separately
iam-validator validate --path identity-policies/ --policy-type IDENTITY_POLICY
iam-validator validate --path resource-policies/ --policy-type RESOURCE_POLICY
iam-validator validate --path resource-control-policies/ --policy-type RESOURCE_CONTROL_POLICY
iam-validator validate --path service-control-policies/ --policy-type SERVICE_CONTROL_POLICY

# Test all at once (uses auto-detection and provides hints)
iam-validator validate --path .
```

### Test specific features

**SID validation (spaces and special characters):**
```bash
iam-validator validate --path identity-policies/invalid-sid-with-spaces.json
iam-validator validate --path identity-policies/invalid-sid-special-chars.json
```

**Principal validation (strict mode - blocks public access):**
```bash
iam-validator validate \
  --path resource-policies/s3-bucket-policy-public.json \
  --policy-type RESOURCE_POLICY \
  --config ../../configs/principal-validation-strict.yaml
```

**RCP validation (service restrictions):**
```bash
iam-validator validate \
  --path resource-control-policies/rcp-invalid-unsupported-service.json \
  --policy-type RESOURCE_CONTROL_POLICY
```

---

## Policy Type Summary

| Type | Principal | Use Case | Count |
|------|-----------|----------|-------|
| **Identity** | ❌ No | Attached to IAM users/roles/groups | 40 |
| **Resource** | ✅ Required | Attached to AWS resources | 7 |
| **RCP** | ✅ Must be "*" | AWS Organizations resource control | 6 |
| **SCP** | ❌ No | AWS Organizations permission guardrails | 3 |

---

## Contributing

Want to add more example policies? Please ensure:
1. Policy is valid JSON
2. Policy is placed in the correct type folder
3. Policy name is descriptive (e.g., `deny-root-account-usage.json` for SCPs)
4. Policy includes realistic use cases

For invalid/test policies, prefix with `invalid-` (e.g., `invalid-sid-with-spaces.json`)
