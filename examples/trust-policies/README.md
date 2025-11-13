# Trust Policy Examples

This directory contains example trust policies (role assumption policies) for IAM roles.

Trust policies control **who can assume a role** and under what conditions. They are attached to IAM roles and use the `Principal` element to specify the trusted entities.

## What are Trust Policies?

Trust policies are resource-based policies attached to IAM roles that define:
- **Who** can assume the role (Principal)
- **How** they can assume it (Action: AssumeRole, AssumeRoleWithSAML, etc.)
- **When** they can assume it (Condition)


### Explicit Validation (Required)

Trust policies **require** the `--policy-type TRUST_POLICY` flag for proper validation:

```bash
iam-validator validate trust-policy.json --policy-type TRUST_POLICY
```

**Why explicit flag is required:**
- ✅ Suppresses irrelevant warnings (missing Resource field - trust policies don't need it)
- ✅ Enables trust-specific validation (action-principal coupling, provider ARNs, required conditions)
- ✅ Avoids false positives from mixed-purpose policies
- ✅ Clear and explicit about policy intent

**Benefits of explicit flag:**
- Action-principal type matching (AssumeRoleWithSAML requires Federated)
- Provider ARN format validation (SAML vs OIDC)
- **Required `aud` condition for SAML and OIDC**
- No confusing missing Resource warnings

**Without the flag:**
```bash
# ❌ Not recommended - shows irrelevant warnings
iam-validator validate trust-policy.json
```

You'll see:
- ℹ️ Hint: "This is a TRUST POLICY. Use --policy-type TRUST_POLICY"
- ℹ️ Warning: "Statement is missing Resource field" (not applicable to trust policies)
### With Custom Configuration

```bash
iam-validator validate trust-policy.json \
  --policy-type TRUST_POLICY \
  --config trust-policy-config.yaml
```

**trust-policy-config.yaml:**
```yaml
trust_policy_validation:
  enabled: true  # Enabled by default
  severity: high
  # Optional: customize validation rules
  # validation_rules:
  #   sts:AssumeRole:
  #     allowed_principal_types: ["AWS"]  # Only AWS, not Service
  #     required_conditions: ["sts:ExternalId"]
  #   sts:TagSession:
  #     allowed_principal_types: ["AWS", "Service", "Federated"]
```

## Example Trust Policies

### 1. [lambda-service-role-trust-policy.json](lambda-service-role-trust-policy.json)
**Use Case:** Allow Lambda service to assume this role

```bash
iam-validator validate examples/trust-policies/lambda-service-role-trust-policy.json \
  --policy-type TRUST_POLICY
```

**What it validates:**
- ✅ Service principal (`lambda.amazonaws.com`) is allowed for `sts:AssumeRole`
- ✅ No conditions required for AWS service principals

---

### 2. [github-actions-oidc-trust-policy.json](github-actions-oidc-trust-policy.json)
**Use Case:** Allow GitHub Actions to assume this role using OIDC

```bash
iam-validator validate examples/trust-policies/github-actions-oidc-trust-policy.json \
  --policy-type TRUST_POLICY
```

**What it validates:**
- ✅ Federated principal with OIDC provider
- ✅ `AssumeRoleWithWebIdentity` matches Federated principal type
- ✅ OIDC provider ARN format is correct
- ✅ Required conditions for GitHub Actions (aud, sub)

---

### 3. [saml-federated-trust-policy.json](saml-federated-trust-policy.json)
**Use Case:** Allow SAML-based federated access

```bash
iam-validator validate examples/trust-policies/saml-federated-trust-policy.json \
  --policy-type TRUST_POLICY
```

**What it validates:**
- ✅ Federated principal with SAML provider
- ✅ `AssumeRoleWithSAML` matches Federated principal type
- ✅ SAML provider ARN format is correct
- ✅ Required `SAML:aud` condition is present

---

### 4. [cross-account-trust-policy.json](cross-account-trust-policy.json)
**Use Case:** Allow another AWS account to assume this role

```bash
iam-validator validate examples/trust-policies/cross-account-trust-policy.json \
  --policy-type TRUST_POLICY
```

**What it validates:**
- ✅ AWS principal (IAM account root) is allowed for `sts:AssumeRole`
- ✅ `ExternalId` condition is present to prevent confused deputy attacks

---

## Trust Policy Validation Check

The `trust_policy_validation` check ensures:

### 1. Action-Principal Type Matching

| Action                          | Allowed Principal Types     |
| ------------------------------- | --------------------------- |
| `sts:AssumeRole`                | `AWS`, `Service`            |
| `sts:AssumeRoleWithSAML`        | `Federated` (SAML provider) |
| `sts:AssumeRoleWithWebIdentity` | `Federated` (OIDC provider) |

### 2. Provider ARN Format Validation

- **SAML providers**: `arn:aws:iam::account-id:saml-provider/provider-name`
- **OIDC providers**: `arn:aws:iam::account-id:oidc-provider/domain`

### 3. Required Conditions

- **SAML**: Requires `SAML:aud` condition
- **OIDC**: Recommends provider-specific conditions (e.g., `token.actions.githubusercontent.com:aud`)

## How it Complements Other Checks

Trust policy validation works alongside:

### `principal_validation` Check
- **Focus**: Which principals are allowed/blocked
- **Example**: Block public access (`Principal: "*"`)
- **Applies to**: ALL resource policies

### `trust_policy_validation` Check (New)
- **Focus**: Action-principal type coupling
- **Example**: `AssumeRoleWithSAML` must use Federated principal
- **Applies to**: Trust policies (assume role actions)

### `action_condition_enforcement` Check
- **Focus**: Required conditions for actions
- **Example**: Specific actions need MFA or IP restrictions
- **Applies to**: ALL policies

**All three checks complement each other without conflicts!**

## Common Patterns

### AWS Service Trust (Lambda, EC2, ECS, etc.)
```json
{
  "Effect": "Allow",
  "Principal": {"Service": "SERVICE.amazonaws.com"},
  "Action": "sts:AssumeRole"
}
```

### Cross-Account Trust
```json
{
  "Effect": "Allow",
  "Principal": {"AWS": "arn:aws:iam::ACCOUNT:root"},
  "Action": "sts:AssumeRole",
  "Condition": {
    "StringEquals": {"sts:ExternalId": "SECRET"}
  }
}
```

### SAML Federation
```json
{
  "Effect": "Allow",
  "Principal": {"Federated": "arn:aws:iam::ACCOUNT:saml-provider/PROVIDER"},
  "Action": "sts:AssumeRoleWithSAML",
  "Condition": {
    "StringEquals": {"SAML:aud": "https://signin.aws.amazon.com/saml"}
  }
}
```

### OIDC Federation (GitHub Actions, Google, etc.)
```json
{
  "Effect": "Allow",
  "Principal": {"Federated": "arn:aws:iam::ACCOUNT:oidc-provider/DOMAIN"},
  "Action": "sts:AssumeRoleWithWebIdentity",
  "Condition": {
    "StringEquals": {"DOMAIN:aud": "sts.amazonaws.com"}
  }
}
```

## Best Practices

1. **Always use conditions** for cross-account trust
2. **Use ExternalId** for untrusted accounts
3. **Use PrincipalOrgID** for organization accounts
4. **Validate SAML:aud** for SAML federation
5. **Restrict OIDC subjects** to specific repos/domains
6. **Avoid wildcard principals** (`"*"`) in trust policies

## See Also

- [Principal Validation Check](../docs/check-reference.md#principal-validation)
- [AWS Trust Policies Documentation](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_terms-and-concepts.html#iam-term-trust-policy)
- [Custom Check: Cross-Account ExternalId](../custom_checks/cross_account_external_id_check.py)
