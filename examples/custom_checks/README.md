# Custom Check Examples

This directory contains examples of custom policy checks that demonstrate how to extend the IAM Policy Validator.

## What are Custom Checks?

Custom checks allow you to implement organization-specific validation rules beyond the built-in checks. They are Python classes that inherit from `PolicyCheck` and can be loaded dynamically through configuration.

## How to Create a Custom Check

### 1. Create a Python Class

Your custom check must:
- Inherit from `iam_validator.core.check_registry.PolicyCheck`
- Implement required properties: `check_id`, `description`
- Implement the `execute()` method to perform your validation

```python
from typing import List
from iam_validator.core.check_registry import PolicyCheck, CheckConfig
from iam_validator.models import ValidationIssue, Statement
from iam_validator.core.aws_fetcher import AWSServiceFetcher


class MyCustomCheck(PolicyCheck):
    @property
    def check_id(self) -> str:
        return "my_custom_check"

    @property
    def description(self) -> str:
        return "My custom validation rule"

    @property
    def default_severity(self) -> str:
        return "warning"  # or "error", "info"

    async def execute(
        self,
        statement: Statement,
        statement_idx: int,
        fetcher: AWSServiceFetcher,
        config: CheckConfig,
    ) -> List[ValidationIssue]:
        issues = []

        # Your validation logic here
        # Access statement properties:
        # - statement.effect ("Allow" or "Deny")
        # - statement.get_actions()
        # - statement.get_resources()
        # - statement.condition
        # - statement.sid

        # Create issues when violations found:
        if some_condition:
            issues.append(ValidationIssue(
                severity=self.get_severity(config),
                statement_sid=statement.sid,
                statement_index=statement_idx,
                issue_type="my_issue_type",
                message="Description of what's wrong",
                suggestion="How to fix it",
            ))

        return issues
```

### 2. Configure in .iam-validator.yaml

Add your custom check to the configuration file:

```yaml
custom_checks:
  - module: "path.to.your.module.MyCustomCheck"
    enabled: true
    config:
      # Check-specific configuration
      your_setting: "value"
```

### 3. Make Your Module Importable

Ensure your custom check is in Python's import path:

**Option A: Install as a package**
```bash
pip install -e /path/to/your/checks
```

**Option B: Add to PYTHONPATH**
```bash
export PYTHONPATH=/path/to/your/checks:$PYTHONPATH
```

**Option C: Place in project directory**
Place your checks in a directory within your project that's already importable.

## Example Checks in This Directory

This directory contains **8 production-ready custom check examples** ranging from simple to highly complex:

### Basic Examples (Good Starting Points)

1. **[domain_restriction_check.py](domain_restriction_check.py)** - Domain Restriction Check
   - **Complexity**: ⭐ Basic
   - **Use Case**: Restrict S3 bucket access to specific domains
   - **What it teaches**: Basic condition validation, pattern matching
   - **Configuration**: Domain whitelist

2. **[region_restriction_check.py](region_restriction_check.py)** - Region Restriction Check
   - **Complexity**: ⭐ Basic
   - **Use Case**: Enforce approved AWS regions for compliance
   - **What it teaches**: Condition key validation, list matching
   - **Configuration**: Allowed regions list

3. **[mfa_required_check.py](mfa_required_check.py)** - MFA Requirement Check
   - **Complexity**: ⭐⭐ Intermediate
   - **Use Case**: Require MFA for sensitive actions
   - **What it teaches**: Action pattern matching, boolean conditions
   - **Configuration**: Action lists and patterns

4. **[tag_enforcement_check.py](tag_enforcement_check.py)** - Tag Enforcement Check
   - **Complexity**: ⭐⭐ Intermediate
   - **Use Case**: Enforce tagging for cost allocation and governance
   - **What it teaches**: Tag condition validation, required vs optional tags
   - **Configuration**: Required tags per action type

5. **[encryption_required_check.py](encryption_required_check.py)** - Encryption Requirement Check
   - **Complexity**: ⭐⭐ Intermediate
   - **Use Case**: Ensure S3 objects and EBS volumes are encrypted
   - **What it teaches**: Service-specific conditions, security controls
   - **Configuration**: Encryption methods and algorithms

### Advanced Examples

6. **[time_based_access_check.py](time_based_access_check.py)** - Time-Based Access Control
   - **Complexity**: ⭐⭐⭐ Advanced
   - **Use Case**: Restrict deployments to business hours, enforce maintenance windows
   - **What it teaches**: Time condition validation, multiple operator handling
   - **Features**:
     - Business hours restrictions
     - Maintenance window enforcement
     - Multiple time condition support
   - **Real-world scenario**: "Only allow production deployments Mon-Fri 9am-5pm UTC"

7. **[cross_account_external_id_check.py](cross_account_external_id_check.py)** - Cross-Account ExternalId Validation
   - **Complexity**: ⭐⭐⭐⭐ Advanced
   - **Use Case**: Prevent "confused deputy" attacks in cross-account access
   - **What it teaches**: Principal parsing, security best practices, ExternalId validation
   - **Features**:
     - Account ID extraction from ARNs
     - Trusted account lists
     - ExternalId format validation with regex
     - Detailed security recommendations
   - **Real-world scenario**: "Ensure all third-party service integrations use ExternalId"

8. **[advanced_multi_condition_validator.py](advanced_multi_condition_validator.py)** - Multi-Condition Policy Validator ⭐ HIGHLY COMPLEX
   - **Complexity**: ⭐⭐⭐⭐⭐ Expert Level
   - **Use Case**: Enterprise-grade policy validation with multiple layered conditions
   - **What it teaches**: Context-aware validation, complex rule engines, exception handling
   - **Features**:
     - Action category-based rules
     - "All of" and "Any of" condition logic
     - Resource pattern matching
     - Exception rules and overrides
     - IP range validation
     - Value format validation
     - Nested condition validation
     - Detailed actionable recommendations
   - **Real-world scenario**: "For critical infrastructure changes, require: MFA + Corporate IP + Approved Region + Business Hours + Resource Tags"

## Comparison Table

| Check                     | Complexity | Lines of Code | Features                            | Best For                 |
| ------------------------- | ---------- | ------------- | ----------------------------------- | ------------------------ |
| Domain Restriction        | ⭐          | ~120          | Basic pattern matching              | Learning basics          |
| Region Restriction        | ⭐          | ~130          | List validation                     | Simple compliance        |
| MFA Required              | ⭐⭐         | ~150          | Pattern matching, bool conditions   | Security basics          |
| Tag Enforcement           | ⭐⭐         | ~160          | Tag validation                      | Governance               |
| Encryption Required       | ⭐⭐         | ~180          | Service-specific rules              | Data security            |
| Time-Based Access         | ⭐⭐⭐        | ~250          | Time conditions, multiple operators | Change control           |
| Cross-Account ExternalId  | ⭐⭐⭐⭐       | ~350          | ARN parsing, trusted lists, regex   | Third-party integrations |
| Multi-Condition Validator | ⭐⭐⭐⭐⭐      | ~550+         | All of the above + logic engine     | Enterprise security      |

## Learning Path

### Beginner: Start Here
1. Read and understand **domain_restriction_check.py**
2. Modify it for your use case
3. Try **region_restriction_check.py** next

### Intermediate: Build on Basics
4. Study **mfa_required_check.py** for pattern matching
5. Implement **tag_enforcement_check.py** for governance
6. Add **encryption_required_check.py** for security

### Advanced: Production-Grade Checks
7. Analyze **time_based_access_check.py** for complex conditions
8. Study **cross_account_external_id_check.py** for security patterns
9. Master **advanced_multi_condition_validator.py** for enterprise needs

## Quick Start

### Using Auto-Discovery (Easiest)

```yaml
# In iam-validator.yaml
custom_checks_dir: "./examples/custom_checks"

checks:
  mfa_required:
    enabled: true
    severity: error
    require_mfa_for:
      - "iam:DeleteUser"
      - "s3:DeleteBucket"
```

### Using Explicit Module Path

```yaml
custom_checks:
  - module: "examples.custom_checks.mfa_required_check.MFARequiredCheck"
    enabled: true
    config:
      require_mfa_for:
        - "iam:DeleteUser"
```

## Configuration Examples

### Example 1: Simple MFA Enforcement

```yaml
custom_checks_dir: "./examples/custom_checks"

checks:
  mfa_required:
    enabled: true
    severity: error
    require_mfa_for:
      - "iam:DeleteUser"
      - "iam:DeleteRole"
      - "s3:DeleteBucket"
    require_mfa_patterns:
      - "^iam:Delete.*"
```

### Example 2: Time-Based Deployment Control

```yaml
custom_checks_dir: "./examples/custom_checks"

checks:
  time_based_access:
    enabled: true
    severity: error
    time_restricted_actions:
      - actions:
          - "cloudformation:CreateStack"
          - "lambda:UpdateFunctionCode"
        required_conditions:
          - condition_key: "aws:CurrentTime"
            description: "Deployments only 9am-5pm UTC, Mon-Fri"
```

### Example 3: Cross-Account Security

```yaml
custom_checks_dir: "./examples/custom_checks"

checks:
  cross_account_external_id:
    enabled: true
    severity: error
    trusted_accounts:
      - "123456789012"  # Your org account
    require_external_id_pattern: "^[a-zA-Z0-9-]{32,}$"
```

### Example 4: Enterprise Multi-Condition (Complex)

```yaml
custom_checks_dir: "./examples/custom_checks"

checks:
  advanced_multi_condition:
    enabled: true
    severity: error
    action_categories:
      critical_operations:
        actions:
          - "cloudformation:CreateStack"
          - "lambda:UpdateFunctionCode"
        required_conditions:
          all_of:
            - condition_key: "aws:MultiFactorAuthPresent"
              operators: ["Bool"]
              expected_value: "true"
            - condition_key: "aws:SourceIp"
              operators: ["IpAddress"]
              allowed_ip_ranges:
                - "203.0.113.0/24"
```

## Common Patterns

### Pattern 1: Action Matching
```python
def _matches_action(self, action: str, patterns: List[str]) -> bool:
    for pattern in patterns:
        if "*" in pattern:
            regex = pattern.replace("*", ".*")
            if re.match(f"^{regex}$", action):
                return True
    return False
```

### Pattern 2: Condition Validation
```python
def _has_condition(self, statement: Statement, key: str) -> bool:
    if not statement.condition:
        return False
    for operator in ["StringEquals", "StringLike", "Bool"]:
        if operator in statement.condition:
            if key in statement.condition[operator]:
                return True
    return False
```

### Pattern 3: Creating Issues
```python
issues.append(ValidationIssue(
    severity=self.get_severity(config),
    message=f"Statement {idx}: Missing required condition",
    check_id=self.check_id,
    statement_index=idx,
    recommendation="Add condition: {...}"
))
```

## Testing Your Custom Checks

Create test policies in your project:

```bash
# Test policy
cat > test-policy.json << EOF
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": "iam:DeleteUser",
    "Resource": "*"
  }]
}
EOF

# Run validation
uv run iam-validator validate \
  --path test-policy.json \
  --config iam-validator.yaml
```

### 1. Domain Restriction Check

**File:** [`domain_restriction_check.py`](domain_restriction_check.py)

**Purpose:** Ensures all resources in policies match approved domain patterns.

**Use Case:** Enforce that IAM policies can only grant access to resources in approved namespaces (e.g., production buckets, specific DynamoDB tables).

**Configuration Example:**
```yaml
custom_checks:
  - module: "examples.custom_checks.domain_restriction_check.DomainRestrictionCheck"
    enabled: true
    config:
      approved_domains:
        - "arn:aws:s3:::prod-*"
        - "arn:aws:s3:::shared-*"
        - "arn:aws:dynamodb:*:*:table/prod-*"
```

### 2. MFA Required Check

**File:** [`mfa_required_check.py`](mfa_required_check.py)

**Purpose:** Ensures sensitive IAM actions require Multi-Factor Authentication.

**Use Case:** Enforce MFA for sensitive operations like user deletion, role deletion, or bucket deletion to prevent unauthorized access.

**Configuration Example:**
```yaml
custom_checks:
  - module: "examples.custom_checks.mfa_required_check.MFARequiredCheck"
    enabled: true
    config:
      require_mfa_for:
        - "iam:DeleteUser"
        - "iam:DeleteRole"
        - "s3:DeleteBucket"
      # Or use regex patterns
      require_mfa_patterns:
        - "^iam:Delete.*"
        - "^s3:DeleteBucket.*"
```

### 3. Region Restriction Check

**File:** [`region_restriction_check.py`](region_restriction_check.py)

**Purpose:** Validates that policies only grant access to resources in approved regions.

**Use Case:** Enforce data residency requirements, cost control, and compliance by limiting resource access to specific AWS regions.

**Configuration Example:**
```yaml
custom_checks:
  - module: "examples.custom_checks.region_restriction_check.RegionRestrictionCheck"
    enabled: true
    config:
      approved_regions:
        - "us-east-1"
        - "us-west-2"
        - "eu-west-1"
      require_region_condition: true
```

### 4. Encryption Required Check

**File:** [`encryption_required_check.py`](encryption_required_check.py)

**Purpose:** Ensures policies require encryption for sensitive data operations.

**Use Case:** Enforce encryption-at-rest and encryption-in-transit for data operations to meet compliance requirements (SOC 2, HIPAA, etc.).

**Configuration Example:**
```yaml
custom_checks:
  - module: "examples.custom_checks.encryption_required_check.EncryptionRequiredCheck"
    enabled: true
    config:
      require_encryption_for:
        - "s3:PutObject"
        - "s3:CreateBucket"
        - "dynamodb:CreateTable"
      require_secure_transport: true
```

### 5. Tag Enforcement Check

**File:** [`tag_enforcement_check.py`](tag_enforcement_check.py)

**Purpose:** Ensures resource creation/modification actions require specific tags.

**Use Case:** Enforce tagging for cost allocation, compliance tracking, and resource organization. Ensure all resources have required tags like Environment, Owner, CostCenter.

**Configuration Example:**
```yaml
custom_checks:
  - module: "examples.custom_checks.tag_enforcement_check.TagEnforcementCheck"
    enabled: true
    config:
      require_tags_for:
        - "ec2:RunInstances"
        - "s3:CreateBucket"
        - "dynamodb:CreateTable"
      required_tags:
        - "Environment"
        - "Owner"
        - "CostCenter"
```

## Custom Check Best Practices

### 1. Clear Naming
- Use descriptive check IDs (e.g., `org_compliance_check` not `check1`)
- Write clear, actionable error messages
- Provide helpful suggestions for fixing issues

### 2. Configuration
- Make checks configurable through the `config` parameter
- Provide sensible defaults
- Document all configuration options in your check's docstring

### 3. Error Handling
- Handle edge cases gracefully
- Don't crash on unexpected input
- Use try/except blocks for risky operations

### 4. Performance
- Make your checks efficient
- Avoid unnecessary API calls
- Consider caching if making external requests

### 5. Testing
- Write unit tests for your custom checks
- Test with various policy structures
- Include edge cases

## Advanced Example: Using AWS Fetcher

The `fetcher` parameter gives you access to AWS service definitions:

```python
async def execute(self, statement, statement_idx, fetcher, config):
    issues = []

    for action in statement.get_actions():
        # Validate action exists
        is_valid, error_msg, is_wildcard = await fetcher.validate_action(action)

        # Get service details
        service, action_name = fetcher.parse_action(action)
        service_detail = await fetcher.fetch_service_by_name(service)

        # Access service metadata
        if service_detail:
            # service_detail.actions - dict of available actions
            # service_detail.condition_keys - available condition keys
            # service_detail.resource_types - available resource types
            pass

    return issues
```

## Issue Types and Severity

### Severity Levels
- `error`: Critical issues that should block deployment
- `warning`: Important issues that should be reviewed
- `info`: Informational messages

### Common Issue Types
- `invalid_action`: Action doesn't exist in AWS
- `invalid_condition_key`: Condition key not valid
- `invalid_resource`: Resource ARN format invalid
- `security_risk`: Critical security anti-pattern
- `overly_permissive`: Too broad permissions
- `missing_condition`: Missing recommended conditions
- Custom types: Use descriptive names for your checks

## Need Help?

- Review the built-in checks in `iam_validator/core/checks/`
- Check the `PolicyCheck` base class in `check_registry.py`
- Look at the `ValidationIssue` model in `models.py`
- See the configuration loader in `config_loader.py`
