# Custom Check Examples

This directory contains **8 production-ready custom check examples** that demonstrate how to extend IAM Policy Validator with your own validation rules.

## What are Custom Checks?

Custom checks allow you to implement organization-specific validation rules beyond the built-in checks. They are Python classes that inherit from `PolicyCheck` and can be loaded automatically from a directory or imported explicitly.

**Key Benefits:**
- Enforce organization-specific security policies
- Implement compliance requirements (SOC2, PCI-DSS, HIPAA)
- Add business logic validation
- No need to modify core code
- Easy to maintain and share across teams

## How to Create a Custom Check

### 1. Create a Python Class

Your custom check must:
- Inherit from `iam_validator.core.check_registry.PolicyCheck`
- Implement required properties: `check_id`, `description`, `default_severity`
- Implement the `async execute()` method for validation logic

**Minimal Example:**
```python
from iam_validator.core.check_registry import PolicyCheck, CheckConfig
from iam_validator.core.aws_fetcher import AWSServiceFetcher
from iam_validator.core.models import Statement, ValidationIssue


class MyCustomCheck(PolicyCheck):
    @property
    def check_id(self) -> str:
        return "my_custom_check"

    @property
    def description(self) -> str:
        return "My custom validation rule"

    @property
    def default_severity(self) -> str:
        return "error"  # or "warning", "info", "critical"

    async def execute(
        self,
        statement: Statement,
        statement_idx: int,
        fetcher: AWSServiceFetcher,
        config: CheckConfig,
    ) -> list[ValidationIssue]:
        issues = []

        # Your validation logic here
        # Access statement properties:
        # - statement.effect ("Allow" or "Deny")
        # - statement.get_actions() -> list of actions
        # - statement.get_resources() -> list of resources
        # - statement.condition -> dict of conditions
        # - statement.principal -> principal info
        # - statement.sid -> statement ID

        # Example: Check for wildcard actions
        actions = statement.get_actions()
        if "*" in actions:
            issues.append(
                ValidationIssue(
                    severity=self.get_severity(config),
                    statement_sid=statement.sid,
                    statement_index=statement_idx,
                    issue_type="wildcard_action",
                    message="Statement uses wildcard action",
                    suggestion="Use specific actions instead of '*'",
                    line_number=statement.line_number,
                )
            )

        return issues
```

### 2. Configure in iam-validator.yaml

**Method A: Auto-Discovery (Easiest)**
Place your checks in a directory and use `custom_checks_dir`:

```yaml
settings:
  custom_checks_dir: "./examples/custom_checks"  # or "./my_checks"

checks:
  my_custom_check:
    enabled: true
    severity: error
    # Check-specific configuration
    your_setting: "value"
```

**Method B: Explicit Import**
Import specific check classes:

```yaml
settings:
  custom_checks:
    - module: "path.to.module.MyCustomCheck"
      enabled: true

checks:
  my_custom_check:
    your_setting: "value"
```

### 3. Directory Structure

Recommended structure for custom checks:

```
your_project/
├── iam-validator.yaml
├── policies/
│   └── my-policy.json
└── my_checks/
    ├── __init__.py  # Can be empty
    ├── mfa_check.py
    ├── encryption_check.py
    └── region_check.py
```

Then in `iam-validator.yaml`:
```yaml
settings:
  custom_checks_dir: "./my_checks"
```

## Example Checks in This Directory

This directory contains **8 production-ready custom check examples** ranging from simple to highly complex:

### Basic Examples (Good Starting Points)

1. **[domain_restriction_check.py](domain_restriction_check.py)** - Domain Restriction Check
   - **Complexity**: ⭐ Basic
   - **Use Case**: Restrict S3 bucket access to specific domains
   - **What it teaches**: Basic condition validation, pattern matching
   - **Lines of Code**: ~120

2. **[region_restriction_check.py](region_restriction_check.py)** - Region Restriction Check
   - **Complexity**: ⭐ Basic
   - **Use Case**: Enforce approved AWS regions for compliance
   - **What it teaches**: Condition key validation, ARN parsing, list matching
   - **Lines of Code**: ~130

3. **[mfa_required_check.py](mfa_required_check.py)** - MFA Requirement Check
   - **Complexity**: ⭐⭐ Intermediate
   - **Use Case**: Require MFA for sensitive actions
   - **What it teaches**: Action pattern matching, boolean conditions
   - **Lines of Code**: ~120

4. **[tag_enforcement_check.py](tag_enforcement_check.py)** - Tag Enforcement Check
   - **Complexity**: ⭐⭐ Intermediate
   - **Use Case**: Enforce tagging for cost allocation and governance
   - **What it teaches**: Tag condition validation, required vs optional tags
   - **Lines of Code**: ~160

5. **[encryption_required_check.py](encryption_required_check.py)** - Encryption Requirement Check
   - **Complexity**: ⭐⭐ Intermediate
   - **Use Case**: Ensure S3 objects and EBS volumes are encrypted
   - **What it teaches**: Service-specific conditions, security controls
   - **Lines of Code**: ~155

### Advanced Examples

6. **[time_based_access_check.py](time_based_access_check.py)** - Time-Based Access Control
   - **Complexity**: ⭐⭐⭐ Advanced
   - **Use Case**: Restrict deployments to business hours, enforce maintenance windows
   - **What it teaches**: Time condition validation, multiple operator handling
   - **Lines of Code**: ~250
   - **Features**:
     - Business hours restrictions
     - Maintenance window enforcement
     - Multiple time condition support
   - **Real-world scenario**: "Only allow production deployments Mon-Fri 9am-5pm UTC"

7. **[cross_account_external_id_check.py](cross_account_external_id_check.py)** - Cross-Account ExternalId Validation
   - **Complexity**: ⭐⭐⭐⭐ Advanced
   - **Use Case**: Prevent "confused deputy" attacks in cross-account access
   - **What it teaches**: Principal parsing, security best practices, ExternalId validation
   - **Lines of Code**: ~230
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
   - **Lines of Code**: ~500+
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

| Check                     | Complexity | LOC  | Best For                 | Key Features                                       |
| ------------------------- | ---------- | ---- | ------------------------ | -------------------------------------------------- |
| Domain Restriction        | ⭐          | ~120 | Learning basics          | Basic pattern matching, fnmatch                    |
| Region Restriction        | ⭐          | ~130 | Simple compliance        | ARN parsing, list validation                       |
| MFA Required              | ⭐⭐         | ~120 | Security basics          | Pattern matching, boolean conditions               |
| Tag Enforcement           | ⭐⭐         | ~160 | Governance               | Tag validation, required tags                      |
| Encryption Required       | ⭐⭐         | ~155 | Data security            | Service-specific rules, secure transport           |
| Time-Based Access         | ⭐⭐⭐        | ~250 | Change control           | Time conditions, multiple operators, date parsing  |
| Cross-Account ExternalId  | ⭐⭐⭐⭐       | ~230 | Third-party integrations | ARN parsing, regex validation, trusted lists       |
| Multi-Condition Validator | ⭐⭐⭐⭐⭐      | ~500 | Enterprise security      | Full rule engine, exception handling, all of above |

## Learning Path

### Beginner: Start Here (30 minutes)
1. Read **[domain_restriction_check.py](domain_restriction_check.py)** - simplest example
2. Modify it for your use case
3. Try **[region_restriction_check.py](region_restriction_check.py)** next

### Intermediate: Build on Basics (1-2 hours)
4. Study **[mfa_required_check.py](mfa_required_check.py)** for pattern matching
5. Implement **[tag_enforcement_check.py](tag_enforcement_check.py)** for governance
6. Add **[encryption_required_check.py](encryption_required_check.py)** for security

### Advanced: Production-Grade Checks (2-4 hours)
7. Analyze **[time_based_access_check.py](time_based_access_check.py)** for complex conditions
8. Study **[cross_account_external_id_check.py](cross_account_external_id_check.py)** for security patterns
9. Master **[advanced_multi_condition_validator.py](advanced_multi_condition_validator.py)** for enterprise needs

## Quick Start

### Step 1: Copy Example Checks
```bash
# Copy the examples to your project
mkdir -p my_checks
cp examples/custom_checks/*.py my_checks/
cd my_checks
```

### Step 2: Configure in iam-validator.yaml
```yaml
settings:
  custom_checks_dir: "./my_checks"

checks:
  mfa_required:
    enabled: true
    severity: error
    require_mfa_for:
      - "iam:DeleteUser"
      - "s3:DeleteBucket"
      - "iam:DeleteRole"
    require_mfa_patterns:
      - "^iam:Delete.*"

  encryption_required:
    enabled: true
    severity: error
    require_encryption_for:
      - "s3:PutObject"
      - "s3:CreateBucket"
    require_secure_transport: true
```

### Step 3: Run Validation
```bash
# CLI
uv run iam-validator validate --path ./policies/

# Or in Python
from iam_validator.core.policy_checks import validate_policies
from iam_validator.core.policy_loader import PolicyLoader

loader = PolicyLoader()
policies = loader.load_from_path("./policies/")
results = await validate_policies(
    policies,
    config_path="./iam-validator.yaml",
    use_registry=True
)
```

## Configuration Examples

### Example 1: Simple MFA Enforcement

```yaml
settings:
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
settings:
  custom_checks_dir: "./examples/custom_checks"

checks:
  time_based_access:
    enabled: true
    severity: error
    time_restricted_actions:
      - actions:
          - "cloudformation:CreateStack"
          - "cloudformation:UpdateStack"
          - "lambda:UpdateFunctionCode"
        required_conditions:
          - condition_key: "aws:CurrentTime"
            description: "Deployments only 9am-5pm UTC, Mon-Fri"
            allowed_operators:
              - "DateGreaterThan"
              - "DateLessThan"
```

### Example 3: Cross-Account Security

```yaml
settings:
  custom_checks_dir: "./examples/custom_checks"

checks:
  cross_account_external_id:
    enabled: true
    severity: error
    trusted_accounts:
      - "123456789012"  # Your org account
      - "987654321098"  # Dev account
    require_external_id_pattern: "^[a-zA-Z0-9-]{32,}$"
```

### Example 4: Enterprise Multi-Condition (Complex)

```yaml
settings:
  custom_checks_dir: "./examples/custom_checks"

checks:
  advanced_multi_condition:
    enabled: true
    severity: error
    action_categories:
      critical_operations:
        actions:
          - "cloudformation:CreateStack"
          - "cloudformation:UpdateStack"
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

### Pattern 1: Action Matching with Wildcards
```python
import re

def _matches_action(self, action: str, patterns: list[str]) -> bool:
    """Match action against wildcard patterns."""
    for pattern in patterns:
        if "*" in pattern:
            regex = pattern.replace("*", ".*")
            if re.match(f"^{regex}$", action):
                return True
        elif action == pattern:
            return True
    return False
```

### Pattern 2: Condition Validation
```python
def _has_condition(self, statement: Statement, key: str) -> bool:
    """Check if statement has a specific condition key."""
    if not statement.condition:
        return False

    for operator in ["StringEquals", "StringLike", "Bool"]:
        if operator in statement.condition:
            if key in statement.condition[operator]:
                return True
    return False
```

### Pattern 3: Creating Validation Issues
```python
issues.append(
    ValidationIssue(
        severity=self.get_severity(config),
        statement_sid=statement.sid,
        statement_index=statement_idx,
        issue_type="custom_issue_type",
        message=f"Clear description of the problem",
        suggestion="Step-by-step fix: add condition X, set value Y",
        action=action,  # Optional: specific action
        resource=resource,  # Optional: specific resource
        line_number=statement.line_number,
    )
)
```

### Pattern 4: Getting Config Values
```python
# In execute() method:
required_tags = config.config.get("required_tags", [])
severity_override = config.config.get("severity")
enabled = config.config.get("enabled", True)

# Use default severity or override
severity = self.get_severity(config)
```

## Testing Your Custom Checks

Create test policies in your project:

```bash
# Create test directory
mkdir -p test_policies

# Test policy with issues
cat > test_policies/test-mfa.json << EOF
{
  "Version": "2012-10-17",
  "Statement": [{
    "Sid": "DeleteUserNoMFA",
    "Effect": "Allow",
    "Action": "iam:DeleteUser",
    "Resource": "*"
  }]
}
EOF

# Run validation
uv run iam-validator validate \
  --path test_policies/ \
  --config iam-validator.yaml
```

### Unit Testing Custom Checks

```python
import asyncio
import pytest
from iam_validator.core.aws_fetcher import AWSServiceFetcher
from iam_validator.core.check_registry import CheckConfig
from iam_validator.core.models import Statement
from my_checks.mfa_required_check import MFARequiredCheck


@pytest.mark.asyncio
async def test_mfa_required_check():
    """Test MFA check detects missing MFA condition."""
    check = MFARequiredCheck()

    # Create test statement without MFA
    statement = Statement(
        effect="Allow",
        action=["iam:DeleteUser"],
        resource="*",
        condition=None,
    )

    # Configure check
    config = CheckConfig(
        check_id="mfa_required",
        config={
            "require_mfa_for": ["iam:DeleteUser"]
        }
    )

    # Run check
    async with AWSServiceFetcher() as fetcher:
        issues = await check.execute(statement, 0, fetcher, config)

    # Verify issue was found
    assert len(issues) == 1
    assert "MFA" in issues[0].message
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
- Use async/await properly

### 5. Testing
- Write unit tests for your custom checks
- Test with various policy structures
- Include edge cases

## Advanced: Using AWS Fetcher

The `fetcher` parameter gives you access to AWS service definitions:

```python
async def execute(self, statement, statement_idx, fetcher, config):
    issues = []

    for action in statement.get_actions():
        # Validate action exists in AWS
        is_valid, error_msg, is_wildcard = await fetcher.validate_action(action)

        if not is_valid and not is_wildcard:
            issues.append(
                ValidationIssue(
                    severity="error",
                    message=f"Invalid action: {action}",
                    suggestion=error_msg,
                    # ...
                )
            )

        # Get service details
        service, action_name = fetcher.parse_action(action)
        service_detail = await fetcher.fetch_service_by_name(service)

        if service_detail:
            # Access service metadata
            # service_detail.actions - dict of available actions
            # service_detail.condition_keys - available condition keys
            # service_detail.resource_types - available resource types
            pass

    return issues
```

## Issue Types and Severity

### Severity Levels
- `critical`: Severe security issues, must fix immediately
- `error`: Critical issues that should block deployment
- `warning`: Important issues that should be reviewed
- `info`: Informational messages, suggestions

### Common Issue Types
- `invalid_action`: Action doesn't exist in AWS
- `invalid_condition_key`: Condition key not valid
- `invalid_resource`: Resource ARN format invalid
- `security_risk`: Critical security anti-pattern
- `overly_permissive`: Too broad permissions
- `missing_condition`: Missing recommended conditions
- Custom types: Use descriptive names for your checks

## Troubleshooting

### Check Not Loading
1. Verify file is in `custom_checks_dir`
2. Check class inherits from `PolicyCheck`
3. Ensure `__init__.py` exists in directory
4. Check for Python syntax errors
5. Verify class name doesn't conflict with built-in checks

### Check Not Running
1. Ensure check is enabled in configuration
2. Verify `check_id` matches configuration key
3. Check statement conditions (e.g., only runs on Allow statements)
4. Add debug logging to `execute()` method

### Configuration Not Applied
1. Verify YAML syntax is correct
2. Check configuration key matches `check_id`
3. Ensure using `use_registry=True` when calling validate_policies
4. Verify config file path is correct

## Need Help?

1. Review the 8 example checks in this directory
2. Check the built-in checks in `iam_validator/checks/`
3. See `PolicyCheck` base class in [check_registry.py](../../iam_validator/core/check_registry.py)
4. Check the [configuration docs](../../docs/configuration.md)
5. Open an issue on GitHub

## Additional Resources

- **[Python Library Usage](../library-usage/README.md)** - How to use the library programmatically
- **[Configuration Guide](../../docs/configuration.md)** - All configuration options
- **[Built-in Checks](../../iam_validator/checks/)** - Source code for built-in checks
- **[API Documentation](../../docs/python-library-usage.md)** - Complete API reference
