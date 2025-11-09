# IAM Policy Validator - Python SDK

Complete guide to using IAM Policy Validator as a Python library in your applications.

## Table of Contents

- [Quick Start](#quick-start)
- [Installation](#installation)
- [Basic Usage](#basic-usage)
- [Advanced Usage](#advanced-usage)
- [Validation Checks](#validation-checks)
- [Policy Utilities](#policy-utilities)
- [Custom Check Development](#custom-check-development)
- [API Reference](#api-reference)
- [Migration from api to sdk](#migration-from-api-to-sdk)

## Quick Start

### Simple Validation

```python
from iam_validator.sdk import quick_validate

# Just need True/False?
is_valid = await quick_validate("policy.json")
```

### Detailed Validation

```python
from iam_validator.sdk import validate_file

result = await validate_file("policy.json")

if not result.is_valid:
    for issue in result.issues:
        print(f"{issue.severity}: {issue.message}")
```

### Batch Validation with Context Manager

```python
from iam_validator.sdk import validator

async with validator() as v:
    # Efficient - shares AWS fetcher across validations
    result1 = await v.validate_file("policy1.json")
    result2 = await v.validate_file("policy2.json")
    results = await v.validate_directory("./policies")

    # Generate reports
    v.generate_report(results, format="json")
```

## Installation

```bash
# Via pip
pip install iam-policy-validator

# Via uv (recommended)
uv add iam-policy-validator
```

## Basic Usage

### Validation Functions

#### validate_file()
Validate a single IAM policy file.

```python
from iam_validator.sdk import validate_file

result = await validate_file("policy.json")
print(f"Valid: {result.is_valid}")
print(f"Issues: {len(result.issues)}")
```

#### validate_directory()
Validate all policies in a directory.

```python
from iam_validator.sdk import validate_directory

results = await validate_directory("./policies")
valid_count = sum(1 for r in results if r.is_valid)
print(f"{valid_count}/{len(results)} policies are valid")
```

#### validate_json()
Validate a policy from a Python dict.

```python
from iam_validator.sdk import validate_json

policy = {
    "Version": "2012-10-17",
    "Statement": [{
        "Effect": "Allow",
        "Action": "s3:GetObject",
        "Resource": "arn:aws:s3:::my-bucket/*"
    }]
}

result = await validate_json(policy)
```

#### quick_validate()
Quick validation returning just True/False.

```python
from iam_validator.sdk import quick_validate

# Auto-detects file, directory, or dict
if await quick_validate("policy.json"):
    print("Valid!")
```

#### get_issues()
Get issues filtered by severity.

```python
from iam_validator.sdk import get_issues

# Get only high and critical issues
issues = await get_issues("policy.json", min_severity="high")

for issue in issues:
    print(f"{issue.severity}: {issue.message}")
```

### Using Configuration

```python
from iam_validator.sdk import validate_file

# With config file
result = await validate_file(
    "policy.json",
    config_path="./iam-validator.yaml"
)

# With Config object
from iam_validator.sdk import Config

config = Config(
    fail_on_severity="medium",
    checks={
        "wildcard_action": {"enabled": True},
        "missing_mfa": {"enabled": False}
    }
)

result = await validate_file("policy.json", config=config)
```

## Advanced Usage

### Context Managers

Context managers handle resource lifecycle automatically and are more efficient for multiple validations.

```python
from iam_validator.sdk import validator

async with validator() as v:
    # AWS fetcher is created once and reused
    r1 = await v.validate_file("policy1.json")
    r2 = await v.validate_file("policy2.json")
    r3 = await v.validate_directory("./policies")

    # Generate reports in different formats
    v.generate_report([r1, r2, r3], format="console")
    json_report = v.generate_report([r1, r2, r3], format="json")
    html_report = v.generate_report([r1, r2, r3], format="html")

# Fetcher automatically cleaned up here
```

With configuration:

```python
from iam_validator.sdk import validator

async with validator(config_path="./iam-validator.yaml") as v:
    results = await v.validate_directory("./policies")
    v.generate_report(results)
```

### Report Generation

```python
from iam_validator.sdk import (
    validate_directory,
    ReportGenerator,
    JsonFormatter,
    HtmlFormatter,
    CsvFormatter
)

results = await validate_directory("./policies")

generator = ReportGenerator()
report = generator.generate_report(results)

# Console output
generator.print_console_report(report)

# JSON
json_output = JsonFormatter().format(report)
with open("report.json", "w") as f:
    f.write(json_output)

# HTML
html_output = HtmlFormatter().format(report)
with open("report.html", "w") as f:
    f.write(html_output)

# CSV
csv_output = CsvFormatter().format(report)
with open("report.csv", "w") as f:
    f.write(csv_output)
```

## Validation Checks

The SDK includes all **17 built-in validation checks** that can be customized programmatically.

### Understanding Validation Results

```python
from iam_validator.sdk import validate_file

result = await validate_file("policy.json")

# Check validation status
if not result.is_valid:
    print(f"Found {len(result.issues)} issues")

    # Filter by severity
    critical_issues = [i for i in result.issues if i.severity == "critical"]
    high_issues = [i for i in result.issues if i.severity == "high"]

    # Group by check type
    by_check = {}
    for issue in result.issues:
        check = issue.check_name
        if check not in by_check:
            by_check[check] = []
        by_check[check].append(issue)

    # Display issues
    for check, issues in by_check.items():
        print(f"\n{check}: {len(issues)} issues")
        for issue in issues:
            print(f"  [{issue.severity}] {issue.message}")
```

### Check Categories

The validator performs checks in three categories:

1. **AWS Validation (6 checks)** - Ensure AWS IAM compliance
   - action_validation
   - condition_key_validation
   - condition_type_mismatch
   - mfa_condition_antipattern
   - resource_validation
   - sid_uniqueness

2. **Security Best Practices (7 checks)** - Identify security risks
   - wildcard_action
   - wildcard_resource
   - full_wildcard (CRITICAL)
   - service_wildcard
   - sensitive_action
   - principal_validation
   - policy_size

3. **Advanced Enforcement (3 checks)** - Enforce custom requirements
   - action_condition_enforcement
   - action_resource_matching
   - set_operator_validation

### Configuring Checks Programmatically

```python
from iam_validator.sdk import Config, validate_file

# Create custom configuration
config = Config(
    fail_on_severity=["error", "critical", "high"],
    checks={
        # Disable specific checks
        "wildcard_action": {"enabled": False},

        # Customize check severity
        "sensitive_action": {
            "enabled": True,
            "severity": "high"
        },

        # Configure check behavior
        "action_condition_enforcement": {
            "enabled": True,
            "severity": "high",
            "action_condition_requirements": [
                {
                    "actions": ["iam:PassRole"],
                    "required_conditions": [
                        {
                            "condition_key": "iam:PassedToService",
                            "description": "Restrict which services can assume the role"
                        }
                    ]
                }
            ]
        }
    }
)

# Use configuration
result = await validate_file("policy.json", config=config)
```

### Filtering Issues by Severity

```python
from iam_validator.sdk import get_issues

# Get only critical and high severity issues
critical_high = await get_issues(
    "policy.json",
    min_severity="high"  # Returns 'high' and 'critical'
)

# Count issues by severity
from iam_validator.sdk import count_issues_by_severity

counts = await count_issues_by_severity("policy.json")
print(f"Critical: {counts['critical']}")
print(f"High: {counts['high']}")
print(f"Medium: {counts['medium']}")
```

### Complete Check Documentation

**📚 For detailed documentation of all 17 validation checks with pass/fail examples:**

**[→ View Complete Checks Reference](check-reference.md)**

---

## Policy Utilities

The SDK provides utilities for parsing, analyzing, and manipulating IAM policies.

### Parsing Policies

```python
from iam_validator.sdk import parse_policy

# From JSON string
policy_str = '{"Version": "2012-10-17", "Statement": [...]}'
policy = parse_policy(policy_str)

# From dict
policy_dict = {"Version": "2012-10-17", "Statement": [...]}
policy = parse_policy(policy_dict)
```

### Analyzing Policies

```python
from iam_validator.sdk import get_policy_summary

summary = get_policy_summary(policy)

print(f"Statements: {summary['statement_count']}")
print(f"Actions: {summary['action_count']}")
print(f"Resources: {summary['resource_count']}")
print(f"Allow statements: {summary['allow_statements']}")
print(f"Deny statements: {summary['deny_statements']}")
print(f"Has wildcards: {summary['has_wildcard_actions']}")
```

### Extracting Information

```python
from iam_validator.sdk import (
    extract_actions,
    extract_resources,
    extract_condition_keys
)

# Get all actions
actions = extract_actions(policy)
print(f"Actions: {', '.join(actions)}")

# Get all resources
resources = extract_resources(policy)
print(f"Resources: {', '.join(resources)}")

# Get condition keys
keys = extract_condition_keys(policy)
print(f"Condition keys: {', '.join(keys)}")
```

### Searching Policies

```python
from iam_validator.sdk import (
    find_statements_with_action,
    find_statements_with_resource
)

# Find statements with specific action
statements = find_statements_with_action(policy, "s3:GetObject")
for stmt in statements:
    print(f"Statement {stmt.sid}: {stmt.effect}")

# Find statements with specific resource
statements = find_statements_with_resource(policy, "arn:aws:s3:::my-bucket/*")
```

### Policy Type Detection

```python
from iam_validator.sdk import is_resource_policy, has_public_access

# Check if it's a resource policy (vs identity policy)
if is_resource_policy(policy):
    print("This is a resource policy (has Principal)")

# Check for public access
if has_public_access(policy):
    print("WARNING: Policy allows public access!")
```

### Merging Policies

```python
from iam_validator.sdk import merge_policies

policy1 = parse_policy(json1)
policy2 = parse_policy(json2)

merged = merge_policies(policy1, policy2)
print(f"Merged policy has {len(merged.statement)} statements")
```

### Converting Policies

```python
from iam_validator.sdk import policy_to_json, policy_to_dict

# To JSON string
json_str = policy_to_json(policy, indent=2)

# To Python dict
policy_dict = policy_to_dict(policy)
```

## Custom Check Development

### Creating a Custom Check

```python
from iam_validator.sdk import PolicyCheck, CheckHelper

class MyCustomCheck(PolicyCheck):
    @property
    def check_id(self) -> str:
        return "my_custom_check"

    @property
    def description(self) -> str:
        return "Check for sensitive bucket access"

    async def execute(self, statement, statement_idx, fetcher, config):
        helper = CheckHelper(fetcher)
        issues = []

        # Check if accessing sensitive buckets
        for resource in statement.get_resources():
            if helper.arn_matches("arn:*:s3:::secret-*", resource):
                issues.append(helper.create_issue(
                    severity="high",
                    statement_idx=statement_idx,
                    message="Access to sensitive bucket detected",
                    resource=resource,
                    suggestion="Restrict access to specific paths"
                ))

        return issues
```

### Registering Custom Checks

```python
from iam_validator.sdk import register_check

# Register the check
register_check(MyCustomCheck)

# Now it will run with validations
result = await validate_file("policy.json")
```

### Using Check Helpers

```python
from iam_validator.sdk import CheckHelper, arn_matches

class MyCheck(PolicyCheck):
    async def execute(self, statement, idx, fetcher, config):
        helper = CheckHelper(fetcher)

        # ARN matching
        if helper.arn_matches("arn:*:s3:::*/*", resource):
            print("Matches S3 object pattern")

        # Expand wildcards
        actions = await helper.expand_actions(["s3:Get*"])

        # Create issues
        issue = helper.create_issue(
            severity="medium",
            statement_idx=idx,
            message="Issue found",
            suggestion="Fix this way",
            example="Example: ..."
        )

        return [issue]
```

## API Reference

### Validation Functions

- `validate_file(file_path, config_path=None, config=None)` - Validate single file
- `validate_directory(dir_path, config_path=None, config=None)` - Validate directory
- `validate_json(policy_json, policy_name="inline", config_path=None, config=None)` - Validate dict
- `quick_validate(policy, config_path=None, config=None)` - Quick True/False validation
- `get_issues(policy, min_severity="medium", config_path=None, config=None)` - Get filtered issues
- `count_issues_by_severity(policy, config_path=None, config=None)` - Count issues by severity

### Context Managers

- `validator(config_path=None, config=None)` - Main validation context
- `validator_from_config(config_path)` - Context with loaded config
- `ValidationContext` - Context object with validation methods

### Policy Utilities

- `parse_policy(policy)` - Parse JSON string or dict
- `normalize_policy(policy)` - Normalize policy format
- `extract_actions(policy)` - Get all actions
- `extract_resources(policy)` - Get all resources
- `extract_condition_keys(policy)` - Get all condition keys
- `find_statements_with_action(policy, action)` - Find statements by action
- `find_statements_with_resource(policy, resource)` - Find statements by resource
- `merge_policies(*policies)` - Merge multiple policies
- `get_policy_summary(policy)` - Get policy statistics
- `policy_to_json(policy, indent=2)` - Convert to JSON
- `policy_to_dict(policy)` - Convert to dict
- `is_resource_policy(policy)` - Check if resource policy
- `has_public_access(policy)` - Check for public access

### ARN Utilities

- `arn_matches(pattern, arn, resource_type=None)` - Match ARN with wildcards
- `arn_strictly_valid(pattern, arn, resource_type=None)` - Strict ARN validation
- `is_glob_match(s1, s2)` - Glob pattern matching
- `convert_aws_pattern_to_wildcard(pattern)` - Convert AWS patterns

### Custom Check Development

- `PolicyCheck` - Base class for checks
- `register_check(check_class)` - Register custom check
- `CheckHelper` - Helper for check development
- `expand_actions(actions, fetcher=None)` - Expand action wildcards

### Models

- `ValidationIssue` - Represents a validation issue
- `ValidationResult` - Validation result for a policy
- `PolicyDocument` - Policy with metadata
- `IAMPolicy` - Parsed IAM policy
- `Statement` - IAM policy statement
- `Config` - Validation configuration

### Exceptions

- `IAMValidatorError` - Base exception
- `PolicyLoadError` - Policy loading errors
- `PolicyValidationError` - Validation errors
- `ConfigurationError` - Config errors
- `AWSServiceError` - AWS service fetch errors
- `InvalidPolicyFormatError` - Invalid policy format
- `UnsupportedPolicyTypeError` - Unsupported policy type

### Additional Features in SDK

The new SDK provides everything from `api` plus:

1. **High-level shortcuts**: `validate_file()`, `quick_validate()`, etc.
2. **Context managers**: `validator()` for resource management
3. **Policy utilities**: `parse_policy()`, `extract_actions()`, etc.
4. **Better organization**: Clear separation of concerns
5. **Comprehensive documentation**: Full API reference

### Recommended Migration

Update imports in your code:

```python
# Before
from iam_validator.api import arn_matches, CheckHelper

# After
from iam_validator.sdk import arn_matches, CheckHelper
```

Or use the new convenience functions:

```python
# Before
from iam_validator.core.policy_checks import validate_policies
from iam_validator.core.policy_loader import PolicyLoader

loader = PolicyLoader()
policies = loader.load_from_path("policy.json")
results = await validate_policies(policies)

# After (much simpler!)
from iam_validator.sdk import validate_file

result = await validate_file("policy.json")
```

## Examples

See the `examples/library-usage/` directory for complete runnable examples:

- `example1_basic_usage_new.py` - Basic validation with shortcuts
- `example2_context_manager.py` - Using context managers for batch validation
- `example3_policy_manipulation.py` - Policy analysis and manipulation utilities
- `example4_custom_condition_requirements.py` - Custom check development guide

### Example: Comprehensive Validation Workflow

```python
import asyncio
from iam_validator.sdk import validator, Config

async def validate_policies():
    # Create configuration
    config = Config(
        fail_on_severity=["error", "critical", "high"],
        checks={
            "full_wildcard": {"enabled": True, "severity": "critical"},
            "sensitive_action": {"enabled": True, "severity": "high"}
        }
    )

    # Use context manager for efficiency
    async with validator(config=config) as v:
        # Validate multiple sources
        file_result = await v.validate_file("policy.json")
        dir_results = await v.validate_directory("./policies")

        # Process results
        all_results = [file_result] + dir_results

        # Generate reports
        console_report = v.generate_report(all_results, format="console")
        json_report = v.generate_report(all_results, format="json")
        html_report = v.generate_report(all_results, format="html")

        # Save reports
        with open("validation_report.json", "w") as f:
            f.write(json_report)
        with open("validation_report.html", "w") as f:
            f.write(html_report)

        # Print summary
        print(console_report)

        # Return validation status
        return all(r.is_valid for r in all_results)

if __name__ == "__main__":
    success = asyncio.run(validate_policies())
    exit(0 if success else 1)
```

## Additional Resources

### Documentation
- **[Complete Usage Guide](../DOCS.md)** - CLI usage, GitHub Actions, configuration
- **[Validation Checks Reference](check-reference.md)** - All 18 checks with examples
- **[Project README](../README.md)** - Project overview and quick start

### Examples
- **[Library Usage Examples](../examples/library-usage/)** - Runnable Python examples
- **[Configuration Examples](../examples/configs/)** - 9 YAML configuration files
- **[Custom Check Examples](../examples/custom_checks/)** - Example custom validators

### Support
- **[Report Issues](https://github.com/boogy/iam-policy-validator/issues)** - Report bugs or request features
- **[Contributing Guide](../CONTRIBUTING.md)** - How to contribute
